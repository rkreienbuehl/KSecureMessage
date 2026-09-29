package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.CiphertextMessage
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import io.kodium.Kodium
import io.kodium.KodiumPrivateKey
import io.kodium.KodiumPublicKey
import io.kodium.ratchet.DoubleRatchetSession
import io.kodium.ratchet.X3DH
import io.kodium.ratchet.RatchetMessage as KodiumRatchetMessage

/**
 * [ProtocolEngine] backed by Kodium's X3DH and Double Ratchet.
 *
 * Key encoding: private keys are Kodium's raw 32-byte secret, public keys are
 * Kodium's 64-byte unified key (X25519 encryption key followed by Ed25519
 * signing key).
 *
 * Every operation imports the ratchet from [SecureSession.state], works on a
 * throwaway Kodium session and exports it again. Kodium mutates its session
 * even when decryption fails, so a failed call must never produce a new state;
 * the caller's stored session stays valid.
 *
 * Kodium's X3DH neither verifies the signed prekey signature nor defines
 * associated data. This engine verifies the signature before key agreement.
 * Sessions it creates use session initiation version 2 (S1): the associated
 * data of every ratchet message is the canonical initiation transcript
 * ([SessionInitiationId.v2Transcript]) with both device addresses, both
 * identity keys, the whole ephemeral key and both prekey IDs. Sessions
 * created before S1 keep their version 1 associated data
 * `initiatorIdentityKey || responderIdentityKey`.
 */
class KodiumProtocolEngine : ProtocolEngine {
    override suspend fun createIdentity(): LocalIdentity {
        val key = KodiumPrivateKey.generate()
        return LocalIdentity(publicKey = key.getPublicKey().toBytes(), privateKey = key.exportToArray())
    }

    override suspend fun createDeviceAuthenticationKey(): DeviceAuthenticationKeyPair = Ed25519.generate()

    override suspend fun createLastDeviceRecoveryKey(): LastDeviceRecoveryKey {
        val generated = Ed25519.generate()
        try {
            return LastDeviceRecoveryKey(generated.privateKey, generated.publicKey)
        } finally {
            generated.privateKey.fill(0)
        }
    }

    override suspend fun createSignedPreKey(identity: LocalIdentity, id: SignedPreKeyId): SignedPreKeyPair {
        val identityKey = privateKey(identity.privateKey)
        val preKey = KodiumPrivateKey.generate()
        val publicKey = preKey.getPublicKey().toBytes()
        val signature = Kodium.signDetached(identityKey, publicKey)
            .getOrElse { throw IllegalStateException("Signing the signed prekey failed", it) }
        return SignedPreKeyPair(id, publicKey, signature, preKey.exportToArray())
    }

    override suspend fun createOneTimePreKeys(firstId: OneTimePreKeyId, count: Int): List<OneTimePreKeyPair> {
        require(count >= 0) { "count must not be negative" }
        require(firstId.value.toLong() + count - 1 <= Int.MAX_VALUE) { "One-time prekey IDs would overflow" }
        return List(count) { index ->
            val key = KodiumPrivateKey.generate()
            OneTimePreKeyPair(
                id = OneTimePreKeyId(firstId.value + index),
                publicKey = key.getPublicKey().toBytes(),
                privateKey = key.exportToArray(),
            )
        }
    }

    override suspend fun initiateSession(localIdentity: LocalIdentity, localAddress: DeviceAddress, remoteBundle: PreKeyBundle): SecureSession {
        val remoteIdentityKey = bundleKey(remoteBundle.identityKey)
        val signedPreKey = bundleKey(remoteBundle.signedPreKey.publicKey)
        val oneTimePreKey = remoteBundle.oneTimePreKey?.let { bundleKey(it.publicKey) }

        if (!Kodium.verifyDetached(remoteIdentityKey, remoteBundle.signedPreKey.publicKey, remoteBundle.signedPreKey.signature)) {
            throw ProtocolException.InvalidSignature("Signed prekey signature does not verify")
        }

        val ephemeralKey = KodiumPrivateKey.generate()
        val sharedSecret = X3DH.calculateSecretAsInitiator(
            initiatorIdentityKey = privateKey(localIdentity.privateKey),
            initiatorEphemeralKey = ephemeralKey,
            responderBundle = X3DH.PublicBundle(remoteIdentityKey, signedPreKey, oneTimePreKey),
            info = X3DH_INFO,
        )
        val ratchet = try {
            DoubleRatchetSession.initializeAsInitiator(sharedSecret, signedPreKey, RATCHET_INFO)
        } finally {
            sharedSecret.fill(0)
            ephemeralKey.secretKey.fill(0)
        }

        val header = PendingPreKey(
            identityKey = localIdentity.publicKey.copyOf(),
            ephemeralKey = ephemeralKey.getPublicKey().toBytes(),
            signedPreKeyId = remoteBundle.signedPreKey.id,
            oneTimePreKeyId = remoteBundle.oneTimePreKey?.id,
        )
        // Version 2: the transcript binds both addresses and every header field (S1).
        val transcript = SessionInitiationId.v2Transcript(
            sender = localAddress,
            recipient = remoteBundle.address,
            initiatorIdentityKey = header.identityKey,
            responderIdentityKey = remoteBundle.identityKey,
            ephemeralKey = header.ephemeralKey,
            signedPreKeyId = header.signedPreKeyId,
            oneTimePreKeyId = header.oneTimePreKeyId,
        )
        val state = SessionState(
            initiationVersion = SessionInitiationVersion.V2,
            associatedData = transcript,
            initiatorIdentityKey = localIdentity.publicKey.copyOf(),
            responderIdentityKey = remoteBundle.identityKey.copyOf(),
            pending = header,
            initiation = header,
            origin = SessionInitiationId.ofTranscript(transcript),
            acceptedSignedPreKeyId = null,
            ratchet = ratchet.exportToArray(),
        )
        return SecureSession(remoteBundle.address, state.encodeAndWipe())
    }

    override suspend fun acceptSession(
        localIdentity: LocalIdentity,
        localAddress: DeviceAddress,
        remote: DeviceAddress,
        signedPreKey: SignedPreKeyPair,
        oneTimePreKey: OneTimePreKeyPair?,
        message: PreKeyMessage,
    ): SessionAcceptanceResult {
        // A version 1 initiation leaves header fields and the sender address
        // unauthenticated; it never creates a session (S1, findings F3/F4).
        if (message.initiationVersion != SessionInitiationVersion.V2) {
            throw ProtocolException.InvalidMessage("Version 1 session initiations are not accepted")
        }
        if (signedPreKey.id != message.signedPreKeyId) {
            throw ProtocolException.InvalidMessage("Signed prekey ID does not match the message")
        }
        if (oneTimePreKey?.id != message.oneTimePreKeyId) {
            throw ProtocolException.InvalidMessage("One-time prekey ID does not match the message")
        }
        val initiatorIdentityKey = messageKey(message.identityKey)
        val initiatorEphemeralKey = messageKey(message.ephemeralKey)
        val ratchetMessage = parse(message.message)
        val transcript = SessionInitiationId.v2Transcript(
            sender = remote,
            recipient = localAddress,
            initiatorIdentityKey = message.identityKey,
            responderIdentityKey = localIdentity.publicKey,
            ephemeralKey = message.ephemeralKey,
            signedPreKeyId = message.signedPreKeyId,
            oneTimePreKeyId = message.oneTimePreKeyId,
        )

        val sharedSecret = X3DH.calculateSecretAsResponder(
            responderIdentityKey = privateKey(localIdentity.privateKey),
            responderSignedPreKey = privateKey(signedPreKey.privateKey),
            responderOneTimePreKey = oneTimePreKey?.let { privateKey(it.privateKey) },
            initiatorIdentityKey = initiatorIdentityKey,
            initiatorEphemeralKey = initiatorEphemeralKey,
            info = X3DH_INFO,
        )
        try {
            // Kodium keeps sharedSecret as the root key until the first
            // decrypt, so it is wiped only after the session is exported.
            val ratchet = DoubleRatchetSession.initializeAsResponder(
                sharedSecret,
                privateKey(signedPreKey.privateKey),
                RATCHET_INFO,
            )
            val plaintext = ratchet.decrypt(ratchetMessage, transcript)
                .getOrElse { throw ProtocolException.DecryptionFailed("Could not decrypt the first message", it) }
            // Decryption authenticated the whole transcript (addresses and
            // every header field), so the origin derived from it is genuine.
            val state = SessionState(
                initiationVersion = SessionInitiationVersion.V2,
                associatedData = transcript,
                initiatorIdentityKey = message.identityKey.copyOf(),
                responderIdentityKey = localIdentity.publicKey.copyOf(),
                pending = null,
                initiation = PendingPreKey(message.identityKey.copyOf(), message.ephemeralKey.copyOf(), message.signedPreKeyId, message.oneTimePreKeyId),
                origin = SessionInitiationId.ofTranscript(transcript),
                acceptedSignedPreKeyId = signedPreKey.id,
                ratchet = ratchet.exportToArray(),
            )
            return SessionAcceptanceResult(
                session = SecureSession(remote, state.encodeAndWipe()),
                plaintext = plaintext,
                consumedOneTimePreKeyId = oneTimePreKey?.id,
            )
        } finally {
            sharedSecret.fill(0)
        }
    }

    override suspend fun encrypt(session: SecureSession, plaintext: ByteArray): EncryptionResult {
        val state = SessionState.decode(session.state)
        val ratchet = importRatchet(state)
        val encrypted = ratchet.encrypt(plaintext, state.associatedData)
            .getOrElse { throw ProtocolException.InvalidSessionState("Session cannot encrypt", it) }
        val ratchetMessage = RatchetMessage(encrypted.serialize())

        val pending = state.pending
        val message = if (pending == null) {
            ratchetMessage
        } else {
            PreKeyMessage(
                identityKey = pending.identityKey.copyOf(),
                ephemeralKey = pending.ephemeralKey.copyOf(),
                signedPreKeyId = pending.signedPreKeyId,
                oneTimePreKeyId = pending.oneTimePreKeyId,
                message = ratchetMessage,
                // A pending session keeps the version it was initiated with.
                initiationVersion = state.initiationVersion,
            )
        }
        val updated = state.advanced(pending, ratchet.exportToArray())
        state.ratchet.fill(0)
        return EncryptionResult(message, session.copy(state = updated.encodeAndWipe()))
    }

    override suspend fun decrypt(session: SecureSession, message: CiphertextMessage, localIdentityKey: ByteArray): DecryptionResult {
        val state = SessionState.decode(session.state)
        val ratchetMessage = when (message) {
            is RatchetMessage -> message
            is PreKeyMessage -> {
                checkRepeatedInitiation(state, message, localIdentityKey)
                message.message
            }
        }
        val parsed = parse(ratchetMessage)
        val ratchet = importRatchet(state)
        val plaintext = ratchet.decrypt(parsed, state.associatedData)
            .getOrElse { throw ProtocolException.DecryptionFailed("Could not decrypt message", it) }

        // An authenticated message from the remote side proves it has the
        // session, so the initiator can stop sending prekey messages.
        val updated = state.advanced(pending = null, ratchet = ratchet.exportToArray())
        state.ratchet.fill(0)
        return DecryptionResult(plaintext, session.copy(state = updated.encodeAndWipe()))
    }

    /**
     * A [PreKeyMessage] on an existing session is only the initiator
     * repeating its X3DH data until it sees a reply. So the local device
     * must be the session's responder (never its initiator: that is how a
     * reflected or rewrapped message would pin the local identity as the
     * remote one, finding F9), the message must name the session's
     * initiator, have the session's initiation version, and belong to the
     * initiation that created the session.
     */
    private fun checkRepeatedInitiation(state: SessionState, message: PreKeyMessage, localIdentityKey: ByteArray) {
        if (message.initiationVersion != state.initiationVersion) {
            throw ProtocolException.InvalidMessage("Prekey message has another session initiation version")
        }
        if (!state.responderIdentityKey.contentEquals(localIdentityKey) || state.initiatorIdentityKey.contentEquals(localIdentityKey)) {
            throw ProtocolException.InvalidMessage("Prekey message for a session this device did not accept")
        }
        if (!state.initiatorIdentityKey.contentEquals(message.identityKey)) {
            throw ProtocolException.InvalidMessage("Prekey message is from a different identity")
        }
        when (state.initiationVersion) {
            SessionInitiationVersion.V2 -> {
                // Every field the transcript binds must be the session's own.
                val initiation = state.initiation ?: throw ProtocolException.InvalidSessionState("Version 2 session without initiation")
                if (!initiation.ephemeralKey.contentEquals(message.ephemeralKey) ||
                    initiation.signedPreKeyId != message.signedPreKeyId ||
                    initiation.oneTimePreKeyId != message.oneTimePreKeyId
                ) {
                    throw ProtocolException.InvalidMessage("Prekey message belongs to another session initiation")
                }
            }
            SessionInitiationVersion.V1 -> {
                // A session set up by another initiation cannot decrypt it.
                val origin = state.origin
                if (origin != null && origin != SessionInitiationId.of(message, state.responderIdentityKey)) {
                    throw ProtocolException.InvalidMessage("Prekey message belongs to another session initiation")
                }
            }
        }
    }

    override fun sessionInfo(session: SecureSession): SessionInfo {
        val state = SessionState.decode(session.state)
        state.ratchet.fill(0)
        return SessionInfo(
            initiationId = state.origin,
            awaitingReply = state.pending != null,
            acceptedSignedPreKeyId = state.acceptedSignedPreKeyId,
            initiationVersion = state.initiationVersion,
        )
    }

    override fun sessionRemoteIdentityKey(session: SecureSession, localIdentityKey: ByteArray): ByteArray? {
        val state = SessionState.decode(session.state)
        state.ratchet.fill(0)
        val initiatorIsLocal = state.initiatorIdentityKey.contentEquals(localIdentityKey)
        val responderIsLocal = state.responderIdentityKey.contentEquals(localIdentityKey)
        return when {
            initiatorIsLocal && !responderIsLocal -> state.responderIdentityKey.copyOf()
            responderIsLocal && !initiatorIsLocal -> state.initiatorIdentityKey.copyOf()
            // Both or neither slot is the local key: the remote identity cannot be told apart.
            else -> null
        }
    }

    private fun importRatchet(state: SessionState): DoubleRatchetSession =
        DoubleRatchetSession.importFromArray(state.ratchet)
            .getOrElse { throw ProtocolException.InvalidSessionState("Stored ratchet state is invalid", it) }

    private fun parse(message: RatchetMessage): KodiumRatchetMessage {
        if (message.bytes.size < RATCHET_HEADER_SIZE) {
            throw ProtocolException.InvalidMessage("Ratchet message is truncated")
        }
        return try {
            KodiumRatchetMessage.deserialize(message.bytes)
        } catch (e: IllegalArgumentException) {
            throw ProtocolException.InvalidMessage("Ratchet message is malformed", e)
        }
    }

    private fun bundleKey(bytes: ByteArray): KodiumPublicKey =
        publicKey(bytes) ?: throw ProtocolException.InvalidPreKeyBundle("Prekey bundle contains a malformed public key")

    private fun messageKey(bytes: ByteArray): KodiumPublicKey =
        publicKey(bytes) ?: throw ProtocolException.InvalidMessage("Prekey message contains a malformed public key")

    private fun publicKey(bytes: ByteArray): KodiumPublicKey? =
        if (bytes.size != PUBLIC_KEY_SIZE) {
            null
        } else {
            KodiumPublicKey(bytes.copyOfRange(0, KEY_SIZE), bytes.copyOfRange(KEY_SIZE, PUBLIC_KEY_SIZE))
        }

    private fun privateKey(bytes: ByteArray): KodiumPrivateKey {
        require(bytes.size == KEY_SIZE) { "Private key has an invalid size" }
        // fromRaw keeps a reference to its argument; pass a copy so Kodium
        // never shares the caller's array.
        return KodiumPrivateKey.fromRaw(bytes.copyOf())
    }

    private fun KodiumPublicKey.toBytes(): ByteArray = encryptionKey + signingKey

    private fun SessionState.encodeAndWipe(): ByteArray = encode().also { ratchet.fill(0) }

    private companion object {
        const val KEY_SIZE = 32
        const val PUBLIC_KEY_SIZE = ProtocolConstants.PUBLIC_KEY_SIZE
        const val RATCHET_HEADER_SIZE = 72

        // Domain separation for KSecureMessage sessions, see ProtocolConstants.
        val X3DH_INFO = ProtocolConstants.X3DH_INFO.encodeToByteArray()
        val RATCHET_INFO = ProtocolConstants.RATCHET_INFO.encodeToByteArray()
    }
}
