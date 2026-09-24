package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.CiphertextMessage
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
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
 * associated data. This engine verifies the signature before key agreement
 * and uses `initiatorIdentityKey || responderIdentityKey` as associated data
 * for every ratchet message, as in the X3DH specification.
 */
class KodiumProtocolEngine : ProtocolEngine {
    override suspend fun createIdentity(): LocalIdentity {
        val key = KodiumPrivateKey.generate()
        return LocalIdentity(publicKey = key.getPublicKey().toBytes(), privateKey = key.exportToArray())
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

    override suspend fun initiateSession(localIdentity: LocalIdentity, remoteBundle: PreKeyBundle): SecureSession {
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

        val state = SessionState(
            associatedData = localIdentity.publicKey + remoteBundle.identityKey,
            pending = PendingPreKey(
                identityKey = localIdentity.publicKey.copyOf(),
                ephemeralKey = ephemeralKey.getPublicKey().toBytes(),
                signedPreKeyId = remoteBundle.signedPreKey.id,
                oneTimePreKeyId = remoteBundle.oneTimePreKey?.id,
            ),
            ratchet = ratchet.exportToArray(),
        )
        return SecureSession(remoteBundle.address, state.encodeAndWipe())
    }

    override suspend fun acceptSession(
        localIdentity: LocalIdentity,
        remote: DeviceAddress,
        signedPreKey: SignedPreKeyPair,
        oneTimePreKey: OneTimePreKeyPair?,
        message: PreKeyMessage,
    ): SessionAcceptanceResult {
        if (signedPreKey.id != message.signedPreKeyId) {
            throw ProtocolException.InvalidMessage("Signed prekey ID does not match the message")
        }
        if (oneTimePreKey?.id != message.oneTimePreKeyId) {
            throw ProtocolException.InvalidMessage("One-time prekey ID does not match the message")
        }
        val initiatorIdentityKey = messageKey(message.identityKey)
        val initiatorEphemeralKey = messageKey(message.ephemeralKey)
        val ratchetMessage = parse(message.message)

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
            val associatedData = message.identityKey + localIdentity.publicKey
            val plaintext = ratchet.decrypt(ratchetMessage, associatedData)
                .getOrElse { throw ProtocolException.DecryptionFailed("Could not decrypt the first message", it) }
            val state = SessionState(associatedData, pending = null, ratchet = ratchet.exportToArray())
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
            )
        }
        val updated = SessionState(state.associatedData, pending, ratchet.exportToArray())
        state.ratchet.fill(0)
        return EncryptionResult(message, session.copy(state = updated.encodeAndWipe()))
    }

    override suspend fun decrypt(session: SecureSession, message: CiphertextMessage): DecryptionResult {
        val state = SessionState.decode(session.state)
        val ratchetMessage = when (message) {
            is RatchetMessage -> message
            is PreKeyMessage -> {
                // Initiator repeats its X3DH data until it sees a reply; it
                // must belong to the identity this session was set up with.
                if (!state.associatedData.startsWith(message.identityKey)) {
                    throw ProtocolException.InvalidMessage("Prekey message is from a different identity")
                }
                message.message
            }
        }
        val parsed = parse(ratchetMessage)
        val ratchet = importRatchet(state)
        val plaintext = ratchet.decrypt(parsed, state.associatedData)
            .getOrElse { throw ProtocolException.DecryptionFailed("Could not decrypt message", it) }

        // An authenticated message from the remote side proves it has the
        // session, so the initiator can stop sending prekey messages.
        val updated = SessionState(state.associatedData, pending = null, ratchet = ratchet.exportToArray())
        state.ratchet.fill(0)
        return DecryptionResult(plaintext, session.copy(state = updated.encodeAndWipe()))
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

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
        size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }

    private companion object {
        const val KEY_SIZE = 32
        const val PUBLIC_KEY_SIZE = 64
        const val RATCHET_HEADER_SIZE = 72

        // Domain separation for KSecureMessage sessions. Changing these breaks
        // all existing sessions.
        val X3DH_INFO = "KSecureMessage-X3DH-v1".encodeToByteArray()
        val RATCHET_INFO = "KSecureMessage-Ratchet-v1".encodeToByteArray()
    }
}
