package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
import io.kodium.KodiumPrivateKey
import io.kodium.KodiumPublicKey
import io.kodium.ratchet.DoubleRatchetSession
import io.kodium.ratchet.X3DH
import io.kodium.ratchet.RatchetMessage as KodiumRatchetMessage

/**
 * Test only: sessions exactly as KSecureMessage created them before S1
 * (session initiation version 1, associated data
 * `initiatorIdentityKey || responderIdentityKey`, milestones 1–25). The
 * production engine no longer creates or accepts such initiations; these
 * reproduce the stored sessions an upgraded device still has.
 */
internal object LegacySessions {
    private val X3DH_INFO = ProtocolConstants.X3DH_INFO.encodeToByteArray()
    private val RATCHET_INFO = ProtocolConstants.RATCHET_INFO.encodeToByteArray()

    /** The pre-S1 `initiateSession`. */
    fun initiate(local: LocalIdentity, bundle: PreKeyBundle): SecureSession {
        val remoteIdentityKey = publicKey(bundle.identityKey)
        val signedPreKey = publicKey(bundle.signedPreKey.publicKey)
        val oneTimePreKey = bundle.oneTimePreKey?.let { publicKey(it.publicKey) }
        val ephemeralKey = KodiumPrivateKey.generate()
        val sharedSecret = X3DH.calculateSecretAsInitiator(
            initiatorIdentityKey = KodiumPrivateKey.fromRaw(local.privateKey.copyOf()),
            initiatorEphemeralKey = ephemeralKey,
            responderBundle = X3DH.PublicBundle(remoteIdentityKey, signedPreKey, oneTimePreKey),
            info = X3DH_INFO,
        )
        val ratchet = DoubleRatchetSession.initializeAsInitiator(sharedSecret, signedPreKey, RATCHET_INFO)
        val associatedData = local.publicKey + bundle.identityKey
        val pending = PendingPreKey(
            identityKey = local.publicKey.copyOf(),
            ephemeralKey = ephemeralKey.getPublicKey().let { it.encryptionKey + it.signingKey },
            signedPreKeyId = bundle.signedPreKey.id,
            oneTimePreKeyId = bundle.oneTimePreKey?.id,
        )
        val state = SessionState(
            SessionInitiationVersion.V1,
            associatedData,
            local.publicKey.copyOf(),
            bundle.identityKey.copyOf(),
            pending = pending,
            initiation = null,
            origin = SessionState.originOf(associatedData, pending),
            acceptedSignedPreKeyId = null,
            ratchet = ratchet.exportToArray(),
        )
        return SecureSession(bundle.address, state.encode())
    }

    /** The pre-S1 `acceptSession`: [receiver] accepts [message] from [sender]. */
    fun accept(receiver: Party, sender: DeviceAddress, message: PreKeyMessage): SessionAcceptanceResult {
        check(message.initiationVersion == SessionInitiationVersion.V1) { "Not a legacy message" }
        val oneTimePreKey = receiver.oneTimePreKey(message.oneTimePreKeyId)
        val sharedSecret = X3DH.calculateSecretAsResponder(
            responderIdentityKey = KodiumPrivateKey.fromRaw(receiver.identity.privateKey.copyOf()),
            responderSignedPreKey = KodiumPrivateKey.fromRaw(receiver.signedPreKey.privateKey.copyOf()),
            responderOneTimePreKey = oneTimePreKey?.let { KodiumPrivateKey.fromRaw(it.privateKey.copyOf()) },
            initiatorIdentityKey = publicKey(message.identityKey),
            initiatorEphemeralKey = publicKey(message.ephemeralKey),
            info = X3DH_INFO,
        )
        val ratchet = DoubleRatchetSession.initializeAsResponder(
            sharedSecret,
            KodiumPrivateKey.fromRaw(receiver.signedPreKey.privateKey.copyOf()),
            RATCHET_INFO,
        )
        val associatedData = message.identityKey + receiver.identity.publicKey
        val plaintext = ratchet.decrypt(KodiumRatchetMessage.deserialize(message.message.bytes), associatedData).getOrThrow()
        val state = SessionState(
            SessionInitiationVersion.V1,
            associatedData,
            message.identityKey.copyOf(),
            receiver.identity.publicKey.copyOf(),
            pending = null,
            initiation = null,
            origin = SessionInitiationId.of(message, receiver.identity.publicKey),
            acceptedSignedPreKeyId = receiver.signedPreKey.id,
            ratchet = ratchet.exportToArray(),
        )
        return SessionAcceptanceResult(SecureSession(sender, state.encode()), plaintext, oneTimePreKey?.id)
    }

    /**
     * Re-encodes the version 1 [session] in the pre-S1 state format
     * [version] (1: before milestone 6, 2: milestone 6, 3: milestones 7–25).
     */
    fun encode(session: SecureSession, version: Int): SecureSession {
        val state = SessionState.decode(session.state)
        check(state.initiationVersion == SessionInitiationVersion.V1) { "Not a legacy session" }
        val out = BinaryWriter()
        out.byte(version.toByte())
        out.bytes(state.associatedData)
        val pending = state.pending
        if (pending == null) {
            out.byte(0)
        } else {
            out.byte(1)
            out.bytes(pending.identityKey)
            out.bytes(pending.ephemeralKey)
            out.int(pending.signedPreKeyId.value)
            val oneTimePreKeyId = pending.oneTimePreKeyId
            if (oneTimePreKeyId == null) out.byte(0) else { out.byte(1); out.int(oneTimePreKeyId.value) }
        }
        if (version >= 2) {
            val origin = state.origin
            if (origin == null) out.byte(0) else { out.byte(1); out.fixed(origin.bytes) }
        }
        if (version >= 3) {
            val accepted = state.acceptedSignedPreKeyId
            if (accepted == null) out.byte(0) else { out.byte(1); out.int(accepted.value) }
        }
        out.bytes(state.ratchet)
        return session.copy(state = out.toByteArray())
    }

    private fun publicKey(bytes: ByteArray) = KodiumPublicKey(bytes.copyOfRange(0, 32), bytes.copyOfRange(32, 64))
}
