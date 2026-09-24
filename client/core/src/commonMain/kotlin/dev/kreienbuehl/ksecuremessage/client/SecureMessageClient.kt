package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import kotlin.uuid.Uuid

/**
 * Sends and receives messages for [localAddress]. Envelope payloads are
 * [CiphertextMessageCodec]-encoded ciphertext messages.
 *
 * Every operation stores the new session state in the same
 * [ClientStorage.transaction] as the crypto work, and only after all fallible
 * steps succeeded. A failed encrypt or decrypt leaves the stored session as
 * it was.
 *
 * Not handled yet: the remote identity key in a first-contact
 * [PreKeyMessage] is accepted without a trust check, and a new session from a
 * sender that already has one (reinstall, simultaneous initiation) fails.
 */
class SecureMessageClient(
    val localAddress: DeviceAddress,
    private val localIdentity: LocalIdentity,
    private val storage: ClientStorage,
    private val protocol: ProtocolEngine,
    private val transport: SecureMessageTransport,
) {
    suspend fun ensureSession(remote: DeviceAddress) = storage.transaction {
        sessions.load(remote) ?: initiateSession(remote).also { sessions.store(it) }
    }

    /** Encrypts [plaintext] for [remote], starting a session if there is none. */
    suspend fun encrypt(
        remote: DeviceAddress,
        plaintext: ByteArray,
        id: MessageId = MessageId(Uuid.random().toString()),
    ): EncryptedEnvelope = storage.transaction {
        val session = sessions.load(remote) ?: initiateSession(remote)
        val result = protocol.encrypt(session, plaintext)
        val payload = CiphertextMessageCodec.encode(result.message)
        sessions.store(result.updatedSession)
        EncryptedEnvelope(
            id = id,
            sender = localAddress,
            recipient = remote,
            protocolVersion = ENVELOPE_VERSION,
            payload = payload,
        )
    }

    /** [encrypt]s [plaintext] and hands the envelope to the transport. */
    suspend fun send(remote: DeviceAddress, plaintext: ByteArray): EncryptedEnvelope =
        encrypt(remote, plaintext).also { transport.send(it) }

    suspend fun decrypt(envelope: EncryptedEnvelope): ByteArray {
        if (envelope.protocolVersion != ENVELOPE_VERSION) {
            throw ProtocolException.InvalidMessage("Unsupported envelope version")
        }
        if (envelope.recipient != localAddress) {
            throw ProtocolException.InvalidMessage("Envelope is addressed to another device")
        }
        // Decode first: a PreKeyMessage is valid without an existing session.
        val message = CiphertextMessageCodec.decode(envelope.payload)
        val sender = envelope.sender

        return storage.transaction {
            val session = sessions.load(sender)
            if (session != null) {
                // Also covers repeated PreKeyMessages from the initiator.
                val result = protocol.decrypt(session, message)
                sessions.store(result.updatedSession)
                result.plaintext
            } else {
                when (message) {
                    is PreKeyMessage -> acceptSession(sender, message)
                    is RatchetMessage -> throw ProtocolException.InvalidSessionState("No session with the sender")
                }
            }
        }
    }

    private suspend fun initiateSession(remote: DeviceAddress): SecureSession =
        protocol.initiateSession(localIdentity, transport.fetchPreKeyBundle(remote))

    private suspend fun ClientStorage.acceptSession(sender: DeviceAddress, message: PreKeyMessage): ByteArray {
        val signedPreKey = preKeys.signedPreKey(message.signedPreKeyId)
            ?: throw ProtocolException.InvalidMessage("Unknown signed prekey")
        val oneTimePreKey = message.oneTimePreKeyId?.let { id ->
            // Missing usually means it was already consumed by another session.
            preKeys.oneTimePreKey(id) ?: throw ProtocolException.InvalidMessage("Unknown one-time prekey")
        }
        val result = protocol.acceptSession(localIdentity, sender, signedPreKey, oneTimePreKey, message)
        sessions.store(result.session)
        result.consumedOneTimePreKeyId?.let { preKeys.removeOneTimePreKey(it) }
        return result.plaintext
    }

    private companion object {
        /** Version of the envelope metadata, see [EncryptedEnvelope.protocolVersion]. */
        const val ENVELOPE_VERSION = 1
    }
}
