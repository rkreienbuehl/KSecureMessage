package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage

class SecureMessageClient(
    val localAddress: DeviceAddress,
    private val storage: ClientStorage,
    private val protocol: ProtocolEngine,
    private val transport: SecureMessageTransport,
) {
    suspend fun ensureSession(remote: DeviceAddress) = storage.transaction {
        sessions.load(remote) ?: protocol
            .establishInitiatorSession(transport.fetchPreKeyBundle(remote))
            .also { sessions.store(it) }
    }

    suspend fun decrypt(envelope: EncryptedEnvelope): ByteArray = storage.transaction {
        val session = sessions.load(envelope.sender)
            ?: error("No session for ${envelope.sender}")

        val result = protocol.decrypt(session, envelope.payload)
        sessions.store(result.updatedSession)
        result.plaintext
    }
}
