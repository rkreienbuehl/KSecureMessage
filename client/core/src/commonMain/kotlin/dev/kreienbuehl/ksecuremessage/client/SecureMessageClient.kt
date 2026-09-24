package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage

class SecureMessageClient(
    val localAddress: DeviceAddress,
    private val localIdentity: LocalIdentity,
    private val storage: ClientStorage,
    private val protocol: ProtocolEngine,
    private val transport: SecureMessageTransport,
) {
    suspend fun ensureSession(remote: DeviceAddress) = storage.transaction {
        sessions.load(remote) ?: protocol
            .initiateSession(localIdentity, transport.fetchPreKeyBundle(remote))
            .also { sessions.store(it) }
    }

    suspend fun decrypt(envelope: EncryptedEnvelope): ByteArray =
        TODO("Milestone 2: decode EncryptedEnvelope.payload into a CiphertextMessage, then decrypt or accept the session")
}
