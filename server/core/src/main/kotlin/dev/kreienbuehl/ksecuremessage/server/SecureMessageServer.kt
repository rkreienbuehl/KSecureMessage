package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage

class SecureMessageServer(
    private val storage: ServerStorage,
) {
    suspend fun publishPreKeys(bundle: PreKeyBundle) = storage.preKeys.publish(bundle)

    suspend fun getPreKeys(address: DeviceAddress): PreKeyBundle? = storage.preKeys.get(address)

    suspend fun relay(envelope: EncryptedEnvelope) = storage.mailboxes.enqueue(envelope)

    suspend fun receive(address: DeviceAddress): List<EncryptedEnvelope> = storage.mailboxes.drain(address)
}
