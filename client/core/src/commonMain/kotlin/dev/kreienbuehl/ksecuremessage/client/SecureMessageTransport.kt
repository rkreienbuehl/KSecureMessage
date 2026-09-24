package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle

interface SecureMessageTransport {
    suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle
    suspend fun send(envelope: EncryptedEnvelope)
    suspend fun receive(address: DeviceAddress): List<EncryptedEnvelope>
}
