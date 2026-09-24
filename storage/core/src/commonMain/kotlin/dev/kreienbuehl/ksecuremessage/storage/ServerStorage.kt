package dev.kreienbuehl.ksecuremessage.storage

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle

interface PreKeyRepository {
    suspend fun publish(bundle: PreKeyBundle)
    suspend fun get(address: DeviceAddress): PreKeyBundle?
}

interface MailboxRepository {
    suspend fun enqueue(envelope: EncryptedEnvelope)
    suspend fun drain(recipient: DeviceAddress): List<EncryptedEnvelope>
}

interface ServerStorage {
    val preKeys: PreKeyRepository
    val mailboxes: MailboxRepository
}
