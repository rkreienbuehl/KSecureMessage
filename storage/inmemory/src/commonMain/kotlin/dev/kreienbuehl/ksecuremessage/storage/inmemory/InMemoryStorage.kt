package dev.kreienbuehl.ksecuremessage.storage.inmemory

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.SessionStore

class InMemoryClientStorage : ClientStorage {
    private val sessionMap = mutableMapOf<DeviceAddress, SecureSession>()

    override val sessions: SessionStore = object : SessionStore {
        override suspend fun load(address: DeviceAddress): SecureSession? = sessionMap[address]

        override suspend fun store(session: SecureSession) {
            sessionMap[session.remote] = session
        }

        override suspend fun remove(address: DeviceAddress) {
            sessionMap.remove(address)
        }
    }

    override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = block()
}

class InMemoryServerStorage : ServerStorage {
    private val bundles = mutableMapOf<DeviceAddress, PreKeyBundle>()
    private val messages = mutableMapOf<DeviceAddress, MutableList<EncryptedEnvelope>>()

    override val preKeys: PreKeyRepository = object : PreKeyRepository {
        override suspend fun publish(bundle: PreKeyBundle) {
            bundles[bundle.address] = bundle
        }

        override suspend fun get(address: DeviceAddress): PreKeyBundle? = bundles[address]
    }

    override val mailboxes: MailboxRepository = object : MailboxRepository {
        override suspend fun enqueue(envelope: EncryptedEnvelope) {
            messages.getOrPut(envelope.recipient) { mutableListOf() }.add(envelope)
        }

        override suspend fun drain(recipient: DeviceAddress): List<EncryptedEnvelope> =
            messages.remove(recipient)?.toList().orEmpty()
    }
}
