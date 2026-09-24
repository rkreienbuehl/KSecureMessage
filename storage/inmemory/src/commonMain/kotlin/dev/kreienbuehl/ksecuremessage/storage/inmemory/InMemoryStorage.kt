package dev.kreienbuehl.ksecuremessage.storage.inmemory

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
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

    private val signedPreKeyMap = mutableMapOf<SignedPreKeyId, SignedPreKeyPair>()
    private val oneTimePreKeyMap = mutableMapOf<OneTimePreKeyId, OneTimePreKeyPair>()

    override val preKeys: PreKeyStore = object : PreKeyStore {
        override suspend fun signedPreKey(id: SignedPreKeyId): SignedPreKeyPair? = signedPreKeyMap[id]

        override suspend fun oneTimePreKey(id: OneTimePreKeyId): OneTimePreKeyPair? = oneTimePreKeyMap[id]

        override suspend fun removeOneTimePreKey(id: OneTimePreKeyId) {
            oneTimePreKeyMap.remove(id)
        }
    }

    /** Seeds a local signed prekey. Tests and examples only. */
    fun storeSignedPreKey(preKey: SignedPreKeyPair) {
        signedPreKeyMap[preKey.id] = preKey
    }

    /** Seeds local one-time prekeys. Tests and examples only. */
    fun storeOneTimePreKeys(preKeys: List<OneTimePreKeyPair>) {
        preKeys.forEach { oneTimePreKeyMap[it.id] = it }
    }

    // Not atomic: a failing block keeps the writes it already made.
    // SecureMessageClient only writes after all fallible work succeeded.
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
