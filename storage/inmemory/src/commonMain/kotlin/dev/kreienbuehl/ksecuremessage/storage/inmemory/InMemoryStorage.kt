package dev.kreienbuehl.ksecuremessage.storage.inmemory

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.IdentityStore
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.SessionStore
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext

/**
 * Non-persistent [ClientStorage] for tests and examples.
 *
 * Transactions are atomic: a transaction works on a copy of the committed
 * state and replaces it only when the block returns normally. A [Mutex]
 * serializes transactions. Byte arrays are copied on the way in and out, so
 * callers cannot change stored keys or sessions through an alias.
 */
class InMemoryClientStorage : ClientStorage {
    private val mutex = Mutex()
    private var committed = State()

    override val identity: IdentityStore = object : IdentityStore {
        override suspend fun identity() = transaction { identity.identity() }
        override suspend fun store(identity: LocalIdentity) = transaction { this.identity.store(identity) }
    }

    override val sessions: SessionStore = object : SessionStore {
        override suspend fun load(address: DeviceAddress) = transaction { sessions.load(address) }
        override suspend fun store(session: SecureSession) = transaction { sessions.store(session) }
        override suspend fun remove(address: DeviceAddress) = transaction { sessions.remove(address) }
    }

    override val preKeys: PreKeyStore = object : PreKeyStore {
        override suspend fun signedPreKey(id: SignedPreKeyId) = transaction { preKeys.signedPreKey(id) }
        override suspend fun currentSignedPreKey() = transaction { preKeys.currentSignedPreKey() }
        override suspend fun storeCurrentSignedPreKey(preKey: SignedPreKeyPair) =
            transaction { preKeys.storeCurrentSignedPreKey(preKey) }
        override suspend fun highestSignedPreKeyId() = transaction { preKeys.highestSignedPreKeyId() }
        override suspend fun oneTimePreKey(id: OneTimePreKeyId) = transaction { preKeys.oneTimePreKey(id) }
        override suspend fun publicOneTimePreKeys() = transaction { preKeys.publicOneTimePreKeys() }
        override suspend fun oneTimePreKeyCount() = transaction { preKeys.oneTimePreKeyCount() }
        override suspend fun storeOneTimePreKeys(preKeys: List<OneTimePreKeyPair>) =
            transaction { this.preKeys.storeOneTimePreKeys(preKeys) }
        override suspend fun removeOneTimePreKey(id: OneTimePreKeyId) = transaction { preKeys.removeOneTimePreKey(id) }
        override suspend fun highestOneTimePreKeyId() = transaction { preKeys.highestOneTimePreKeyId() }
    }

    override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T {
        val active = currentCoroutineContext()[ActiveTransaction]
        if (active != null && active.owner === this) return active.view.block()

        return mutex.withLock {
            val view = TransactionView(committed)
            val result = withContext(ActiveTransaction(this, view)) { view.block() }
            committed = view.state
            result
        }
    }

    /** Marks the coroutine that runs a transaction, so nested calls join it. */
    private class ActiveTransaction(
        val owner: InMemoryClientStorage,
        val view: TransactionView,
    ) : CoroutineContext.Element {
        override val key: CoroutineContext.Key<*> get() = ActiveTransaction

        companion object : CoroutineContext.Key<ActiveTransaction>
    }
}

private data class State(
    val identity: LocalIdentity? = null,
    val sessions: Map<DeviceAddress, SecureSession> = emptyMap(),
    val signedPreKeys: Map<SignedPreKeyId, SignedPreKeyPair> = emptyMap(),
    val currentSignedPreKeyId: SignedPreKeyId? = null,
    val highestSignedPreKeyId: SignedPreKeyId? = null,
    val oneTimePreKeys: Map<OneTimePreKeyId, OneTimePreKeyPair> = emptyMap(),
    val highestOneTimePreKeyId: OneTimePreKeyId? = null,
)

/** Uncommitted state of one transaction. */
private class TransactionView(var state: State) : ClientStorage {
    override val identity: IdentityStore = object : IdentityStore {
        override suspend fun identity() = state.identity?.copy()

        override suspend fun store(identity: LocalIdentity) {
            check(state.identity == null) { "A local identity is already stored" }
            state = state.copy(identity = identity.copy())
        }
    }

    override val sessions: SessionStore = object : SessionStore {
        override suspend fun load(address: DeviceAddress) = state.sessions[address]?.copyState()

        override suspend fun store(session: SecureSession) {
            state = state.copy(sessions = state.sessions + (session.remote to session.copyState()))
        }

        override suspend fun remove(address: DeviceAddress) {
            state = state.copy(sessions = state.sessions - address)
        }
    }

    override val preKeys: PreKeyStore = object : PreKeyStore {
        override suspend fun signedPreKey(id: SignedPreKeyId) = state.signedPreKeys[id]?.copy()

        override suspend fun currentSignedPreKey() = state.currentSignedPreKeyId?.let { state.signedPreKeys[it]?.copy() }

        override suspend fun storeCurrentSignedPreKey(preKey: SignedPreKeyPair) {
            require(preKey.id.value > (state.highestSignedPreKeyId?.value ?: -1)) { "Signed prekey ID already used" }
            state = state.copy(
                signedPreKeys = state.signedPreKeys + (preKey.id to preKey.copy()),
                currentSignedPreKeyId = preKey.id,
                highestSignedPreKeyId = preKey.id,
            )
        }

        override suspend fun highestSignedPreKeyId() = state.highestSignedPreKeyId

        override suspend fun oneTimePreKey(id: OneTimePreKeyId) = state.oneTimePreKeys[id]?.copy()

        override suspend fun publicOneTimePreKeys(): List<PublicOneTimePreKey> =
            state.oneTimePreKeys.values.sortedBy { it.id.value }.map { it.copy().toPublic() }

        override suspend fun oneTimePreKeyCount() = state.oneTimePreKeys.size

        override suspend fun storeOneTimePreKeys(preKeys: List<OneTimePreKeyPair>) {
            if (preKeys.isEmpty()) return
            val ids = preKeys.map { it.id }
            require(ids.toSet().size == ids.size) { "Duplicate one-time prekey ID" }
            val highest = state.highestOneTimePreKeyId?.value ?: -1
            require(ids.all { it.value > highest }) { "One-time prekey ID already used" }
            state = state.copy(
                oneTimePreKeys = state.oneTimePreKeys + preKeys.associate { it.id to it.copy() },
                highestOneTimePreKeyId = ids.maxBy { it.value },
            )
        }

        override suspend fun removeOneTimePreKey(id: OneTimePreKeyId) {
            state = state.copy(oneTimePreKeys = state.oneTimePreKeys - id)
        }

        override suspend fun highestOneTimePreKeyId() = state.highestOneTimePreKeyId
    }

    override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = block()
}

private fun LocalIdentity.copy() = LocalIdentity(publicKey.copyOf(), privateKey.copyOf())

private fun SignedPreKeyPair.copy() = SignedPreKeyPair(id, publicKey.copyOf(), signature.copyOf(), privateKey.copyOf())

private fun OneTimePreKeyPair.copy() = OneTimePreKeyPair(id, publicKey.copyOf(), privateKey.copyOf())

private fun SecureSession.copyState() = copy(state = state.copyOf())

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
