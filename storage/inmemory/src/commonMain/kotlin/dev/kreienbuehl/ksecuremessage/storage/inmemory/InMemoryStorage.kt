package dev.kreienbuehl.ksecuremessage.storage.inmemory

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.IdentityStore
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
import dev.kreienbuehl.ksecuremessage.storage.RemoteIdentityStore
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.SessionInitiationStore
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

    override val remoteIdentities: RemoteIdentityStore = object : RemoteIdentityStore {
        override suspend fun identityKey(address: DeviceAddress) = transaction { remoteIdentities.identityKey(address) }
        override suspend fun store(address: DeviceAddress, identityKey: ByteArray) =
            transaction { remoteIdentities.store(address, identityKey) }
    }

    override val sessions: SessionStore = object : SessionStore {
        override suspend fun load(address: DeviceAddress) = transaction { sessions.load(address) }
        override suspend fun store(session: SecureSession) = transaction { sessions.store(session) }
        override suspend fun remove(address: DeviceAddress) = transaction { sessions.remove(address) }
    }

    override val sessionInitiations: SessionInitiationStore = object : SessionInitiationStore {
        override suspend fun isRetired(remote: DeviceAddress, id: SessionInitiationId) =
            transaction { sessionInitiations.isRetired(remote, id) }
        override suspend fun retire(remote: DeviceAddress, id: SessionInitiationId) =
            transaction { sessionInitiations.retire(remote, id) }
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
    val remoteIdentities: Map<DeviceAddress, ByteArray> = emptyMap(),
    val sessions: Map<DeviceAddress, SecureSession> = emptyMap(),
    val retiredInitiations: Map<DeviceAddress, Set<SessionInitiationId>> = emptyMap(),
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

    override val remoteIdentities: RemoteIdentityStore = object : RemoteIdentityStore {
        override suspend fun identityKey(address: DeviceAddress) = state.remoteIdentities[address]?.copyOf()

        override suspend fun store(address: DeviceAddress, identityKey: ByteArray) {
            val pinned = state.remoteIdentities[address]
            if (pinned != null) {
                check(pinned.contentEquals(identityKey)) { "A different remote identity is already pinned" }
                return
            }
            state = state.copy(remoteIdentities = state.remoteIdentities + (address to identityKey.copyOf()))
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

    // SessionInitiationId is immutable (it copies its bytes), so no copies needed.
    override val sessionInitiations: SessionInitiationStore = object : SessionInitiationStore {
        override suspend fun isRetired(remote: DeviceAddress, id: SessionInitiationId) =
            state.retiredInitiations[remote]?.contains(id) == true

        override suspend fun retire(remote: DeviceAddress, id: SessionInitiationId) {
            val retired = state.retiredInitiations[remote].orEmpty()
            state = state.copy(retiredInitiations = state.retiredInitiations + (remote to retired + id))
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

/**
 * Non-persistent [ServerStorage] for tests and examples.
 *
 * The prekey repository keeps immutable state behind a [Mutex]: publication
 * and bundle consumption each run under the lock and replace the state only
 * after all checks passed, so they are atomic and serialized. The mailboxes
 * are one queue per recipient behind another [Mutex], so enqueue and drain
 * are serialized too and each recipient's queue is in enqueue order. That is
 * stronger than the per (sender, recipient) order [MailboxRepository]
 * promises.
 */
class InMemoryServerStorage : ServerStorage {
    override val preKeys: PreKeyRepository = InMemoryPreKeyRepository()

    override val mailboxes: MailboxRepository = InMemoryMailboxRepository()
}

private class InMemoryMailboxRepository : MailboxRepository {
    private val mutex = Mutex()
    private val queues = mutableMapOf<DeviceAddress, ArrayDeque<EncryptedEnvelope>>()

    override suspend fun enqueue(envelope: EncryptedEnvelope) = mutex.withLock {
        queues.getOrPut(envelope.recipient) { ArrayDeque() }.addLast(envelope)
    }

    override suspend fun drain(recipient: DeviceAddress): List<EncryptedEnvelope> = mutex.withLock {
        queues.remove(recipient)?.toList().orEmpty()
    }
}

/** Published state of one device. Arrays are never handed out without a copy. */
private data class DeviceKeys(
    val identityKey: ByteArray,
    val signedPreKey: PublicSignedPreKey,
    /** Available one-time prekeys, public key by ID. */
    val available: Map<OneTimePreKeyId, ByteArray>,
    /** IDs already handed out. Never published again. */
    val consumed: Set<OneTimePreKeyId>,
)

private class InMemoryPreKeyRepository : PreKeyRepository {
    private val mutex = Mutex()
    private var devices = mapOf<DeviceAddress, DeviceKeys>()

    override suspend fun publish(publication: PreKeyPublication) = mutex.withLock {
        val ids = publication.oneTimePreKeys.map { it.id }
        if (ids.toSet().size != ids.size) {
            throw PreKeyPublicationException.InvalidPublication("Duplicate one-time prekey ID")
        }
        val existing = devices[publication.address]
        if (existing != null && !existing.identityKey.contentEquals(publication.identityKey)) {
            throw PreKeyPublicationException.IdentityKeyConflict()
        }
        val signedPreKey = publication.signedPreKey
        if (existing != null) checkSignedPreKey(existing.signedPreKey, signedPreKey)

        val available = existing?.available.orEmpty().toMutableMap()
        val consumed = existing?.consumed.orEmpty()
        for (preKey in publication.oneTimePreKeys) {
            if (preKey.id in consumed) continue
            val stored = available[preKey.id]
            when {
                stored == null -> available[preKey.id] = preKey.publicKey.copyOf()
                !stored.contentEquals(preKey.publicKey) -> throw PreKeyPublicationException.OneTimePreKeyConflict(preKey.id)
            }
        }
        // All checks passed: commit.
        devices = devices + (publication.address to DeviceKeys(
            identityKey = publication.identityKey.copyOf(),
            signedPreKey = signedPreKey.deepCopy(),
            available = available,
            consumed = consumed,
        ))
    }

    private fun checkSignedPreKey(current: PublicSignedPreKey, published: PublicSignedPreKey) {
        when {
            published.id.value < current.id.value ->
                throw PreKeyPublicationException.SignedPreKeyConflict("Signed prekey is older than the current one")
            published.id == current.id && (
                !published.publicKey.contentEquals(current.publicKey) ||
                    !published.signature.contentEquals(current.signature)
                ) ->
                throw PreKeyPublicationException.SignedPreKeyConflict("Signed prekey ID already exists with other bytes")
        }
    }

    override suspend fun consumePreKeyBundle(address: DeviceAddress): PreKeyBundle? = mutex.withLock {
        val device = devices[address] ?: return@withLock null
        val id = device.available.keys.minByOrNull { it.value }
        if (id != null) {
            devices = devices + (address to device.copy(available = device.available - id, consumed = device.consumed + id))
        }
        PreKeyBundle(
            address = address,
            identityKey = device.identityKey.copyOf(),
            signedPreKey = device.signedPreKey.deepCopy(),
            oneTimePreKey = id?.let { PublicOneTimePreKey(it, device.available.getValue(it).copyOf()) },
        )
    }

    override suspend fun oneTimePreKeyCount(address: DeviceAddress): Int =
        mutex.withLock { devices[address]?.available?.size ?: 0 }
}

// Not named copy(): the data class member would win and copy shallowly.
private fun PublicSignedPreKey.deepCopy() = PublicSignedPreKey(id, publicKey.copyOf(), signature.copyOf())
