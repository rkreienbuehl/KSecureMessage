package dev.kreienbuehl.ksecuremessage.storage.inmemory

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.IdentityStore
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PendingOutboundMessage
import dev.kreienbuehl.ksecuremessage.storage.PendingOutboundStore
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
import dev.kreienbuehl.ksecuremessage.storage.ProcessedInboundStore
import dev.kreienbuehl.ksecuremessage.storage.RemoteIdentityStore
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.SessionInitiationStore
import dev.kreienbuehl.ksecuremessage.storage.SessionStore
import dev.kreienbuehl.ksecuremessage.storage.SignedPreKeyInfo
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext
import kotlin.time.Instant

/**
 * Non-persistent [ClientStorage] for tests and examples.
 *
 * Transactions are atomic: a transaction works on a copy of the committed
 * state and replaces it only when the block returns normally. A [Mutex]
 * serializes transactions. Byte arrays are copied on the way in and out, so
 * callers cannot change stored keys or sessions through an alias. It never
 * holds pre-milestone-12 state, so [DeviceAuthenticationKeyStore.awaitsUpgradeKey]
 * is always `false`.
 */
class InMemoryClientStorage : ClientStorage {
    private val mutex = Mutex()
    private var committed = State()

    override val identity: IdentityStore = object : IdentityStore {
        override suspend fun identity() = transaction { identity.identity() }
        override suspend fun store(identity: LocalIdentity) = transaction { this.identity.store(identity) }
    }

    override val deviceAuthentication: DeviceAuthenticationKeyStore = object : DeviceAuthenticationKeyStore {
        override suspend fun keyPair() = transaction { deviceAuthentication.keyPair() }
        override suspend fun store(keyPair: DeviceAuthenticationKeyPair) = transaction { deviceAuthentication.store(keyPair) }
        override suspend fun awaitsUpgradeKey() = transaction { deviceAuthentication.awaitsUpgradeKey() }
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
        override suspend fun retire(remote: DeviceAddress, id: SessionInitiationId, signedPreKeyId: SignedPreKeyId?) =
            transaction { sessionInitiations.retire(remote, id, signedPreKeyId) }
        override suspend fun retiredSignedPreKeyIds() = transaction { sessionInitiations.retiredSignedPreKeyIds() }
        override suspend fun removeRetiredFor(signedPreKeyId: SignedPreKeyId) =
            transaction { sessionInitiations.removeRetiredFor(signedPreKeyId) }
    }

    override val preKeys: PreKeyStore = object : PreKeyStore {
        override suspend fun signedPreKey(id: SignedPreKeyId) = transaction { preKeys.signedPreKey(id) }
        override suspend fun currentSignedPreKey() = transaction { preKeys.currentSignedPreKey() }
        override suspend fun storeCurrentSignedPreKey(preKey: SignedPreKeyPair, createdAt: Instant) =
            transaction { preKeys.storeCurrentSignedPreKey(preKey, createdAt) }
        override suspend fun signedPreKeyInfo(id: SignedPreKeyId) = transaction { preKeys.signedPreKeyInfo(id) }
        override suspend fun signedPreKeyInfos() = transaction { preKeys.signedPreKeyInfos() }
        override suspend fun stampLegacySignedPreKeys(at: Instant) = transaction { preKeys.stampLegacySignedPreKeys(at) }
        override suspend fun removeSignedPreKey(id: SignedPreKeyId) = transaction { preKeys.removeSignedPreKey(id) }
        override suspend fun highestSignedPreKeyId() = transaction { preKeys.highestSignedPreKeyId() }
        override suspend fun oneTimePreKey(id: OneTimePreKeyId) = transaction { preKeys.oneTimePreKey(id) }
        override suspend fun publicOneTimePreKeys() = transaction { preKeys.publicOneTimePreKeys() }
        override suspend fun oneTimePreKeyCount() = transaction { preKeys.oneTimePreKeyCount() }
        override suspend fun storeOneTimePreKeys(preKeys: List<OneTimePreKeyPair>) =
            transaction { this.preKeys.storeOneTimePreKeys(preKeys) }
        override suspend fun removeOneTimePreKey(id: OneTimePreKeyId) = transaction { preKeys.removeOneTimePreKey(id) }
        override suspend fun highestOneTimePreKeyId() = transaction { preKeys.highestOneTimePreKeyId() }
    }

    override val pendingOutbound: PendingOutboundStore = object : PendingOutboundStore {
        override suspend fun store(recipient: DeviceAddress, id: LogicalMessageId, frame: ByteArray) =
            transaction { pendingOutbound.store(recipient, id, frame) }
        override suspend fun get(recipient: DeviceAddress, id: LogicalMessageId) = transaction { pendingOutbound.get(recipient, id) }
        override suspend fun list(recipient: DeviceAddress) = transaction { pendingOutbound.list(recipient) }
        override suspend fun remove(recipient: DeviceAddress, id: LogicalMessageId) =
            transaction { pendingOutbound.remove(recipient, id) }
    }

    override val processedInbound: ProcessedInboundStore = object : ProcessedInboundStore {
        override suspend fun isProcessed(sender: DeviceAddress, id: LogicalMessageId) =
            transaction { processedInbound.isProcessed(sender, id) }
        override suspend fun markProcessed(sender: DeviceAddress, id: LogicalMessageId) =
            transaction { processedInbound.markProcessed(sender, id) }
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
    val deviceAuthenticationKey: DeviceAuthenticationKeyPair? = null,
    val remoteIdentities: Map<DeviceAddress, ByteArray> = emptyMap(),
    val sessions: Map<DeviceAddress, SecureSession> = emptyMap(),
    /** Retired initiation to the local signed prekey it needs, if known. */
    val retiredInitiations: Map<DeviceAddress, Map<SessionInitiationId, SignedPreKeyId?>> = emptyMap(),
    val signedPreKeys: Map<SignedPreKeyId, SignedPreKeyPair> = emptyMap(),
    val signedPreKeyTimes: Map<SignedPreKeyId, SignedPreKeyTimes> = emptyMap(),
    val currentSignedPreKeyId: SignedPreKeyId? = null,
    val highestSignedPreKeyId: SignedPreKeyId? = null,
    val oneTimePreKeys: Map<OneTimePreKeyId, OneTimePreKeyPair> = emptyMap(),
    val highestOneTimePreKeyId: OneTimePreKeyId? = null,
    /** Pending messages by (recipient, logical ID); frames are copied on the way in and out. */
    val pendingOutbound: Map<Pair<DeviceAddress, LogicalMessageId>, PendingEntry> = emptyMap(),
    /** Highest pending sequence number ever assigned; never lowered. */
    val highestPendingSequence: Long = 0,
    val processedInbound: Set<Pair<DeviceAddress, LogicalMessageId>> = emptySet(),
)

private class PendingEntry(val sequence: Long, val frame: ByteArray)

/** Lifecycle timestamps of a stored signed prekey; `null` until stamped (see PreKeyStore). */
private data class SignedPreKeyTimes(val createdAt: Instant?, val replacedAt: Instant?)

/** Uncommitted state of one transaction. */
private class TransactionView(var state: State) : ClientStorage {
    override val pendingOutbound: PendingOutboundStore = object : PendingOutboundStore {
        override suspend fun store(recipient: DeviceAddress, id: LogicalMessageId, frame: ByteArray): Long {
            require((recipient to id) !in state.pendingOutbound) { "Message is already pending" }
            val sequence = state.highestPendingSequence + 1
            state = state.copy(
                pendingOutbound = state.pendingOutbound + ((recipient to id) to PendingEntry(sequence, frame.copyOf())),
                highestPendingSequence = sequence,
            )
            return sequence
        }

        override suspend fun get(recipient: DeviceAddress, id: LogicalMessageId) =
            state.pendingOutbound[recipient to id]?.let { PendingOutboundMessage(recipient, id, it.sequence, it.frame.copyOf()) }

        override suspend fun list(recipient: DeviceAddress) = state.pendingOutbound
            .filterKeys { it.first == recipient }
            .map { (key, entry) -> PendingOutboundMessage(recipient, key.second, entry.sequence, entry.frame.copyOf()) }
            .sortedBy { it.sequence }

        override suspend fun remove(recipient: DeviceAddress, id: LogicalMessageId): Boolean {
            if ((recipient to id) !in state.pendingOutbound) return false
            state = state.copy(pendingOutbound = state.pendingOutbound - (recipient to id))
            return true
        }
    }

    override val processedInbound: ProcessedInboundStore = object : ProcessedInboundStore {
        override suspend fun isProcessed(sender: DeviceAddress, id: LogicalMessageId) = (sender to id) in state.processedInbound

        override suspend fun markProcessed(sender: DeviceAddress, id: LogicalMessageId) {
            state = state.copy(processedInbound = state.processedInbound + (sender to id))
        }
    }

    override val identity: IdentityStore = object : IdentityStore {
        override suspend fun identity() = state.identity?.copy()

        override suspend fun store(identity: LocalIdentity) {
            check(state.identity == null) { "A local identity is already stored" }
            state = state.copy(identity = identity.copy())
        }
    }

    override val deviceAuthentication: DeviceAuthenticationKeyStore = object : DeviceAuthenticationKeyStore {
        override suspend fun keyPair() = state.deviceAuthenticationKey?.copy()

        override suspend fun store(keyPair: DeviceAuthenticationKeyPair) {
            check(state.deviceAuthenticationKey == null) { "A device authentication key is already stored" }
            state = state.copy(deviceAuthenticationKey = keyPair.copy())
        }

        override suspend fun awaitsUpgradeKey() = false
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
            state.retiredInitiations[remote]?.containsKey(id) == true

        override suspend fun retire(remote: DeviceAddress, id: SessionInitiationId, signedPreKeyId: SignedPreKeyId?) {
            val retired = state.retiredInitiations[remote].orEmpty()
            if (id in retired) return
            state = state.copy(retiredInitiations = state.retiredInitiations + (remote to retired + (id to signedPreKeyId)))
        }

        override suspend fun retiredSignedPreKeyIds(): Set<SignedPreKeyId> =
            state.retiredInitiations.values.flatMap { it.values }.filterNotNull().toSet()

        override suspend fun removeRetiredFor(signedPreKeyId: SignedPreKeyId) {
            state = state.copy(
                retiredInitiations = state.retiredInitiations
                    .mapValues { (_, retired) -> retired.filterValues { it != signedPreKeyId } }
                    .filterValues { it.isNotEmpty() },
            )
        }
    }

    override val preKeys: PreKeyStore = object : PreKeyStore {
        override suspend fun signedPreKey(id: SignedPreKeyId) = state.signedPreKeys[id]?.copy()

        override suspend fun currentSignedPreKey() = state.currentSignedPreKeyId?.let { state.signedPreKeys[it]?.copy() }

        override suspend fun storeCurrentSignedPreKey(preKey: SignedPreKeyPair, createdAt: Instant) {
            require(preKey.id.value > (state.highestSignedPreKeyId?.value ?: -1)) { "Signed prekey ID already used" }
            val previous = state.currentSignedPreKeyId
            var times = state.signedPreKeyTimes + (preKey.id to SignedPreKeyTimes(createdAt, replacedAt = null))
            if (previous != null) {
                times = times + (previous to times.getValue(previous).copy(replacedAt = createdAt))
            }
            state = state.copy(
                signedPreKeys = state.signedPreKeys + (preKey.id to preKey.copy()),
                signedPreKeyTimes = times,
                currentSignedPreKeyId = preKey.id,
                highestSignedPreKeyId = preKey.id,
            )
        }

        override suspend fun signedPreKeyInfo(id: SignedPreKeyId): SignedPreKeyInfo? {
            if (id !in state.signedPreKeys) return null
            val times = state.signedPreKeyTimes[id] ?: SignedPreKeyTimes(null, null)
            return SignedPreKeyInfo(id, id == state.currentSignedPreKeyId, times.createdAt, times.replacedAt)
        }

        override suspend fun signedPreKeyInfos(): List<SignedPreKeyInfo> =
            state.signedPreKeys.keys.sortedBy { it.value }.mapNotNull { signedPreKeyInfo(it) }

        override suspend fun stampLegacySignedPreKeys(at: Instant) {
            val times = state.signedPreKeys.keys.associateWith { id ->
                val old = state.signedPreKeyTimes[id] ?: SignedPreKeyTimes(null, null)
                SignedPreKeyTimes(
                    createdAt = old.createdAt ?: at,
                    replacedAt = old.replacedAt ?: at.takeIf { id != state.currentSignedPreKeyId },
                )
            }
            state = state.copy(signedPreKeyTimes = times)
        }

        override suspend fun removeSignedPreKey(id: SignedPreKeyId) {
            require(id != state.currentSignedPreKeyId) { "The current signed prekey cannot be removed" }
            state = state.copy(
                signedPreKeys = state.signedPreKeys - id,
                signedPreKeyTimes = state.signedPreKeyTimes - id,
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

private fun DeviceAuthenticationKeyPair.copy() = DeviceAuthenticationKeyPair(publicKey.copyOf(), privateKey.copyOf())

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
 * promises. Device registrations and authentication nonces each keep their
 * state behind their own [Mutex] as well, so registration and nonce claims
 * are atomic.
 */
class InMemoryServerStorage : ServerStorage {
    override val preKeys: PreKeyRepository = InMemoryPreKeyRepository()

    override val mailboxes: MailboxRepository = InMemoryMailboxRepository()

    override val devices: DeviceRegistrationRepository = InMemoryDeviceRegistrationRepository()

    override val authenticationNonces: AuthenticationNonceRepository = InMemoryAuthenticationNonceRepository()
}

private class InMemoryDeviceRegistrationRepository : DeviceRegistrationRepository {
    private val mutex = Mutex()
    private var registrations = mapOf<DeviceAddress, DeviceRegistration>()

    // DeviceRegistration copies its key on the way in and out.
    override suspend fun registration(address: DeviceAddress): DeviceRegistration? = mutex.withLock { registrations[address] }

    override suspend fun register(registration: DeviceRegistration): Boolean = mutex.withLock {
        val existing = registrations[registration.address]
        when {
            existing == null -> {
                registrations = registrations + (registration.address to registration)
                true
            }
            existing == registration -> false
            else -> throw DeviceRegistrationException.Conflict()
        }
    }
}

/**
 * Accepted nonces with their request timestamps. Pruning runs inside every
 * claim, under the same lock, so the state never outgrows the nonces of the
 * validity window.
 */
private class InMemoryAuthenticationNonceRepository : AuthenticationNonceRepository {
    private val mutex = Mutex()
    private var nonces = mapOf<Pair<DeviceAddress, NonceKey>, Instant>()

    override suspend fun claim(address: DeviceAddress, nonce: ByteArray, timestamp: Instant, pruneBefore: Instant): Boolean =
        mutex.withLock {
            val kept = nonces.filterValues { it >= pruneBefore }
            val key = address to NonceKey(nonce.copyOf())
            if (key in kept) {
                nonces = kept
                return@withLock false
            }
            nonces = kept + (key to timestamp)
            true
        }

    private class NonceKey(val bytes: ByteArray) {
        override fun equals(other: Any?) = other is NonceKey && bytes.contentEquals(other.bytes)
        override fun hashCode() = bytes.contentHashCode()
    }
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
