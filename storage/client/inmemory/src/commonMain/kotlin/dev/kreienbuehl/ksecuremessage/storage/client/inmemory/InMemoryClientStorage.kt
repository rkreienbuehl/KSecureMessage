package dev.kreienbuehl.ksecuremessage.storage.client.inmemory

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.InboundFinalization
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.MessageDiscardReason
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore
import dev.kreienbuehl.ksecuremessage.storage.IdentityStore
import dev.kreienbuehl.ksecuremessage.storage.PendingInboundMessage
import dev.kreienbuehl.ksecuremessage.storage.PendingInboundStore
import dev.kreienbuehl.ksecuremessage.storage.PendingOutboundMessage
import dev.kreienbuehl.ksecuremessage.storage.PendingOutboundStore
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
import dev.kreienbuehl.ksecuremessage.storage.ProcessedInboundMessage
import dev.kreienbuehl.ksecuremessage.storage.ProcessedInboundStore
import dev.kreienbuehl.ksecuremessage.storage.RemoteIdentityRecord
import dev.kreienbuehl.ksecuremessage.storage.RemoteIdentityStore
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
 * is always `false`, and every processed entry has a digest and a commit
 * time.
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
        override suspend fun pendingRecoveryKeyPair() = transaction { deviceAuthentication.pendingRecoveryKeyPair() }
        override suspend fun storePendingRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) =
            transaction { deviceAuthentication.storePendingRecoveryKeyPair(keyPair) }
        override suspend fun removePendingRecoveryKeyPair() = transaction { deviceAuthentication.removePendingRecoveryKeyPair() }
        override suspend fun promotePendingRecoveryKeyPair() = transaction { deviceAuthentication.promotePendingRecoveryKeyPair() }
        override suspend fun pendingRotationKeyPair() = transaction { deviceAuthentication.pendingRotationKeyPair() }
        override suspend fun storePendingRotationKeyPair(keyPair: DeviceAuthenticationKeyPair) =
            transaction { deviceAuthentication.storePendingRotationKeyPair(keyPair) }
        override suspend fun removePendingRotationKeyPair() = transaction { deviceAuthentication.removePendingRotationKeyPair() }
        override suspend fun promotePendingRotationKeyPair() = transaction { deviceAuthentication.promotePendingRotationKeyPair() }
        override suspend fun pendingLastDeviceRecoveryKeyPair() = transaction { deviceAuthentication.pendingLastDeviceRecoveryKeyPair() }
        override suspend fun storePendingLastDeviceRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) =
            transaction { deviceAuthentication.storePendingLastDeviceRecoveryKeyPair(keyPair) }
        override suspend fun removePendingLastDeviceRecoveryKeyPair() =
            transaction { deviceAuthentication.removePendingLastDeviceRecoveryKeyPair() }
        override suspend fun promotePendingLastDeviceRecoveryKeyPair() =
            transaction { deviceAuthentication.promotePendingLastDeviceRecoveryKeyPair() }
    }

    override val remoteIdentities: RemoteIdentityStore = object : RemoteIdentityStore {
        override suspend fun identityKey(address: DeviceAddress) = transaction { remoteIdentities.identityKey(address) }
        override suspend fun record(address: DeviceAddress) = transaction { remoteIdentities.record(address) }
        override suspend fun store(address: DeviceAddress, identityKey: ByteArray) =
            transaction { remoteIdentities.store(address, identityKey) }
        override suspend fun setVerification(address: DeviceAddress, identityKey: ByteArray, verification: VerificationState) =
            transaction { remoteIdentities.setVerification(address, identityKey, verification) }
        override suspend fun replace(address: DeviceAddress, expectedIdentityKey: ByteArray, newIdentityKey: ByteArray) =
            transaction { remoteIdentities.replace(address, expectedIdentityKey, newIdentityKey) }
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
        override suspend fun page(afterSequence: Long, limit: Int, recipient: DeviceAddress?) =
            transaction { pendingOutbound.page(afterSequence, limit, recipient) }
        override suspend fun count(recipient: DeviceAddress?) = transaction { pendingOutbound.count(recipient) }
        override suspend fun remove(recipient: DeviceAddress, id: LogicalMessageId) =
            transaction { pendingOutbound.remove(recipient, id) }
    }

    override val pendingInbound: PendingInboundStore = object : PendingInboundStore {
        override suspend fun store(sender: DeviceAddress, id: LogicalMessageId, frame: ByteArray, receivedAt: Instant) =
            transaction { pendingInbound.store(sender, id, frame, receivedAt) }
        override suspend fun contains(sender: DeviceAddress, id: LogicalMessageId) = transaction { pendingInbound.contains(sender, id) }
        override suspend fun get(sender: DeviceAddress, id: LogicalMessageId) = transaction { pendingInbound.get(sender, id) }
        override suspend fun page(afterSequence: Long, limit: Int, sender: DeviceAddress?) =
            transaction { pendingInbound.page(afterSequence, limit, sender) }
        override suspend fun count(sender: DeviceAddress?) = transaction { pendingInbound.count(sender) }
        override suspend fun remove(sender: DeviceAddress, id: LogicalMessageId) = transaction { pendingInbound.remove(sender, id) }
    }

    override val processedInbound: ProcessedInboundStore = object : ProcessedInboundStore {
        override suspend fun isProcessed(sender: DeviceAddress, id: LogicalMessageId) =
            transaction { processedInbound.isProcessed(sender, id) }
        override suspend fun get(sender: DeviceAddress, id: LogicalMessageId) = transaction { processedInbound.get(sender, id) }
        override suspend fun markCommitted(sender: DeviceAddress, id: LogicalMessageId, digest: ByteArray, committedAt: Instant) =
            transaction { processedInbound.markCommitted(sender, id, digest, committedAt) }
        override suspend fun markDiscarded(
            sender: DeviceAddress,
            id: LogicalMessageId,
            digest: ByteArray,
            discardedAt: Instant,
            reason: MessageDiscardReason,
        ) = transaction { processedInbound.markDiscarded(sender, id, digest, discardedAt, reason) }
        override suspend fun stampLegacyCommitTimes(at: Instant) = transaction { processedInbound.stampLegacyCommitTimes(at) }
        override suspend fun pruneFinalizedAtOrBefore(cutoff: Instant) = transaction { processedInbound.pruneFinalizedAtOrBefore(cutoff) }
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

private class PinnedIdentity(val key: ByteArray, val verification: VerificationState)

private data class State(
    val identity: LocalIdentity? = null,
    val deviceAuthenticationKey: DeviceAuthenticationKeyPair? = null,
    val pendingRecoveryKey: DeviceAuthenticationKeyPair? = null,
    val pendingRotationKey: DeviceAuthenticationKeyPair? = null,
    val pendingLastDeviceRecoveryKey: DeviceAuthenticationKeyPair? = null,
    /** Pinned keys with their verification state; the key arrays are never shared with callers. */
    val remoteIdentities: Map<DeviceAddress, PinnedIdentity> = emptyMap(),
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
    /** Received messages awaiting the application's commit or discard; frames are copied on the way in and out. */
    val pendingInbound: Map<Pair<DeviceAddress, LogicalMessageId>, PendingInboundEntry> = emptyMap(),
    /** Highest pending inbound sequence number ever assigned; never lowered. */
    val highestPendingInboundSequence: Long = 0,
    val processedInbound: Map<Pair<DeviceAddress, LogicalMessageId>, ProcessedEntry> = emptyMap(),
)

private class PendingEntry(val sequence: Long, val frame: ByteArray)

private class PendingInboundEntry(val sequence: Long, val receivedAt: Instant, val frame: ByteArray)

private class ProcessedEntry(
    val finalization: InboundFinalization,
    val digest: ByteArray,
    val finalizedAt: Instant,
    val discardReason: MessageDiscardReason?,
)

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

        override suspend fun page(afterSequence: Long, limit: Int, recipient: DeviceAddress?): List<PendingOutboundMessage> {
            require(limit > 0) { "limit must be positive" }
            require(afterSequence >= 0) { "afterSequence must not be negative" }
            return state.pendingOutbound.entries
                .filter { (key, entry) -> (recipient == null || key.first == recipient) && entry.sequence > afterSequence }
                .sortedBy { it.value.sequence }
                .take(limit)
                .map { (key, entry) -> PendingOutboundMessage(key.first, key.second, entry.sequence, entry.frame.copyOf()) }
        }

        override suspend fun count(recipient: DeviceAddress?) =
            state.pendingOutbound.keys.count { recipient == null || it.first == recipient }.toLong()

        override suspend fun remove(recipient: DeviceAddress, id: LogicalMessageId): Boolean {
            if ((recipient to id) !in state.pendingOutbound) return false
            state = state.copy(pendingOutbound = state.pendingOutbound - (recipient to id))
            return true
        }
    }

    override val pendingInbound: PendingInboundStore = object : PendingInboundStore {
        override suspend fun store(sender: DeviceAddress, id: LogicalMessageId, frame: ByteArray, receivedAt: Instant): Long {
            require((sender to id) !in state.pendingInbound) { "Message is already pending" }
            val sequence = state.highestPendingInboundSequence + 1
            state = state.copy(
                pendingInbound = state.pendingInbound + ((sender to id) to PendingInboundEntry(sequence, receivedAt, frame.copyOf())),
                highestPendingInboundSequence = sequence,
            )
            return sequence
        }

        override suspend fun contains(sender: DeviceAddress, id: LogicalMessageId) = (sender to id) in state.pendingInbound

        override suspend fun get(sender: DeviceAddress, id: LogicalMessageId) =
            state.pendingInbound[sender to id]?.let { PendingInboundMessage(sender, id, it.sequence, it.receivedAt, it.frame.copyOf()) }

        override suspend fun page(afterSequence: Long, limit: Int, sender: DeviceAddress?): List<PendingInboundMessage> {
            require(limit > 0) { "limit must be positive" }
            require(afterSequence >= 0) { "afterSequence must not be negative" }
            return state.pendingInbound.entries
                .filter { (key, entry) -> (sender == null || key.first == sender) && entry.sequence > afterSequence }
                .sortedBy { it.value.sequence }
                .take(limit)
                .map { (key, entry) -> PendingInboundMessage(key.first, key.second, entry.sequence, entry.receivedAt, entry.frame.copyOf()) }
        }

        override suspend fun count(sender: DeviceAddress?) =
            state.pendingInbound.keys.count { sender == null || it.first == sender }.toLong()

        override suspend fun remove(sender: DeviceAddress, id: LogicalMessageId): Boolean {
            if ((sender to id) !in state.pendingInbound) return false
            state = state.copy(pendingInbound = state.pendingInbound - (sender to id))
            return true
        }
    }

    override val processedInbound: ProcessedInboundStore = object : ProcessedInboundStore {
        override suspend fun isProcessed(sender: DeviceAddress, id: LogicalMessageId) = (sender to id) in state.processedInbound

        override suspend fun get(sender: DeviceAddress, id: LogicalMessageId) =
            state.processedInbound[sender to id]?.let {
                ProcessedInboundMessage(sender, id, it.finalization, it.digest.copyOf(), it.finalizedAt, it.discardReason)
            }

        override suspend fun markCommitted(sender: DeviceAddress, id: LogicalMessageId, digest: ByteArray, committedAt: Instant) =
            mark(sender, id, ProcessedEntry(InboundFinalization.COMMITTED, digest.copyOf(), committedAt, null))

        override suspend fun markDiscarded(
            sender: DeviceAddress,
            id: LogicalMessageId,
            digest: ByteArray,
            discardedAt: Instant,
            reason: MessageDiscardReason,
        ) = mark(sender, id, ProcessedEntry(InboundFinalization.DISCARDED, digest.copyOf(), discardedAt, reason))

        private fun mark(sender: DeviceAddress, id: LogicalMessageId, entry: ProcessedEntry) {
            require(entry.digest.size == DIGEST_SIZE) { "A processed message digest has $DIGEST_SIZE bytes" }
            require((sender to id) !in state.processedInbound) { "Message is already finalized" }
            state = state.copy(processedInbound = state.processedInbound + ((sender to id) to entry))
        }

        // Every entry here has a commit time.
        override suspend fun stampLegacyCommitTimes(at: Instant) = 0

        override suspend fun pruneFinalizedAtOrBefore(cutoff: Instant): Int {
            val kept = state.processedInbound.filterValues { it.finalizedAt > cutoff }
            val removed = state.processedInbound.size - kept.size
            state = state.copy(processedInbound = kept)
            return removed
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

        override suspend fun pendingRecoveryKeyPair() = state.pendingRecoveryKey?.copy()

        override suspend fun storePendingRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) {
            check(state.pendingRecoveryKey == null) { "A pending recovery key is already stored" }
            check(state.pendingRotationKey == null) { "A device authentication rotation is pending" }
            check(state.pendingLastDeviceRecoveryKey == null) { "A last-device recovery is pending" }
            state = state.copy(pendingRecoveryKey = keyPair.copy())
        }

        override suspend fun removePendingRecoveryKeyPair() {
            state = state.copy(pendingRecoveryKey = null)
        }

        override suspend fun promotePendingRecoveryKeyPair() {
            val pending = checkNotNull(state.pendingRecoveryKey) { "No pending recovery key" }
            state = state.copy(deviceAuthenticationKey = pending, pendingRecoveryKey = null)
        }

        override suspend fun pendingRotationKeyPair() = state.pendingRotationKey?.copy()

        override suspend fun storePendingRotationKeyPair(keyPair: DeviceAuthenticationKeyPair) {
            check(state.pendingRotationKey == null) { "A pending rotation key is already stored" }
            check(state.pendingRecoveryKey == null) { "A device recovery is pending" }
            check(state.pendingLastDeviceRecoveryKey == null) { "A last-device recovery is pending" }
            state = state.copy(pendingRotationKey = keyPair.copy())
        }

        override suspend fun removePendingRotationKeyPair() {
            state = state.copy(pendingRotationKey = null)
        }

        override suspend fun promotePendingRotationKeyPair() {
            val pending = checkNotNull(state.pendingRotationKey) { "No pending rotation key" }
            state = state.copy(deviceAuthenticationKey = pending, pendingRotationKey = null)
        }

        override suspend fun pendingLastDeviceRecoveryKeyPair() = state.pendingLastDeviceRecoveryKey?.copy()

        override suspend fun storePendingLastDeviceRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) {
            check(state.pendingLastDeviceRecoveryKey == null) { "A pending last-device recovery key is already stored" }
            check(state.pendingRecoveryKey == null) { "A device recovery is pending" }
            check(state.pendingRotationKey == null) { "A device authentication rotation is pending" }
            state = state.copy(pendingLastDeviceRecoveryKey = keyPair.copy())
        }

        override suspend fun removePendingLastDeviceRecoveryKeyPair() {
            state = state.copy(pendingLastDeviceRecoveryKey = null)
        }

        override suspend fun promotePendingLastDeviceRecoveryKeyPair() {
            val pending = checkNotNull(state.pendingLastDeviceRecoveryKey) { "No pending last-device recovery key" }
            state = state.copy(deviceAuthenticationKey = pending, pendingLastDeviceRecoveryKey = null)
        }
    }

    override val remoteIdentities: RemoteIdentityStore = object : RemoteIdentityStore {
        override suspend fun identityKey(address: DeviceAddress) = state.remoteIdentities[address]?.key?.copyOf()

        override suspend fun record(address: DeviceAddress) =
            state.remoteIdentities[address]?.let { RemoteIdentityRecord(it.key.copyOf(), it.verification) }

        override suspend fun store(address: DeviceAddress, identityKey: ByteArray) {
            val pinned = state.remoteIdentities[address]
            if (pinned != null) {
                check(pinned.key.contentEquals(identityKey)) { "A different remote identity is already pinned" }
                return
            }
            pin(address, PinnedIdentity(identityKey.copyOf(), VerificationState.UNVERIFIED))
        }

        override suspend fun setVerification(address: DeviceAddress, identityKey: ByteArray, verification: VerificationState) {
            val pinned = checkNotNull(state.remoteIdentities[address]) { "No remote identity is pinned" }
            check(pinned.key.contentEquals(identityKey)) { "Another remote identity is pinned" }
            pin(address, PinnedIdentity(pinned.key, verification))
        }

        override suspend fun replace(address: DeviceAddress, expectedIdentityKey: ByteArray, newIdentityKey: ByteArray) {
            require(!expectedIdentityKey.contentEquals(newIdentityKey)) { "The new identity key is the pinned one" }
            val pinned = checkNotNull(state.remoteIdentities[address]) { "No remote identity is pinned" }
            check(pinned.key.contentEquals(expectedIdentityKey)) { "Another remote identity is pinned" }
            pin(address, PinnedIdentity(newIdentityKey.copyOf(), VerificationState.UNVERIFIED))
        }

        private fun pin(address: DeviceAddress, pinned: PinnedIdentity) {
            state = state.copy(remoteIdentities = state.remoteIdentities + (address to pinned))
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

private const val DIGEST_SIZE = 32

private fun LocalIdentity.copy() = LocalIdentity(publicKey.copyOf(), privateKey.copyOf())

private fun DeviceAuthenticationKeyPair.copy() = DeviceAuthenticationKeyPair(publicKey.copyOf(), privateKey.copyOf())

private fun SignedPreKeyPair.copy() = SignedPreKeyPair(id, publicKey.copyOf(), signature.copyOf(), privateKey.copyOf())

private fun OneTimePreKeyPair.copy() = OneTimePreKeyPair(id, publicKey.copyOf(), privateKey.copyOf())

private fun SecureSession.copyState() = copy(state = state.copyOf())
