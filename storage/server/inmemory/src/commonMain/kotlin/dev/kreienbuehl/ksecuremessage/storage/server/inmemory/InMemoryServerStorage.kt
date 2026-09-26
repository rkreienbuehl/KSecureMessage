package dev.kreienbuehl.ksecuremessage.storage.server.inmemory

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.time.Instant

/**
 * Non-persistent [ServerStorage] for tests and examples.
 *
 * The prekey repository keeps immutable state behind a [Mutex]: publication
 * and bundle consumption each run under the lock and replace the state only
 * after all checks passed, so they are atomic and serialized. The mailboxes
 * are one queue per recipient behind another [Mutex], so enqueue and drain
 * are serialized too and each recipient's queue is in enqueue order. That is
 * stronger than the per (sender, recipient) order [MailboxRepository]
 * promises. Device registrations and authentication nonces share one more
 * [Mutex], so registration, nonce claims, device recovery and routine
 * rotation (key replacement together with its nonce claim) are atomic.
 */
class InMemoryServerStorage : ServerStorage {
    override val preKeys: PreKeyRepository = InMemoryPreKeyRepository()

    override val mailboxes: MailboxRepository = InMemoryMailboxRepository()

    private val authentication = AuthenticationState()

    override val devices: DeviceRegistrationRepository = InMemoryDeviceRegistrationRepository(authentication)

    override val authenticationNonces: AuthenticationNonceRepository = InMemoryAuthenticationNonceRepository(authentication)

    /** Test support: sets a registered device's epoch, for the epoch exhaustion boundary. */
    internal suspend fun setAuthEpochForTesting(address: DeviceAddress, authEpoch: Long) = authentication.mutex.withLock {
        val registration = checkNotNull(authentication.registrations[address]) { "Device is not registered" }
        authentication.registrations = authentication.registrations +
            (address to Registration(registration.publicKey, authEpoch, registration.installedAt, registration.recoveryId, registration.rotationId))
    }
}

/**
 * One stored registration with the server time its key was installed at and
 * the transition that installed it (at most one of [recoveryId] and
 * [rotationId]). The key is copied on the way in and out.
 */
private class Registration(
    val publicKey: ByteArray,
    val authEpoch: Long,
    val installedAt: Instant,
    val recoveryId: DeviceRecoveryId?,
    val rotationId: DeviceAuthenticationRotationId?,
)

/**
 * Registrations and accepted nonces behind one [Mutex], so a recovery or a
 * rotation replaces a key and claims its nonce in one atomic step
 * ([DeviceRegistrationRepository.replaceForRecovery],
 * [DeviceRegistrationRepository.replaceForRotation]). Nonces are kept with
 * their request timestamps; pruning runs inside every claim, under the same
 * lock, so the state never outgrows the nonces of the validity window.
 */
private class AuthenticationState {
    val mutex = Mutex()
    var registrations = mapOf<DeviceAddress, Registration>()
    var nonces = mapOf<Pair<DeviceAddress, NonceKey>, Instant>()

    /**
     * The compare-and-set shared by recovery and rotation, after their own
     * idempotency and expected-state checks passed. Caller holds [mutex].
     * Checks epoch exhaustion, claims the nonce, then installs [newKey] with
     * epoch + 1, [installedAt] and exactly one of [recoveryId] and [rotationId].
     */
    fun replaceKey(
        address: DeviceAddress,
        current: Registration,
        newKey: ByteArray,
        nonce: RequestNonce,
        timestamp: Instant,
        pruneBefore: Instant,
        installedAt: Instant,
        recoveryId: DeviceRecoveryId?,
        rotationId: DeviceAuthenticationRotationId?,
    ): KeyReplacement {
        if (current.authEpoch == Long.MAX_VALUE) return KeyReplacement.EPOCH_EXHAUSTED
        if (!claim(address, nonce.bytes, timestamp, pruneBefore)) return KeyReplacement.REPLAY
        registrations = registrations + (address to Registration(newKey, current.authEpoch + 1, installedAt, recoveryId, rotationId))
        return KeyReplacement.REPLACED
    }

    enum class KeyReplacement { REPLACED, REPLAY, EPOCH_EXHAUSTED }

    /** Caller holds [mutex]. */
    fun claim(address: DeviceAddress, nonce: ByteArray, timestamp: Instant, pruneBefore: Instant): Boolean {
        val kept = nonces.filterValues { it >= pruneBefore }
        val key = address to NonceKey(nonce.copyOf())
        if (key in kept) {
            nonces = kept
            return false
        }
        nonces = kept + (key to timestamp)
        return true
    }

    class NonceKey(val bytes: ByteArray) {
        override fun equals(other: Any?) = other is NonceKey && bytes.contentEquals(other.bytes)
        override fun hashCode() = bytes.contentHashCode()
    }
}

private class InMemoryDeviceRegistrationRepository(private val state: AuthenticationState) : DeviceRegistrationRepository {
    override suspend fun registration(address: DeviceAddress): DeviceRegistration? =
        state.mutex.withLock { state.registrations[address]?.let { DeviceRegistration(address, it.publicKey) } }

    override suspend fun registrationState(address: DeviceAddress): DeviceRegistrationState? = state.mutex.withLock {
        state.registrations[address]?.let {
            DeviceRegistrationState(DeviceRegistration(address, it.publicKey), it.authEpoch, it.installedAt, it.recoveryId, it.rotationId)
        }
    }

    // A retry of the registered key changes nothing, also not the installation time.
    override suspend fun register(registration: DeviceRegistration, installedAt: Instant): Boolean = state.mutex.withLock {
        val existing = state.registrations[registration.address]
        when {
            existing == null -> {
                state.registrations = state.registrations + (registration.address to Registration(registration.publicKey, 1, installedAt, null, null))
                true
            }
            existing.publicKey.contentEquals(registration.publicKey) -> false
            else -> throw DeviceRegistrationException.Conflict()
        }
    }

    override suspend fun replaceForRecovery(replacement: RecoveryReplacement): RecoveryReplacementResult = state.mutex.withLock {
        val target = state.registrations[replacement.target] ?: return@withLock RecoveryReplacementResult.TARGET_NOT_REGISTERED
        if (target.recoveryId == replacement.recoveryId) return@withLock RecoveryReplacementResult.ALREADY_APPLIED
        val newKey = replacement.replacementPublicKey
        val authorizer = state.registrations[replacement.expectedAuthorizer.address]
        if (!target.matches(replacement.expectedTarget) ||
            authorizer == null || !authorizer.matches(replacement.expectedAuthorizer) ||
            target.publicKey.contentEquals(newKey)
        ) {
            return@withLock RecoveryReplacementResult.CONFLICT
        }
        val result = state.replaceKey(
            replacement.target, target, newKey, replacement.nonce, replacement.timestamp, replacement.pruneBefore,
            replacement.installedAt, recoveryId = replacement.recoveryId, rotationId = null,
        )
        when (result) {
            AuthenticationState.KeyReplacement.REPLACED -> RecoveryReplacementResult.REPLACED
            AuthenticationState.KeyReplacement.REPLAY -> RecoveryReplacementResult.REPLAY
            AuthenticationState.KeyReplacement.EPOCH_EXHAUSTED -> RecoveryReplacementResult.EPOCH_EXHAUSTED
        }
    }

    override suspend fun replaceForRotation(replacement: RotationReplacement): RotationReplacementResult = state.mutex.withLock {
        val current = state.registrations[replacement.address] ?: return@withLock RotationReplacementResult.NOT_REGISTERED
        if (current.rotationId == replacement.rotationId) return@withLock RotationReplacementResult.ALREADY_APPLIED
        val newKey = replacement.replacementPublicKey
        if (!current.matches(replacement.expected) || current.publicKey.contentEquals(newKey)) {
            return@withLock RotationReplacementResult.CONFLICT
        }
        val result = state.replaceKey(
            replacement.address, current, newKey, replacement.nonce, replacement.timestamp, replacement.pruneBefore,
            replacement.installedAt, recoveryId = null, rotationId = replacement.rotationId,
        )
        when (result) {
            AuthenticationState.KeyReplacement.REPLACED -> RotationReplacementResult.REPLACED
            AuthenticationState.KeyReplacement.REPLAY -> RotationReplacementResult.REPLAY
            AuthenticationState.KeyReplacement.EPOCH_EXHAUSTED -> RotationReplacementResult.EPOCH_EXHAUSTED
        }
    }

    private fun Registration.matches(expected: DeviceRegistrationState) =
        authEpoch == expected.authEpoch && publicKey.contentEquals(expected.registration.publicKey)
}

private class InMemoryAuthenticationNonceRepository(private val state: AuthenticationState) : AuthenticationNonceRepository {
    override suspend fun claim(address: DeviceAddress, nonce: ByteArray, timestamp: Instant, pruneBefore: Instant): Boolean =
        state.mutex.withLock { state.claim(address, nonce, timestamp, pruneBefore) }
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
