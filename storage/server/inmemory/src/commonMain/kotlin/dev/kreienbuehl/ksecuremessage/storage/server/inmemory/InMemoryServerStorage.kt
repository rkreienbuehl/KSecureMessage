package dev.kreienbuehl.ksecuremessage.storage.server.inmemory

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
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
