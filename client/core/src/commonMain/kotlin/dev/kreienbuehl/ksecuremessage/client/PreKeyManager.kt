package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.SignedPreKeyInfo
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Creates and replenishes the local identity and prekeys. Keys come from the
 * [ProtocolEngine]; storage only persists them. Every function runs inside
 * the caller's [ClientStorage.transaction].
 *
 * Local state only: publishing keys to a server is not handled here.
 *
 * Signed prekeys follow the lifecycle in docs/signed-prekey-lifecycle.md:
 * current, then (after rotation) in a grace period, then deleted. Lifecycle
 * decisions compare [clock] readings with timestamps persisted in storage, so
 * they come out the same after a restart. A clock that moved backwards only
 * delays rotation and expiry: a negative age is never "due", and a deleted
 * key is gone for good.
 */
internal class PreKeyManager(
    private val protocol: ProtocolEngine,
    private val configuration: PreKeyConfiguration,
    private val clock: Clock,
) {
    /** The current time in whole milliseconds, the precision every adapter stores. */
    fun now(): Instant = Instant.fromEpochMilliseconds(clock.now().toEpochMilliseconds())

    /**
     * Creates whatever is missing and runs signed prekey maintenance:
     * - the identity together with the device authentication key, or the
     *   device authentication key alone for storage from before milestone 12
     *   (see [ensureDeviceAuthenticationKey]),
     * - timestamps for signed prekeys stored before milestone 7 (current: created
     *   now; older ones: grace period starts now),
     * - a current signed prekey, or a new one if the current one reached
     *   [PreKeyConfiguration.signedPreKeyRotationAge],
     * - deletion of replaced signed prekeys whose grace period is over, and of
     *   the retired session initiations that could only be accepted with them,
     * - one-time prekeys up to the target.
     * Calling it again changes nothing unless one-time prekeys were consumed
     * or time passed.
     */
    suspend fun ClientStorage.ensureInitialized() {
        val now = now()
        val existing = identity.identity()
        val localIdentity = if (existing == null) {
            createIdentity().also { createDeviceAuthenticationKey() }
        } else {
            existing.also { ensureDeviceAuthenticationKey() }
        }
        preKeys.stampLegacySignedPreKeys(now)
        val current = preKeys.signedPreKeyInfos().firstOrNull { it.isCurrent }
        if (current == null || isDueForRotation(current, now)) createSignedPreKey(localIdentity, now)
        deleteExpiredSignedPreKeys(now)
        pruneRetiredInitiations()

        val missing = configuration.oneTimePreKeyTarget - preKeys.oneTimePreKeyCount()
        if (missing > 0) {
            val firstId = nextId(preKeys.highestOneTimePreKeyId()?.value, missing, "one-time prekey")
            preKeys.storeOneTimePreKeys(protocol.createOneTimePreKeys(OneTimePreKeyId(firstId), missing))
        }
    }

    /**
     * Replaces the current signed prekey. The old one enters its grace period
     * and stays stored for in-flight messages.
     */
    suspend fun ClientStorage.rotateSignedPreKey(): SignedPreKeyPair = createSignedPreKey(requireIdentity(), now())

    /**
     * The signed prekey [id] that an initiation from [remote] names, if it may
     * still accept a new session. A key whose grace period is over is refused
     * even before [ensureInitialized] deleted it.
     */
    suspend fun ClientStorage.signedPreKeyForAcceptance(remote: DeviceAddress, id: SignedPreKeyId): SignedPreKeyPair {
        val info = preKeys.signedPreKeyInfo(id)
        if (info == null) {
            // IDs are allocated upward and never reused: a missing ID at or
            // below the high-water mark belonged to a key that was deleted.
            val highest = preKeys.highestSignedPreKeyId()
            if (highest != null && id.value <= highest.value) throw SecureMessageClientException.ExpiredSignedPreKey(remote, id)
            throw ProtocolException.InvalidMessage("Unknown signed prekey")
        }
        if (isExpired(info, now())) throw SecureMessageClientException.ExpiredSignedPreKey(remote, id)
        return preKeys.signedPreKey(id) ?: throw ProtocolException.InvalidMessage("Unknown signed prekey")
    }

    private fun isDueForRotation(current: SignedPreKeyInfo, now: Instant): Boolean {
        // Stamped by ensureInitialized before this runs; unknown age is not due.
        val createdAt = current.createdAt ?: return false
        return now - createdAt >= configuration.signedPreKeyRotationAge
    }

    private fun isExpired(info: SignedPreKeyInfo, now: Instant): Boolean {
        if (info.isCurrent) return false
        // Not stamped yet (stored before milestone 7): its grace period has not started.
        val replacedAt = info.replacedAt ?: return false
        return now - replacedAt >= configuration.signedPreKeyGracePeriod
    }

    private suspend fun ClientStorage.deleteExpiredSignedPreKeys(now: Instant) {
        for (info in preKeys.signedPreKeyInfos()) {
            if (isExpired(info, now)) preKeys.removeSignedPreKey(info.id)
        }
    }

    /**
     * Removes retired initiations whose local signed prekey is deleted. Accepting
     * an initiation needs the private signed prekey it names, and IDs are never
     * reused, so such an initiation can no longer become a session and its
     * entry protects nothing (docs/signed-prekey-lifecycle.md). Entries without
     * a signed prekey ID are kept.
     */
    private suspend fun ClientStorage.pruneRetiredInitiations() {
        val highest = preKeys.highestSignedPreKeyId() ?: return
        for (id in sessionInitiations.retiredSignedPreKeyIds()) {
            if (id.value <= highest.value && preKeys.signedPreKeyInfo(id) == null) sessionInitiations.removeRetiredFor(id)
        }
    }

    private suspend fun ClientStorage.createIdentity(): LocalIdentity {
        // Prekeys without an identity mean lost or damaged storage. A new
        // identity would not match the stored prekeys and sessions.
        if (preKeys.highestSignedPreKeyId() != null || preKeys.highestOneTimePreKeyId() != null) {
            throw SecureMessageClientException.InconsistentStorage("Prekeys are stored but the local identity is missing")
        }
        if (deviceAuthentication.keyPair() != null) {
            throw SecureMessageClientException.InconsistentStorage("A device authentication key is stored but the local identity is missing")
        }
        return protocol.createIdentity().also { identity.store(it) }
    }

    /**
     * An installation with an identity has its device authentication key
     * already, unless it was set up before milestone 12: storage marks that
     * case ([dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore.awaitsUpgradeKey]),
     * and only then is a first key created. A key that is missing otherwise
     * was lost; a new one could never replace the registration on the
     * server, so this fails closed instead (docs/server-authentication.md).
     * A stored key that does not open throws from storage.
     */
    private suspend fun ClientStorage.ensureDeviceAuthenticationKey() {
        if (deviceAuthentication.keyPair() != null) return
        if (!deviceAuthentication.awaitsUpgradeKey()) {
            throw SecureMessageClientException.InconsistentStorage("The device authentication key is missing")
        }
        createDeviceAuthenticationKey()
    }

    private suspend fun ClientStorage.createDeviceAuthenticationKey() {
        deviceAuthentication.store(protocol.createDeviceAuthenticationKey())
    }

    private suspend fun ClientStorage.createSignedPreKey(identity: LocalIdentity, now: Instant): SignedPreKeyPair {
        val id = nextId(preKeys.highestSignedPreKeyId()?.value, 1, "signed prekey")
        return protocol.createSignedPreKey(identity, SignedPreKeyId(id)).also { preKeys.storeCurrentSignedPreKey(it, now) }
    }

    /** First of [count] unused IDs above [highest]. Fails instead of wrapping past `Int.MAX_VALUE`. */
    private fun nextId(highest: Int?, count: Int, kind: String): Int {
        val first = (highest ?: -1).toLong() + 1
        if (first + count - 1 > Int.MAX_VALUE) throw SecureMessageClientException.PreKeyIdsExhausted(kind)
        return first.toInt()
    }
}

/** Loads the device authentication key, which [SecureMessageClient.initialize] must have created. */
internal suspend fun ClientStorage.requireDeviceAuthenticationKey(): DeviceAuthenticationKeyPair {
    requireIdentity()
    return deviceAuthentication.keyPair() ?: throw SecureMessageClientException.NotInitialized()
}

/** Loads the local identity, which [SecureMessageClient.initialize] must have created. */
internal suspend fun ClientStorage.requireIdentity(): LocalIdentity =
    identity.identity() ?: throw SecureMessageClientException.NotInitialized()
