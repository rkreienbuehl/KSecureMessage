package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceAuthenticationRegistrationStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQuery
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryKeyException
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Blind relay: stores public prekeys and queues opaque envelopes. Never
 * decrypts payloads and never holds client secrets.
 *
 * Device-scoped operations need the device's authentication
 * (docs/server-authentication.md): a device registers its authentication key
 * once ([registerDevice]); publishing prekeys and draining the mailbox then
 * take an [AuthenticatedDevice] from [authenticate]. Fetching a prekey bundle
 * and relaying an envelope stay open to anyone. [clock] is the server time
 * that request timestamps are checked against and that is recorded as the
 * installation time of registered device authentication keys.
 *
 * [recoveryKeyResetPolicy] enables delayed recovery key resets
 * (docs/recovery-key-reset.md) with the host's delay; `null` (the default)
 * disables them: requests are refused, while an already pending reset can
 * still be read, cancelled and completed.
 */
class SecureMessageServer(
    private val storage: ServerStorage,
    private val clock: Clock = Clock.System,
    recoveryKeyResetPolicy: RecoveryKeyResetPolicy? = null,
) {
    private val preKeys = PreKeyService(storage.preKeys)
    private val authenticator = DeviceAuthenticator(storage.devices, storage.authenticationNonces, clock)
    private val recovery = DeviceRecoveryService(storage.devices, clock)
    private val rotation = DeviceAuthenticationRotationService(storage.devices, clock)
    private val lastDeviceRecovery = LastDeviceRecoveryService(storage.devices, storage.lastDeviceRecovery, clock)
    private val recoveryKeyLifecycle = RecoveryKeyLifecycleService(storage.lastDeviceRecovery, clock)
    private val recoveryKeyReset = RecoveryKeyResetService(storage.lastDeviceRecovery, clock, recoveryKeyResetPolicy)

    /**
     * Registers the device authentication key of [registration]'s address.
     * [body] is the exact HTTP body the request carried and [authentication]
     * must be signed with the key being registered. Returns `true` for a
     * first registration, `false` if exactly this key was registered before.
     *
     * A first registration records [clock]'s time as the key's installation
     * time; a repeated registration of the same key keeps the recorded one.
     *
     * Throws [DeviceRegistrationException.InvalidRegistration] for a key of
     * the wrong size, [DeviceAuthenticationException] if the request is not
     * authenticated with that key (nothing is registered), and
     * [DeviceRegistrationException.Conflict] if another key is registered;
     * a registered key is never replaced.
     *
     * First registration is trust on first registration: whoever registers
     * an unregistered address first owns it. There is no reset; only
     * [recoverDevice], [rotateDeviceAuthenticationKey] and [recoverLastDevice]
     * replace a registered key.
     */
    suspend fun registerDevice(
        registration: DeviceRegistration,
        body: ByteArray,
        authentication: RequestAuthentication?,
    ): Boolean {
        if (registration.publicKey.size != ServerRequestAuthentication.PUBLIC_KEY_SIZE) {
            throw DeviceRegistrationException.InvalidRegistration("Device authentication key has an invalid size")
        }
        authenticator.authenticateRegistration(registration.address, registration.publicKey, body, authentication)
        return storage.devices.register(registration, installedAt = Instant.fromEpochMilliseconds(clock.now().toEpochMilliseconds()))
    }

    /**
     * Replaces the registered device authentication key of
     * [authorization]'s target with its replacement key, authorized by
     * another registered device of the same user and proven by the
     * replacement key (docs/device-recovery.md). Throws
     * [DeviceRecoveryException] and changes nothing if any check fails.
     *
     * From the moment this returns [DeviceRecoveryOutcome.REPLACED], only
     * the replacement key authenticates the target; the old key is rejected.
     * The target's messaging identity, prekeys and mailbox are not touched.
     * A retry of the same recovery returns [DeviceRecoveryOutcome.ALREADY_APPLIED].
     */
    suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization): DeviceRecoveryOutcome =
        recovery.recover(authorization)

    /**
     * Replaces [address]'s registered device authentication key K1 with the
     * statement's replacement key K2 in a routine rotation
     * (docs/device-authentication-rotation.md): authorized by K1 (the
     * registered key at the statement's epoch) and proven by K2. The
     * statement is the request's authentication; no other device takes part.
     * Throws [DeviceAuthenticationRotationException] and changes nothing if
     * any check fails.
     *
     * From the moment this returns [DeviceAuthenticationRotationOutcome.ROTATED],
     * only K2 authenticates the device and the epoch is one higher. The
     * messaging identity, prekeys and mailbox are not touched. A retry of the
     * same rotation returns [DeviceAuthenticationRotationOutcome.ALREADY_APPLIED].
     */
    suspend fun rotateDeviceAuthenticationKey(
        address: DeviceAddress,
        authorization: DeviceAuthenticationRotationAuthorization,
    ): DeviceAuthenticationRotationOutcome = rotation.rotate(address, authorization)

    /**
     * Registers [registration]'s public key as the last-device recovery key
     * of the authenticated [device]'s user (docs/last-device-recovery.md).
     * Returns `true` if it was stored (the user had none, or its key was
     * revoked: the recovery key epoch continues, docs/recovery-key-lifecycle.md),
     * `false` if exactly this key is active. Throws
     * [LastDeviceRecoveryException.InvalidKeyRegistration] if the
     * registration is for another user or its proof of possession does not
     * verify, [LastDeviceRecoveryKeyException.Conflict] if the user has
     * another active recovery key (only [rotateLastDeviceRecoveryKey]
     * replaces it), and [LastDeviceRecoveryKeyException.EpochExhausted] if
     * the recovery key epoch cannot grow any more.
     */
    suspend fun registerLastDeviceRecoveryKey(device: AuthenticatedDevice, registration: LastDeviceRecoveryKeyRegistration): Boolean =
        lastDeviceRecovery.registerKey(device, registration)

    /**
     * The recovery key state of the authenticated [device]'s user
     * (docs/recovery-key-lifecycle.md): unconfigured, active (epoch,
     * installation time, public key) or revoked (epoch, revocation time).
     */
    suspend fun lastDeviceRecoveryKeyStatus(device: AuthenticatedDevice): LastDeviceRecoveryKeyStatus =
        recoveryKeyLifecycle.status(device)

    /**
     * Replaces the authenticated [device]'s user's offline recovery key with
     * the statement's new key (docs/recovery-key-lifecycle.md): authorized by
     * the device (ServerAuth, [ProtectedEndpoint.ROTATE_LAST_DEVICE_RECOVERY_KEY])
     * together with the current recovery key's signature, proven by the new
     * key. Throws [RecoveryKeyLifecycleException] and changes nothing if any
     * check fails. From the moment this returns
     * [RecoveryKeyRotationOutcome.ROTATED], only the new key authorizes
     * last-device recoveries, and every outstanding challenge and any pending
     * recovery key reset of the user are gone. Device registrations, prekeys
     * and mailboxes are not touched.
     */
    suspend fun rotateLastDeviceRecoveryKey(
        device: AuthenticatedDevice,
        authorization: RecoveryKeyRotationAuthorization,
    ): RecoveryKeyRotationOutcome = recoveryKeyLifecycle.rotate(device, authorization)

    /**
     * Revokes the authenticated [device]'s user's offline recovery key
     * (docs/recovery-key-lifecycle.md), authorized by the device together
     * with the current recovery key's signature. Throws
     * [RecoveryKeyLifecycleException] and changes nothing if any check fails.
     * Afterwards no last-device recovery is possible until a new key is
     * registered, and every outstanding challenge and any pending recovery
     * key reset of the user are gone.
     */
    suspend fun revokeLastDeviceRecoveryKey(
        device: AuthenticatedDevice,
        authorization: RecoveryKeyRevocationAuthorization,
    ): RecoveryKeyRevocationOutcome = recoveryKeyLifecycle.revoke(device, authorization)

    /**
     * Requests a delayed reset of the authenticated [device]'s user's offline
     * recovery key, for when that key is lost (docs/recovery-key-reset.md).
     * The reset is bound to the active key and epoch; its request time is
     * [clock]'s time and its eligibility time follows from the policy; the
     * request chooses neither. If a reset is pending already, it is returned
     * unchanged (`created = false`): the delay never restarts. Throws
     * [RecoveryKeyResetException.NotAvailable] without a policy, and
     * [RecoveryKeyResetException] for no active key, a changed registration
     * or an exhausted epoch. Last-device recovery challenges stay valid.
     */
    suspend fun requestLastDeviceRecoveryKeyReset(device: AuthenticatedDevice): RecoveryKeyResetRequestOutcome =
        recoveryKeyReset.request(device)

    /** The pending recovery key reset of the authenticated [device]'s user, visible to every registered device of the user. */
    suspend fun lastDeviceRecoveryKeyResetStatus(device: AuthenticatedDevice): RecoveryKeyResetStatus = recoveryKeyReset.status(device)

    /**
     * The pending recovery key reset of [query]'s user, for the holder of
     * the current recovery key (no device needed): the query must be signed
     * by the registered recovery key within the validity window. Throws
     * [RecoveryKeyResetException] otherwise.
     */
    suspend fun lastDeviceRecoveryKeyResetStatusByRecoveryKey(query: RecoveryKeyResetStatusQuery): RecoveryKeyResetStatus =
        recoveryKeyReset.statusByRecoveryKey(query)

    /**
     * Completes the pending recovery key reset with the statement's new key,
     * by the authenticated [device] of the user, from the eligibility time
     * on, proven by the new key. Throws [RecoveryKeyResetException] and
     * changes nothing if any check fails. From the moment this returns
     * [RecoveryKeyResetCompletionOutcome.COMPLETED], only the new key
     * authorizes last-device recoveries (at epoch + 1), and every outstanding
     * challenge of the user is gone. A retry of the same completion returns
     * [RecoveryKeyResetCompletionOutcome.ALREADY_APPLIED].
     */
    suspend fun completeLastDeviceRecoveryKeyReset(
        device: AuthenticatedDevice,
        authorization: RecoveryKeyResetCompletionAuthorization,
    ): RecoveryKeyResetCompletionOutcome = recoveryKeyReset.complete(device, authorization)

    /**
     * Cancels the pending reset [resetId] by the authenticated [device] of
     * the user. The recovery key, its epoch and the challenges stay. Throws
     * [RecoveryKeyResetException.NotPending] if no such reset is pending.
     */
    suspend fun cancelLastDeviceRecoveryKeyReset(device: AuthenticatedDevice, resetId: RecoveryKeyResetId) =
        recoveryKeyReset.cancel(device, resetId)

    /**
     * Cancels the pending reset named by [authorization] with the signature
     * of the recovery key it would replace (no device needed). Throws
     * [RecoveryKeyResetException] and changes nothing if any check fails.
     */
    suspend fun cancelLastDeviceRecoveryKeyResetByRecoveryKey(authorization: RecoveryKeyResetCancellationAuthorization) =
        recoveryKeyReset.cancelByRecoveryKey(authorization)

    /**
     * The challenge for recovering [target] with its user's last-device
     * recovery key: the target's outstanding challenge while it is valid for
     * the current registration, else a new random one valid for
     * [dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery.CHALLENGE_LIFETIME].
     * Public. Throws [LastDeviceRecoveryException.TargetNotRegistered] or
     * [LastDeviceRecoveryException.NotConfigured].
     */
    suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge =
        lastDeviceRecovery.issueChallenge(target)

    /**
     * Replaces [address]'s registered device authentication key with the
     * statement's replacement key, authorized by the user's offline recovery
     * key over the server-issued challenge and proven by the replacement key
     * (docs/last-device-recovery.md). Consumes the challenge. Throws
     * [LastDeviceRecoveryException] and changes nothing if any check fails.
     *
     * From the moment this returns [LastDeviceRecoveryOutcome.REPLACED], only
     * the replacement key authenticates the device and the epoch is one
     * higher. The messaging identity, prekeys and mailbox are not touched. A
     * retry of the same recovery returns [LastDeviceRecoveryOutcome.ALREADY_APPLIED].
     */
    suspend fun recoverLastDevice(address: DeviceAddress, authorization: LastDeviceRecoveryAuthorization): LastDeviceRecoveryOutcome =
        lastDeviceRecovery.recover(address, authorization)

    /**
     * The authenticated [device]'s registration metadata: its current
     * authentication epoch, which a routine rotation statement has to name,
     * and the server time its registered key was installed at. Metadata only:
     * whether a rotation is due is the application's policy
     * (docs/device-authentication-rotation.md), never the server's.
     */
    suspend fun registrationStatus(device: AuthenticatedDevice): DeviceAuthenticationRegistrationStatus {
        require(device.endpoint == ProtectedEndpoint.READ_REGISTRATION) { "Not authenticated for the registration" }
        // The device authenticated with its registered key, so the registration exists.
        val state = checkNotNull(storage.devices.registrationState(device.address)) { "Registration disappeared" }
        return DeviceAuthenticationRegistrationStatus(state.authEpoch, state.authKeyInstalledAt)
    }

    /** See [DeviceAuthenticator.authenticate]. */
    suspend fun authenticate(
        address: DeviceAddress,
        endpoint: ProtectedEndpoint,
        body: ByteArray,
        authentication: RequestAuthentication?,
    ): AuthenticatedDevice = authenticator.authenticate(address, endpoint, body, authentication)

    /**
     * Publishes prekeys for the authenticated [device]. See
     * [PreKeyService.publish]. Throws [PreKeyPublicationException] on
     * rejection.
     */
    suspend fun publishPreKeys(device: AuthenticatedDevice, publication: PreKeyPublication) {
        require(device.endpoint == ProtectedEndpoint.PUBLISH_PRE_KEYS) { "Not authenticated for prekey publication" }
        require(device.address == publication.address) { "Publication is for another device" }
        preKeys.publish(publication)
    }

    /** See [PreKeyService.fetchPreKeyBundle]. Public. */
    suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle? = preKeys.fetchPreKeyBundle(address)

    /**
     * Queues [envelope] for its recipient. When this returns, the envelope is
     * ordered after every envelope of the same sender for the same recipient
     * that was relayed before ([MailboxRepository], docs/transport-ordering.md).
     * Public: the envelope's sender is not authenticated here.
     */
    suspend fun relay(envelope: EncryptedEnvelope) = storage.mailboxes.enqueue(envelope)

    /** Removes and returns the authenticated [device]'s envelopes, each sender's in relay order. */
    suspend fun receive(device: AuthenticatedDevice): List<EncryptedEnvelope> {
        require(device.endpoint == ProtectedEndpoint.DRAIN_MAILBOX) { "Not authenticated for the mailbox" }
        return storage.mailboxes.drain(device.address)
    }
}
