package dev.kreienbuehl.ksecuremessage.client

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
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest

/**
 * Network boundary of [SecureMessageClient]. Implementations report server
 * rejections as [SecureMessageTransportException].
 *
 * Device-scoped requests (registration, registration state, prekey
 * publication, mailbox drain) are authenticated with the device authentication key
 * (docs/server-authentication.md). The client passes a [ServerRequestSigner];
 * the transport describes the exact request it sends as a [ServerRequest]
 * (method, canonical path, exact body bytes), has it signed once per attempt
 * and attaches the result.
 */
interface SecureMessageTransport {
    /**
     * Registers the device authentication public key of
     * [registration]'s address, signed with that key. Registering the same key
     * again is harmless. Throws
     * [SecureMessageTransportException.DeviceRegistrationConflict] if the
     * server holds another key for the address.
     */
    suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner)

    /**
     * Submits a device recovery (docs/device-recovery.md):
     * `PUT /v1/devices/{user}/{device}/registration/recovery` for the
     * authorization's target. Not signed with a [ServerRequestSigner]: the
     * authorization carries its own two signatures. Returns once the server
     * replaced the key, or recognized a retry of the recovery that did.
     * Throws [SecureMessageTransportException.DeviceRecoveryRejected].
     */
    suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization)

    /**
     * The registration metadata of [address]: its current authentication
     * epoch, needed to build a routine rotation statement, and the server
     * time its registered key was installed at, for the rotation policy
     * (docs/device-authentication-rotation.md).
     * `GET /v1/devices/{user}/{device}/registration`, signed with the
     * registered key. Throws
     * [SecureMessageTransportException.AuthenticationFailed] if the key is
     * not the registered one.
     */
    suspend fun registrationStatus(address: DeviceAddress, signer: ServerRequestSigner): DeviceAuthenticationRegistrationStatus

    /**
     * Submits a routine device authentication key rotation
     * (docs/device-authentication-rotation.md):
     * `PUT /v1/devices/{user}/{device}/registration/rotation` for the
     * statement's device. Not signed with a [ServerRequestSigner]: the
     * authorization carries the current key's signature and the replacement
     * key's proof of possession. Returns once the server replaced the key, or
     * recognized a retry of the rotation that did. Throws
     * [SecureMessageTransportException.DeviceAuthenticationRotationRejected].
     */
    suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization)

    /**
     * Registers the user's last-device recovery public key
     * (docs/last-device-recovery.md):
     * `PUT /v1/devices/{user}/{device}/last-device-recovery/key` for
     * [address], signed with [address]'s registered device authentication
     * key. Registering the same key again is harmless. Throws
     * [SecureMessageTransportException.LastDeviceRecoveryKeyRejected]
     * ([SecureMessageTransportException.RecoveryKeyFailure.CONFLICT] if the
     * user has another recovery key) or
     * [SecureMessageTransportException.AuthenticationFailed].
     */
    suspend fun registerLastDeviceRecoveryKey(
        address: DeviceAddress,
        registration: LastDeviceRecoveryKeyRegistration,
        signer: ServerRequestSigner,
    )

    /**
     * The user's recovery key state (docs/recovery-key-lifecycle.md):
     * `GET /v1/devices/{user}/{device}/last-device-recovery/key` for
     * [address], signed with [address]'s registered device authentication
     * key. Throws [SecureMessageTransportException.AuthenticationFailed].
     */
    suspend fun lastDeviceRecoveryKeyStatus(address: DeviceAddress, signer: ServerRequestSigner): LastDeviceRecoveryKeyStatus

    /**
     * Submits a recovery key rotation (docs/recovery-key-lifecycle.md):
     * `PUT /v1/devices/{user}/{device}/last-device-recovery/key/rotation` for
     * the statement's authorizing device, signed with that device's
     * registered device authentication key. The body carries the current
     * recovery key's signature and the new key's proof of possession. Returns
     * once the server rotated the key, or recognized a retry of the rotation
     * that did. Throws [SecureMessageTransportException.RecoveryKeyRotationRejected]
     * or [SecureMessageTransportException.AuthenticationFailed].
     */
    suspend fun rotateLastDeviceRecoveryKey(authorization: RecoveryKeyRotationAuthorization, signer: ServerRequestSigner)

    /**
     * Submits a recovery key revocation (docs/recovery-key-lifecycle.md):
     * `PUT /v1/devices/{user}/{device}/last-device-recovery/key/revocation`,
     * signed like [rotateLastDeviceRecoveryKey]. Throws
     * [SecureMessageTransportException.RecoveryKeyRevocationRejected] or
     * [SecureMessageTransportException.AuthenticationFailed].
     */
    suspend fun revokeLastDeviceRecoveryKey(authorization: RecoveryKeyRevocationAuthorization, signer: ServerRequestSigner)

    /**
     * Requests a delayed reset of the user's recovery key
     * (docs/recovery-key-reset.md): `PUT /v1/devices/{user}/{device}/last-device-recovery/key/reset`
     * for [address], signed with its registered device authentication key.
     * Returns the pending reset: the new one, or the one already pending
     * (unchanged). Throws [SecureMessageTransportException.RecoveryKeyResetRejected]
     * or [SecureMessageTransportException.AuthenticationFailed].
     */
    suspend fun requestLastDeviceRecoveryKeyReset(address: DeviceAddress, signer: ServerRequestSigner): RecoveryKeyResetStatus.Pending

    /**
     * The user's pending recovery key reset: `GET …/last-device-recovery/key/reset`
     * for [address], signed. Throws [SecureMessageTransportException.AuthenticationFailed].
     */
    suspend fun lastDeviceRecoveryKeyResetStatus(address: DeviceAddress, signer: ServerRequestSigner): RecoveryKeyResetStatus

    /**
     * Completes the pending reset: `PUT …/last-device-recovery/key/reset/completion`
     * for the statement's completing device, signed with its registered key;
     * the body carries the new key's proof of possession. Returns once the
     * server completed it, or recognized a retry of the completion that did.
     * Throws [SecureMessageTransportException.RecoveryKeyResetRejected] or
     * [SecureMessageTransportException.AuthenticationFailed].
     */
    suspend fun completeLastDeviceRecoveryKeyReset(authorization: RecoveryKeyResetCompletionAuthorization, signer: ServerRequestSigner)

    /**
     * Cancels the pending reset [resetId]: `PUT …/last-device-recovery/key/reset/cancellation`
     * for [address], signed. Throws [SecureMessageTransportException.RecoveryKeyResetRejected]
     * (`NOT_PENDING` if no such reset is pending) or
     * [SecureMessageTransportException.AuthenticationFailed].
     */
    suspend fun cancelLastDeviceRecoveryKeyReset(address: DeviceAddress, resetId: RecoveryKeyResetId, signer: ServerRequestSigner)

    /**
     * The pending reset of the query's user, for the holder of the current
     * recovery key: `POST /v1/users/{user}/last-device-recovery/key/reset/status`.
     * Not signed with a [ServerRequestSigner]: the query carries the recovery
     * key's signature. Throws [SecureMessageTransportException.RecoveryKeyResetRejected].
     */
    suspend fun lastDeviceRecoveryKeyResetStatusByRecoveryKey(query: RecoveryKeyResetStatusQuery): RecoveryKeyResetStatus

    /**
     * Cancels the pending reset with the signature of the recovery key it
     * would replace: `PUT /v1/users/{user}/last-device-recovery/key/reset/cancellation`.
     * Not signed with a [ServerRequestSigner]. Throws
     * [SecureMessageTransportException.RecoveryKeyResetRejected].
     */
    suspend fun cancelLastDeviceRecoveryKeyResetByRecoveryKey(authorization: RecoveryKeyResetCancellationAuthorization)

    /**
     * A last-device recovery challenge for [target]:
     * `POST /v1/devices/{user}/{device}/last-device-recovery/challenge`.
     * Public. Throws [SecureMessageTransportException.LastDeviceRecoveryRejected]
     * (`NOT_CONFIGURED`, `TARGET_NOT_REGISTERED`).
     */
    suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge

    /**
     * Submits a last-device recovery (docs/last-device-recovery.md):
     * `PUT /v1/devices/{user}/{device}/last-device-recovery` for the
     * statement's target. Not signed with a [ServerRequestSigner]: the
     * authorization carries the recovery key's signature and the replacement
     * key's proof of possession. Returns once the server replaced the key, or
     * recognized a retry of the recovery that did. Throws
     * [SecureMessageTransportException.LastDeviceRecoveryRejected].
     */
    suspend fun recoverLastDevice(authorization: LastDeviceRecoveryAuthorization)

    /**
     * Uploads public prekey material. The server applies it atomically and
     * treats a repeated identical publication as a no-op, so a retry after a
     * lost response is safe. Authenticated.
     */
    suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner)

    /**
     * Fetches a bundle for a first contact. The server consumes the one-time
     * prekey it returns. Throws [SecureMessageTransportException.DeviceNotFound]
     * for an unknown device. Public.
     */
    suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle

    /**
     * Hands [envelope] to the server. When this returns, the envelope is
     * queued behind every envelope this device sent to the same recipient
     * before (docs/transport-ordering.md). Public.
     */
    suspend fun send(envelope: EncryptedEnvelope)

    /**
     * Removes and returns the envelopes queued for [address]. Envelopes of
     * one sender come in the order that sender sent them; process them in
     * that order. Authenticated: only the registered device drains its mailbox.
     */
    suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope>
}

/**
 * Signs a device-scoped server request with the local device authentication
 * key. Every call uses the current time and a fresh nonce, so a request sent
 * again must be signed again. Never sees or returns private key bytes.
 */
fun interface ServerRequestSigner {
    suspend fun sign(request: ServerRequest): RequestAuthentication
}
