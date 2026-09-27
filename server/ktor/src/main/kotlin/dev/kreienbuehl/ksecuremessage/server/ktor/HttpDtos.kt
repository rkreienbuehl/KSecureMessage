package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationStatement
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryRequest
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryStatement
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationStatement
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionStatement
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQuery
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQueryStatement
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationStatement
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationStatement
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import kotlinx.serialization.Serializable
import kotlin.io.encoding.Base64
import kotlin.time.Instant

// HTTP API v1 bodies. Mirrored in client:ktor; keep both in sync (see
// docs/prekey-publication.md). Binary fields are Base64 strings (RFC 4648
// standard alphabet, with padding). Public keys only: there is no field for
// private keys, sessions or plaintext.

@Serializable
internal class SignedPreKeyDto(val id: Int, val publicKey: String, val signature: String)

@Serializable
internal class OneTimePreKeyDto(val id: Int, val publicKey: String)

/** Body of `PUT /v1/devices/{user}/{device}/prekeys`. The address is in the path. */
@Serializable
internal class PreKeyPublicationRequest(
    val identityKey: String,
    val signedPreKey: SignedPreKeyDto,
    val oneTimePreKeys: List<OneTimePreKeyDto>,
)

/** Body of `GET /v1/devices/{user}/{device}/prekey-bundle`. */
@Serializable
internal class PreKeyBundleResponse(
    val identityKey: String,
    val signedPreKey: SignedPreKeyDto,
    val oneTimePreKey: OneTimePreKeyDto? = null,
)

/** Body of `PUT /v1/devices/{user}/{device}/registration`. The address is in the path. */
@Serializable
internal class DeviceRegistrationRequest(val publicKey: String)

@Serializable
internal class DeviceAddressDto(val userId: String, val deviceId: String)

/**
 * Body of `PUT /v1/devices/{user}/{device}/registration/recovery`
 * (docs/device-recovery.md). The target is in the path. [timestamp] is epoch
 * milliseconds; the signatures cover the binary recovery statement, never
 * this JSON.
 */
@Serializable
internal class DeviceRecoveryRequestDto(
    val authorizer: DeviceAddressDto,
    val replacementPublicKey: String,
    val timestamp: Long,
    val nonce: String,
    val proofOfPossession: String,
    val authorizerSignature: String,
)

/**
 * Body of `PUT /v1/devices/{user}/{device}/registration/rotation`
 * (docs/device-authentication-rotation.md). The device is in the path.
 * [timestamp] is epoch milliseconds; the signatures cover the binary rotation
 * statement, never this JSON.
 */
@Serializable
internal class DeviceAuthenticationRotationRequestDto(
    val currentPublicKey: String,
    val replacementPublicKey: String,
    val authEpoch: Long,
    val timestamp: Long,
    val nonce: String,
    val authorizationSignature: String,
    val proofOfPossession: String,
)

/**
 * Body of the `200` response of `GET /v1/devices/{user}/{device}/registration`:
 * the authentication epoch and the server time the registered key was
 * installed at, in epoch milliseconds.
 */
@Serializable
internal class DeviceRegistrationStateResponse(val authEpoch: Long, val authKeyInstalledAt: Long)

/**
 * Body of `PUT /v1/devices/{user}/{device}/last-device-recovery/key`
 * (docs/last-device-recovery.md): the recovery public key and its proof of
 * possession. Registered for the path's user. Never a private key.
 */
@Serializable
internal class LastDeviceRecoveryKeyRequest(val publicKey: String, val proofOfPossession: String)

/**
 * Body of the `200` response of
 * `POST /v1/devices/{user}/{device}/last-device-recovery/challenge`.
 * [expiresAt] is epoch milliseconds (server clock).
 */
@Serializable
internal class LastDeviceRecoveryChallengeResponse(
    val challengeId: String,
    val challengeNonce: String,
    val authEpoch: Long,
    val expiresAt: Long,
)

/**
 * Body of `PUT /v1/devices/{user}/{device}/last-device-recovery`
 * (docs/last-device-recovery.md). The target is in the path; the challenge
 * fields are the ones the server issued. The signatures cover the binary
 * recovery statement, never this JSON.
 */
@Serializable
internal class LastDeviceRecoveryRequestDto(
    val recoveryPublicKey: String,
    val challengeId: String,
    val challengeNonce: String,
    val authEpoch: Long,
    val expiresAt: Long,
    val replacementPublicKey: String,
    val recoverySignature: String,
    val proofOfPossession: String,
)

/**
 * Body of the `200` response of `GET /v1/devices/{user}/{device}/last-device-recovery/key`
 * (docs/recovery-key-lifecycle.md). [state] is `unconfigured`, `active` or
 * `revoked`; times are epoch milliseconds (server clock). [installedAt] and
 * [activePublicKey] are set only while `active`, [revokedAt] only when
 * `revoked`, [recoveryKeyEpoch] unless `unconfigured`. Every field is always
 * present (`null` when not set).
 */
@Serializable
internal class LastDeviceRecoveryKeyStatusResponse(
    val state: String,
    val recoveryKeyEpoch: Long?,
    val installedAt: Long?,
    val revokedAt: Long?,
    val activePublicKey: String?,
)

/**
 * Body of `PUT /v1/devices/{user}/{device}/last-device-recovery/key/rotation`
 * (docs/recovery-key-lifecycle.md). The user and the authorizing device are
 * the path's. [timestamp] is epoch milliseconds; the signatures cover the
 * binary rotation statement, never this JSON.
 */
@Serializable
internal class RecoveryKeyRotationRequestDto(
    val currentPublicKey: String,
    val newPublicKey: String,
    val recoveryKeyEpoch: Long,
    val timestamp: Long,
    val nonce: String,
    val currentKeySignature: String,
    val newKeyProofOfPossession: String,
)

/**
 * Body of `PUT /v1/devices/{user}/{device}/last-device-recovery/key/revocation`
 * (docs/recovery-key-lifecycle.md). The user and the authorizing device are
 * the path's. The signature covers the binary revocation statement.
 */
@Serializable
internal class RecoveryKeyRevocationRequestDto(
    val publicKey: String,
    val recoveryKeyEpoch: Long,
    val timestamp: Long,
    val nonce: String,
    val signature: String,
)

/**
 * The pending recovery key reset of the route's user (docs/recovery-key-reset.md):
 * `state` is `none` or `pending`; every other field is set only while
 * `pending` and always present (`null` otherwise). [resetId] and
 * [recoveryPublicKey] are Base64, times epoch milliseconds (server clock),
 * [requestedByDevice] a device of the route's user.
 */
@Serializable
internal class RecoveryKeyResetStatusResponse(
    val state: String,
    val resetId: String?,
    val requestedByDevice: String?,
    val requestedAt: Long?,
    val eligibleAt: Long?,
    val recoveryKeyEpoch: Long?,
    val recoveryPublicKey: String?,
)

/**
 * Body of `PUT /v1/devices/{user}/{device}/last-device-recovery/key/reset/completion`.
 * The user and the completing device are the path's; the other fields
 * repeat the pending reset. The proof of possession covers the binary
 * completion statement, never this JSON.
 */
@Serializable
internal class RecoveryKeyResetCompletionRequestDto(
    val resetId: String,
    val currentPublicKey: String,
    val newPublicKey: String,
    val recoveryKeyEpoch: Long,
    val requestedAt: Long,
    val eligibleAt: Long,
    val newKeyProofOfPossession: String,
)

/** Body of `PUT /v1/devices/{user}/{device}/last-device-recovery/key/reset/cancellation`: the reset the device cancels. */
@Serializable
internal class RecoveryKeyResetCancellationRequestDto(val resetId: String)

/**
 * Body of `PUT /v1/users/{user}/last-device-recovery/key/reset/cancellation`
 * (no device, no ServerAuth): the pending reset and the current recovery
 * key's signature over the binary cancellation statement.
 */
@Serializable
internal class RecoveryKeyResetRecoveryKeyCancellationRequestDto(
    val resetId: String,
    val publicKey: String,
    val recoveryKeyEpoch: Long,
    val requestedAt: Long,
    val eligibleAt: Long,
    val signature: String,
)

/**
 * Body of `POST /v1/users/{user}/last-device-recovery/key/reset/status` (no
 * device, no ServerAuth): the current recovery key's signature over the
 * binary status query statement.
 */
@Serializable
internal class RecoveryKeyResetStatusQueryDto(val publicKey: String, val timestamp: Long, val signature: String)

/** Body of 4xx responses. */
@Serializable
internal class ErrorResponse(val error: String)

/**
 * Throws [IllegalArgumentException] for invalid Base64 or a negative ID. Key
 * sizes are checked later, by the service.
 */
internal fun PreKeyPublicationRequest.toPublication(address: DeviceAddress) = PreKeyPublication(
    address = address,
    identityKey = Base64.decode(identityKey),
    signedPreKey = PublicSignedPreKey(
        SignedPreKeyId(signedPreKey.id),
        Base64.decode(signedPreKey.publicKey),
        Base64.decode(signedPreKey.signature),
    ),
    oneTimePreKeys = oneTimePreKeys.map { PublicOneTimePreKey(OneTimePreKeyId(it.id), Base64.decode(it.publicKey)) },
)

/** Throws [IllegalArgumentException] for invalid Base64. The key size is checked by the server. */
internal fun DeviceRegistrationRequest.toRegistration(address: DeviceAddress) = DeviceRegistration(address, Base64.decode(publicKey))

/**
 * Throws [IllegalArgumentException] for non-canonical Base64, wrong key,
 * nonce or signature sizes, or a negative timestamp.
 */
internal fun DeviceRecoveryRequestDto.toAuthorization(target: DeviceAddress) = DeviceRecoveryAuthorization(
    DeviceRecoveryRequest(
        target = target,
        authorizer = DeviceAddress(UserId(authorizer.userId), DeviceId(authorizer.deviceId)),
        replacementPublicKey = decodeCanonicalBase64(replacementPublicKey),
        timestamp = Instant.fromEpochMilliseconds(timestamp),
        nonce = RequestNonce(decodeCanonicalBase64(nonce)),
        proofOfPossession = decodeCanonicalBase64(proofOfPossession),
    ),
    decodeCanonicalBase64(authorizerSignature),
)

/**
 * Throws [IllegalArgumentException] for non-canonical Base64, wrong key,
 * nonce or signature sizes, a non-positive epoch, a negative timestamp, or
 * the same key twice.
 */
internal fun DeviceAuthenticationRotationRequestDto.toAuthorization(address: DeviceAddress) = DeviceAuthenticationRotationAuthorization(
    DeviceAuthenticationRotationStatement(
        address = address,
        currentPublicKey = decodeCanonicalBase64(currentPublicKey),
        replacementPublicKey = decodeCanonicalBase64(replacementPublicKey),
        expectedAuthEpoch = authEpoch,
        timestamp = Instant.fromEpochMilliseconds(timestamp),
        nonce = RequestNonce(decodeCanonicalBase64(nonce)),
    ),
    decodeCanonicalBase64(authorizationSignature),
    decodeCanonicalBase64(proofOfPossession),
)

/** Throws [IllegalArgumentException] for non-canonical Base64 or wrong sizes. */
internal fun LastDeviceRecoveryKeyRequest.toRegistration(address: DeviceAddress) = LastDeviceRecoveryKeyRegistration(
    address.userId,
    decodeCanonicalBase64(publicKey),
    decodeCanonicalBase64(proofOfPossession),
)

internal fun LastDeviceRecoveryChallenge.toResponse() = LastDeviceRecoveryChallengeResponse(
    challengeId = Base64.encode(id.bytes),
    challengeNonce = Base64.encode(nonce),
    authEpoch = authEpoch,
    expiresAt = expiresAt.toEpochMilliseconds(),
)

/**
 * Throws [IllegalArgumentException] for non-canonical Base64, wrong sizes, a
 * non-positive epoch, a negative expiry, or the recovery key as replacement.
 */
internal fun LastDeviceRecoveryRequestDto.toAuthorization(target: DeviceAddress) = LastDeviceRecoveryAuthorization(
    LastDeviceRecoveryStatement(
        LastDeviceRecoveryChallenge(
            target = target,
            id = LastDeviceRecoveryChallengeId(decodeCanonicalBase64(challengeId)),
            nonce = decodeCanonicalBase64(challengeNonce),
            authEpoch = authEpoch,
            expiresAt = Instant.fromEpochMilliseconds(expiresAt),
        ),
        recoveryPublicKey = decodeCanonicalBase64(recoveryPublicKey),
        replacementPublicKey = decodeCanonicalBase64(replacementPublicKey),
    ),
    decodeCanonicalBase64(recoverySignature),
    decodeCanonicalBase64(proofOfPossession),
)

internal fun LastDeviceRecoveryKeyStatus.toResponse() = when (this) {
    LastDeviceRecoveryKeyStatus.Unconfigured -> LastDeviceRecoveryKeyStatusResponse("unconfigured", null, null, null, null)
    is LastDeviceRecoveryKeyStatus.Active ->
        LastDeviceRecoveryKeyStatusResponse("active", epoch, installedAt.toEpochMilliseconds(), null, Base64.encode(publicKey))
    is LastDeviceRecoveryKeyStatus.Revoked -> LastDeviceRecoveryKeyStatusResponse("revoked", epoch, null, revokedAt.toEpochMilliseconds(), null)
}

/**
 * Throws [IllegalArgumentException] for non-canonical Base64, wrong sizes, a
 * non-positive epoch, a negative timestamp, or the same key twice.
 */
internal fun RecoveryKeyRotationRequestDto.toAuthorization(authorizer: DeviceAddress) = RecoveryKeyRotationAuthorization(
    RecoveryKeyRotationStatement(
        userId = authorizer.userId,
        authorizer = authorizer,
        currentPublicKey = decodeCanonicalBase64(currentPublicKey),
        newPublicKey = decodeCanonicalBase64(newPublicKey),
        expectedEpoch = recoveryKeyEpoch,
        timestamp = Instant.fromEpochMilliseconds(timestamp),
        nonce = RequestNonce(decodeCanonicalBase64(nonce)),
    ),
    decodeCanonicalBase64(currentKeySignature),
    decodeCanonicalBase64(newKeyProofOfPossession),
)

/** Throws [IllegalArgumentException] for non-canonical Base64, wrong sizes, a non-positive epoch or a negative timestamp. */
internal fun RecoveryKeyRevocationRequestDto.toAuthorization(authorizer: DeviceAddress) = RecoveryKeyRevocationAuthorization(
    RecoveryKeyRevocationStatement(
        userId = authorizer.userId,
        authorizer = authorizer,
        currentPublicKey = decodeCanonicalBase64(publicKey),
        expectedEpoch = recoveryKeyEpoch,
        timestamp = Instant.fromEpochMilliseconds(timestamp),
        nonce = RequestNonce(decodeCanonicalBase64(nonce)),
    ),
    decodeCanonicalBase64(signature),
)

internal fun RecoveryKeyResetStatus.toResponse() = when (this) {
    RecoveryKeyResetStatus.None -> RecoveryKeyResetStatusResponse("none", null, null, null, null, null, null)
    is RecoveryKeyResetStatus.Pending -> RecoveryKeyResetStatusResponse(
        "pending", Base64.encode(resetId.bytes), requestedBy.deviceId.value, requestedAt.toEpochMilliseconds(),
        eligibleAt.toEpochMilliseconds(), recoveryKeyEpoch, Base64.encode(recoveryPublicKey),
    )
}

/** Throws [IllegalArgumentException] for non-canonical Base64, wrong sizes, a non-positive epoch, invalid times or the same key twice. */
internal fun RecoveryKeyResetCompletionRequestDto.toAuthorization(completer: DeviceAddress) = RecoveryKeyResetCompletionAuthorization(
    RecoveryKeyResetCompletionStatement(
        userId = completer.userId,
        resetId = RecoveryKeyResetId(decodeCanonicalBase64(resetId)),
        expectedEpoch = recoveryKeyEpoch,
        currentPublicKey = decodeCanonicalBase64(currentPublicKey),
        newPublicKey = decodeCanonicalBase64(newPublicKey),
        requestedAt = Instant.fromEpochMilliseconds(requestedAt),
        eligibleAt = Instant.fromEpochMilliseconds(eligibleAt),
        completer = completer,
    ),
    decodeCanonicalBase64(newKeyProofOfPossession),
)

internal fun RecoveryKeyResetCancellationRequestDto.toResetId() = RecoveryKeyResetId(decodeCanonicalBase64(resetId))

/** Throws [IllegalArgumentException] for non-canonical Base64, wrong sizes, a non-positive epoch or invalid times. */
internal fun RecoveryKeyResetRecoveryKeyCancellationRequestDto.toAuthorization(userId: UserId) = RecoveryKeyResetCancellationAuthorization(
    RecoveryKeyResetCancellationStatement(
        userId = userId,
        resetId = RecoveryKeyResetId(decodeCanonicalBase64(resetId)),
        expectedEpoch = recoveryKeyEpoch,
        currentPublicKey = decodeCanonicalBase64(publicKey),
        requestedAt = Instant.fromEpochMilliseconds(requestedAt),
        eligibleAt = Instant.fromEpochMilliseconds(eligibleAt),
    ),
    decodeCanonicalBase64(signature),
)

/** Throws [IllegalArgumentException] for non-canonical Base64, wrong sizes or a negative timestamp. */
internal fun RecoveryKeyResetStatusQueryDto.toQuery(userId: UserId) = RecoveryKeyResetStatusQuery(
    RecoveryKeyResetStatusQueryStatement(userId, decodeCanonicalBase64(publicKey), Instant.fromEpochMilliseconds(timestamp)),
    decodeCanonicalBase64(signature),
)

/** Standard Base64 with padding, canonical only. */
internal fun decodeCanonicalBase64(value: String): ByteArray {
    val bytes = Base64.decode(value)
    require(Base64.encode(bytes) == value) { "Non-canonical Base64" }
    return bytes
}

/**
 * Request authentication headers, format version 1 (docs/server-authentication.md).
 * Mirrored in client:ktor.
 */
internal object AuthHeaders {
    const val VERSION = "X-KSecureMessage-Auth-Version"
    const val TIMESTAMP = "X-KSecureMessage-Timestamp"
    const val NONCE = "X-KSecureMessage-Nonce"
    const val SIGNATURE = "X-KSecureMessage-Signature"
    const val CURRENT_VERSION = "1"
}

internal fun PreKeyBundle.toResponse() = PreKeyBundleResponse(
    identityKey = Base64.encode(identityKey),
    signedPreKey = SignedPreKeyDto(signedPreKey.id.value, Base64.encode(signedPreKey.publicKey), Base64.encode(signedPreKey.signature)),
    oneTimePreKey = oneTimePreKey?.let { OneTimePreKeyDto(it.id.value, Base64.encode(it.publicKey)) },
)
