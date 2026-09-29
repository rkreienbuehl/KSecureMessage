package dev.kreienbuehl.ksecuremessage.client.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
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
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQuery
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
import kotlinx.serialization.Serializable
import kotlin.io.encoding.Base64

// HTTP API v1 bodies. Mirrored in server:ktor; keep both in sync (see
// docs/prekey-publication.md). Binary fields are Base64 strings (RFC 4648
// standard alphabet, with padding). Public keys only.

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

/** Body of 4xx responses. */
@Serializable
internal class ErrorResponse(val error: String)

/** Body of `PUT /v1/devices/{user}/{device}/last-device-recovery/key` (docs/last-device-recovery.md). */
@Serializable
internal class LastDeviceRecoveryKeyRequest(val publicKey: String, val proofOfPossession: String)

/** Body of the `200` response of `POST /v1/devices/{user}/{device}/last-device-recovery/challenge`. */
@Serializable
internal class LastDeviceRecoveryChallengeResponse(
    val challengeId: String,
    val challengeNonce: String,
    val authEpoch: Long,
    val expiresAt: Long,
)

/** Body of `PUT /v1/devices/{user}/{device}/last-device-recovery`. The target is in the path. */
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
 * (docs/recovery-key-lifecycle.md).
 */
@Serializable
internal class LastDeviceRecoveryKeyStatusResponse(
    val state: String,
    val recoveryKeyEpoch: Long?,
    val installedAt: Long?,
    val revokedAt: Long?,
    val activePublicKey: String?,
)

/** The pending recovery key reset of the route's user (docs/recovery-key-reset.md). Mirrors server:ktor. */
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

/** Body of `PUT /v1/devices/{user}/{device}/last-device-recovery/key/reset/completion`. User and completing device are in the path. */
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

/** Body of `PUT /v1/devices/{user}/{device}/last-device-recovery/key/reset/cancellation`. */
@Serializable
internal class RecoveryKeyResetCancellationRequestDto(val resetId: String)

/** Body of `PUT /v1/users/{user}/last-device-recovery/key/reset/cancellation`. The user is in the path. */
@Serializable
internal class RecoveryKeyResetRecoveryKeyCancellationRequestDto(
    val resetId: String,
    val publicKey: String,
    val recoveryKeyEpoch: Long,
    val requestedAt: Long,
    val eligibleAt: Long,
    val signature: String,
)

/** Body of `POST /v1/users/{user}/last-device-recovery/key/reset/status`. The user is in the path. */
@Serializable
internal class RecoveryKeyResetStatusQueryDto(val publicKey: String, val timestamp: Long, val signature: String)

/** Body of `PUT /v1/devices/{user}/{device}/last-device-recovery/key/rotation`. User and authorizing device are in the path. */
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

/** Body of `PUT /v1/devices/{user}/{device}/last-device-recovery/key/revocation`. User and authorizing device are in the path. */
@Serializable
internal class RecoveryKeyRevocationRequestDto(
    val publicKey: String,
    val recoveryKeyEpoch: Long,
    val timestamp: Long,
    val nonce: String,
    val signature: String,
)

/**
 * Request authentication headers, format version 1 (docs/server-authentication.md).
 * Mirrored in server:ktor.
 */
internal object AuthHeaders {
    const val VERSION = "X-KSecureMessage-Auth-Version"
    const val TIMESTAMP = "X-KSecureMessage-Timestamp"
    const val NONCE = "X-KSecureMessage-Nonce"
    const val SIGNATURE = "X-KSecureMessage-Signature"

    /** The submitting device of `POST /v1/messages` (`ServerApiPaths.encodeDevice`); S1. */
    const val DEVICE = "X-KSecureMessage-Device"
    const val CURRENT_VERSION = "1"
}

internal fun PreKeyPublication.toRequest() = PreKeyPublicationRequest(
    identityKey = Base64.encode(identityKey),
    signedPreKey = SignedPreKeyDto(signedPreKey.id.value, Base64.encode(signedPreKey.publicKey), Base64.encode(signedPreKey.signature)),
    oneTimePreKeys = oneTimePreKeys.map { OneTimePreKeyDto(it.id.value, Base64.encode(it.publicKey)) },
)

/** Throws [IllegalArgumentException] for invalid Base64 or a negative ID. */
internal fun PreKeyBundleResponse.toBundle(address: DeviceAddress) = PreKeyBundle(
    address = address,
    identityKey = Base64.decode(identityKey),
    signedPreKey = PublicSignedPreKey(
        SignedPreKeyId(signedPreKey.id),
        Base64.decode(signedPreKey.publicKey),
        Base64.decode(signedPreKey.signature),
    ),
    oneTimePreKey = oneTimePreKey?.let { PublicOneTimePreKey(OneTimePreKeyId(it.id), Base64.decode(it.publicKey)) },
)

internal fun DeviceRecoveryAuthorization.toRequest() = DeviceRecoveryRequestDto(
    authorizer = DeviceAddressDto(request.authorizer.userId.value, request.authorizer.deviceId.value),
    replacementPublicKey = Base64.encode(request.replacementPublicKey),
    timestamp = request.timestamp.toEpochMilliseconds(),
    nonce = Base64.encode(request.nonce.bytes),
    proofOfPossession = Base64.encode(request.proofOfPossession),
    authorizerSignature = Base64.encode(authorizerSignature),
)

internal fun DeviceAuthenticationRotationAuthorization.toRequest() = DeviceAuthenticationRotationRequestDto(
    currentPublicKey = Base64.encode(statement.currentPublicKey),
    replacementPublicKey = Base64.encode(statement.replacementPublicKey),
    authEpoch = statement.expectedAuthEpoch,
    timestamp = statement.timestamp.toEpochMilliseconds(),
    nonce = Base64.encode(statement.nonce.bytes),
    authorizationSignature = Base64.encode(authorizationSignature),
    proofOfPossession = Base64.encode(proofOfPossession),
)

internal fun LastDeviceRecoveryKeyRegistration.toRequest() =
    LastDeviceRecoveryKeyRequest(Base64.encode(publicKey), Base64.encode(proofOfPossession))

/** Throws [IllegalArgumentException] for invalid Base64, sizes, epoch or expiry. */
internal fun LastDeviceRecoveryChallengeResponse.toChallenge(target: DeviceAddress) = LastDeviceRecoveryChallenge(
    target = target,
    id = LastDeviceRecoveryChallengeId(Base64.decode(challengeId)),
    nonce = Base64.decode(challengeNonce),
    authEpoch = authEpoch,
    expiresAt = kotlin.time.Instant.fromEpochMilliseconds(expiresAt),
)

internal fun LastDeviceRecoveryAuthorization.toRequest(): LastDeviceRecoveryRequestDto {
    val challenge = statement.challenge
    return LastDeviceRecoveryRequestDto(
        recoveryPublicKey = Base64.encode(statement.recoveryPublicKey),
        challengeId = Base64.encode(challenge.id.bytes),
        challengeNonce = Base64.encode(challenge.nonce),
        authEpoch = challenge.authEpoch,
        expiresAt = challenge.expiresAt.toEpochMilliseconds(),
        replacementPublicKey = Base64.encode(statement.replacementPublicKey),
        recoverySignature = Base64.encode(recoverySignature),
        proofOfPossession = Base64.encode(proofOfPossession),
    )
}

/**
 * Throws [IllegalArgumentException] for an unknown state, invalid Base64, a
 * missing field for the state, a field that must be absent, or a
 * non-positive epoch.
 */
internal fun LastDeviceRecoveryKeyStatusResponse.toStatus(): LastDeviceRecoveryKeyStatus = when (state) {
    "unconfigured" -> {
        require(recoveryKeyEpoch == null && installedAt == null && revokedAt == null && activePublicKey == null) { "Unexpected fields" }
        LastDeviceRecoveryKeyStatus.Unconfigured
    }
    "active" -> {
        require(revokedAt == null) { "Unexpected field" }
        LastDeviceRecoveryKeyStatus.Active(
            requireNotNull(recoveryKeyEpoch),
            kotlin.time.Instant.fromEpochMilliseconds(requireNotNull(installedAt)),
            Base64.decode(requireNotNull(activePublicKey)).also { require(it.size == 32) { "Invalid key size" } },
        )
    }
    "revoked" -> {
        require(installedAt == null && activePublicKey == null) { "Unexpected fields" }
        LastDeviceRecoveryKeyStatus.Revoked(requireNotNull(recoveryKeyEpoch), kotlin.time.Instant.fromEpochMilliseconds(requireNotNull(revokedAt)))
    }
    else -> throw IllegalArgumentException("Unknown recovery key state")
}

/** Strict: a field that does not belong to the state, a missing one or a wrong size is rejected. [userId] is the route's. */
internal fun RecoveryKeyResetStatusResponse.toStatus(userId: UserId): RecoveryKeyResetStatus = when (state) {
    "none" -> {
        require(
            resetId == null && requestedByDevice == null && requestedAt == null && eligibleAt == null &&
                recoveryKeyEpoch == null && recoveryPublicKey == null,
        ) { "Unexpected fields" }
        RecoveryKeyResetStatus.None
    }
    "pending" -> RecoveryKeyResetStatus.Pending(
        resetId = RecoveryKeyResetId(Base64.decode(requireNotNull(resetId))),
        requestedBy = DeviceAddress(userId, DeviceId(requireNotNull(requestedByDevice))),
        requestedAt = kotlin.time.Instant.fromEpochMilliseconds(requireNotNull(requestedAt)),
        eligibleAt = kotlin.time.Instant.fromEpochMilliseconds(requireNotNull(eligibleAt)),
        recoveryKeyEpoch = requireNotNull(recoveryKeyEpoch),
        recoveryPublicKey = Base64.decode(requireNotNull(recoveryPublicKey)),
    )
    else -> throw IllegalArgumentException("Unknown recovery key reset state")
}

internal fun RecoveryKeyResetCompletionAuthorization.toRequest() = RecoveryKeyResetCompletionRequestDto(
    resetId = Base64.encode(statement.resetId.bytes),
    currentPublicKey = Base64.encode(statement.currentPublicKey),
    newPublicKey = Base64.encode(statement.newPublicKey),
    recoveryKeyEpoch = statement.expectedEpoch,
    requestedAt = statement.requestedAt.toEpochMilliseconds(),
    eligibleAt = statement.eligibleAt.toEpochMilliseconds(),
    newKeyProofOfPossession = Base64.encode(newKeyProofOfPossession),
)

internal fun RecoveryKeyResetCancellationAuthorization.toRequest() = RecoveryKeyResetRecoveryKeyCancellationRequestDto(
    resetId = Base64.encode(statement.resetId.bytes),
    publicKey = Base64.encode(statement.currentPublicKey),
    recoveryKeyEpoch = statement.expectedEpoch,
    requestedAt = statement.requestedAt.toEpochMilliseconds(),
    eligibleAt = statement.eligibleAt.toEpochMilliseconds(),
    signature = Base64.encode(signature),
)

internal fun RecoveryKeyResetStatusQuery.toRequest() = RecoveryKeyResetStatusQueryDto(
    publicKey = Base64.encode(statement.currentPublicKey),
    timestamp = statement.timestamp.toEpochMilliseconds(),
    signature = Base64.encode(signature),
)

internal fun RecoveryKeyRotationAuthorization.toRequest() = RecoveryKeyRotationRequestDto(
    currentPublicKey = Base64.encode(statement.currentPublicKey),
    newPublicKey = Base64.encode(statement.newPublicKey),
    recoveryKeyEpoch = statement.expectedEpoch,
    timestamp = statement.timestamp.toEpochMilliseconds(),
    nonce = Base64.encode(statement.nonce.bytes),
    currentKeySignature = Base64.encode(currentKeySignature),
    newKeyProofOfPossession = Base64.encode(newKeyProofOfPossession),
)

internal fun RecoveryKeyRevocationAuthorization.toRequest() = RecoveryKeyRevocationRequestDto(
    publicKey = Base64.encode(statement.currentPublicKey),
    recoveryKeyEpoch = statement.expectedEpoch,
    timestamp = statement.timestamp.toEpochMilliseconds(),
    nonce = Base64.encode(statement.nonce.bytes),
    signature = Base64.encode(signature),
)
