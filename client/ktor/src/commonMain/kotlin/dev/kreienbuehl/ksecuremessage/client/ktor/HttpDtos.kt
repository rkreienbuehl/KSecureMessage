package dev.kreienbuehl.ksecuremessage.client.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
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
 * Request authentication headers, format version 1 (docs/server-authentication.md).
 * Mirrored in server:ktor.
 */
internal object AuthHeaders {
    const val VERSION = "X-KSecureMessage-Auth-Version"
    const val TIMESTAMP = "X-KSecureMessage-Timestamp"
    const val NONCE = "X-KSecureMessage-Nonce"
    const val SIGNATURE = "X-KSecureMessage-Signature"
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
