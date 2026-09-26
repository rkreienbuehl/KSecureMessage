package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationStatement
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryRequest
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

/** Body of the `200` response of `GET /v1/devices/{user}/{device}/registration`. */
@Serializable
internal class DeviceRegistrationStateResponse(val authEpoch: Long)

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
