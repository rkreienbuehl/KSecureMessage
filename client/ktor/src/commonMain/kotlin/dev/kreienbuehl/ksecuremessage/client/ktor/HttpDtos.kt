package dev.kreienbuehl.ksecuremessage.client.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
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

/** Body of 4xx responses. */
@Serializable
internal class ErrorResponse(val error: String)

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
