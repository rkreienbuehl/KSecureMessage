package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import kotlinx.serialization.Serializable
import kotlin.io.encoding.Base64

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

internal fun PreKeyBundle.toResponse() = PreKeyBundleResponse(
    identityKey = Base64.encode(identityKey),
    signedPreKey = SignedPreKeyDto(signedPreKey.id.value, Base64.encode(signedPreKey.publicKey), Base64.encode(signedPreKey.signature)),
    oneTimePreKey = oneTimePreKey?.let { OneTimePreKeyDto(it.id.value, Base64.encode(it.publicKey)) },
)
