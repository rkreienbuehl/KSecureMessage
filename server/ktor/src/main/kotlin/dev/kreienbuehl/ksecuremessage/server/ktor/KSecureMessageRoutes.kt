package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.server.DeviceAuthenticationException
import dev.kreienbuehl.ksecuremessage.server.ProtectedEndpoint
import dev.kreienbuehl.ksecuremessage.server.SecureMessageServer
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.log
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import kotlinx.serialization.json.Json
import kotlin.coroutines.cancellation.CancellationException
import kotlin.io.encoding.Base64
import kotlin.time.Instant

/**
 * KSecureMessage HTTP API v1, see docs/prekey-publication.md and
 * docs/server-authentication.md. The application must install
 * ContentNegotiation with JSON. Routes only map HTTP to
 * [SecureMessageServer]; authentication, validation, conflicts and atomicity
 * live behind it.
 *
 * Registration, prekey publication and mailbox drain are authenticated by
 * the device: the signature covers the exact body bytes, so those routes read
 * the raw body and authenticate it before parsing anything that is acted on.
 * A request that fails authentication gets 401 and changes nothing. Prekey
 * bundle fetch and message submission are public. Unexpected failures of
 * the server or its storage get 500 with `internal_error` and no details.
 */
fun Route.kSecureMessageRoutes(server: SecureMessageServer) {
    put("/v1/devices/{user}/{device}/registration") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        // The body names the key to verify with, so it is parsed first; nothing is stored before verification.
        val registration = try {
            Json.decodeFromString<DeviceRegistrationRequest>(body.decodeToString()).toRegistration(address)
        } catch (e: IllegalArgumentException) {
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_REGISTRATION)
        }
        try {
            val created = server.registerDevice(registration, body, call.authentication())
            call.respond(if (created) HttpStatusCode.Created else HttpStatusCode.NoContent)
        } catch (e: DeviceAuthenticationException) {
            call.respondAuthenticationError(e)
        } catch (e: DeviceRegistrationException) {
            when (e) {
                is DeviceRegistrationException.InvalidRegistration -> call.respondError(HttpStatusCode.BadRequest, INVALID_REGISTRATION)
                is DeviceRegistrationException.Conflict -> call.respondError(HttpStatusCode.Conflict, "device_registration_conflict")
            }
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    put("/v1/devices/{user}/{device}/prekeys") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        val device = try {
            server.authenticate(address, ProtectedEndpoint.PUBLISH_PRE_KEYS, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@put call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@put call.respondInternalError(e)
        }
        val publication = try {
            Json.decodeFromString<PreKeyPublicationRequest>(body.decodeToString()).toPublication(address)
        } catch (e: IllegalArgumentException) {
            // Malformed JSON (SerializationException), bad Base64 or a negative ID.
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_PUBLICATION)
        }
        try {
            server.publishPreKeys(device, publication)
            call.respond(HttpStatusCode.NoContent)
        } catch (e: PreKeyPublicationException) {
            when (e) {
                is PreKeyPublicationException.InvalidPublication -> call.respondError(HttpStatusCode.BadRequest, INVALID_PUBLICATION)
                is PreKeyPublicationException.IdentityKeyConflict -> call.respondError(HttpStatusCode.Conflict, "identity_key_conflict")
                is PreKeyPublicationException.SignedPreKeyConflict -> call.respondError(HttpStatusCode.Conflict, "signed_pre_key_conflict")
                is PreKeyPublicationException.OneTimePreKeyConflict -> call.respondError(HttpStatusCode.Conflict, "one_time_pre_key_conflict")
            }
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    get("/v1/devices/{user}/{device}/prekey-bundle") {
        val address = call.deviceAddress()
        val bundle = try {
            server.fetchPreKeyBundle(address)
        } catch (e: Exception) {
            return@get call.respondInternalError(e)
        }
        if (bundle == null) call.respondError(HttpStatusCode.NotFound, "device_not_found")
        else call.respond(bundle.toResponse())
    }

    post("/v1/messages") {
        val envelope = call.receive<EncryptedEnvelope>()
        try {
            // Returns once the envelope is stored, so 202 is never sent for an envelope that was not.
            server.relay(envelope)
        } catch (e: Exception) {
            return@post call.respondInternalError(e)
        }
        call.respond(HttpStatusCode.Accepted)
    }

    get("/v1/devices/{user}/{device}/messages") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        val device = try {
            server.authenticate(address, ProtectedEndpoint.DRAIN_MAILBOX, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@get call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@get call.respondInternalError(e)
        }
        val envelopes = try {
            server.receive(device)
        } catch (e: Exception) {
            return@get call.respondInternalError(e)
        }
        call.respond(envelopes)
    }
}

private const val INVALID_PUBLICATION = "invalid_publication"
private const val INVALID_REGISTRATION = "invalid_registration"

private suspend fun ApplicationCall.respondError(status: HttpStatusCode, error: String) =
    respond(status, ErrorResponse(error))

/**
 * Any other failure of the server or its storage, for example a database
 * error: a generic 500 whose body never carries the exception message (it may
 * name SQL tables or statements). Logged on the server. Cancellation is
 * rethrown.
 */
private suspend fun ApplicationCall.respondInternalError(e: Exception) {
    if (e is CancellationException) throw e
    application.log.error("Unexpected server failure", e)
    respondError(HttpStatusCode.InternalServerError, "internal_error")
}

private suspend fun ApplicationCall.respondAuthenticationError(e: DeviceAuthenticationException) =
    respondError(
        HttpStatusCode.Unauthorized,
        when (e) {
            is DeviceAuthenticationException.MissingAuthentication -> "missing_authentication"
            is DeviceAuthenticationException.DeviceNotRegistered -> "device_not_registered"
            is DeviceAuthenticationException.ExpiredAuthentication -> "expired_authentication"
            is DeviceAuthenticationException.InvalidAuthentication -> "invalid_authentication"
            is DeviceAuthenticationException.AuthenticationReplay -> "authentication_replay"
        },
    )

private fun ApplicationCall.deviceAddress(): DeviceAddress = DeviceAddress(
    userId = UserId(requireNotNull(parameters["user"])),
    deviceId = DeviceId(requireNotNull(parameters["device"])),
)

/**
 * The request's authentication headers, or `null` if it carries none of
 * them. Throws [DeviceAuthenticationException.InvalidAuthentication] if they
 * are incomplete, repeated or malformed.
 */
private fun ApplicationCall.authentication(): RequestAuthentication? {
    val headers = request.headers
    val names = listOf(AuthHeaders.VERSION, AuthHeaders.TIMESTAMP, AuthHeaders.NONCE, AuthHeaders.SIGNATURE)
    if (names.all { headers[it] == null }) return null
    val values = names.map { headers.getAll(it)?.singleOrNull() ?: throw DeviceAuthenticationException.InvalidAuthentication() }
    val (version, timestamp, nonce, signature) = values
    if (version != AuthHeaders.CURRENT_VERSION) throw DeviceAuthenticationException.InvalidAuthentication()
    return try {
        RequestAuthentication(
            timestamp = Instant.fromEpochMilliseconds(parseTimestamp(timestamp)),
            nonce = RequestNonce(decodeBase64(nonce)),
            signature = decodeBase64(signature).also {
                require(it.size == ServerRequestAuthentication.SIGNATURE_SIZE) { "Invalid signature size" }
            },
        )
    } catch (e: IllegalArgumentException) {
        throw DeviceAuthenticationException.InvalidAuthentication()
    }
}

/** Decimal epoch milliseconds: ASCII digits only, at most 18 of them, so no sign and no overflow. */
private fun parseTimestamp(value: String): Long {
    require(value.length in 1..18 && value.all { it in '0'..'9' }) { "Invalid timestamp" }
    return value.toLong()
}

/** Standard Base64 with padding, canonical only. */
private fun decodeBase64(value: String): ByteArray {
    val bytes = Base64.decode(value)
    require(Base64.encode(bytes) == value) { "Non-canonical Base64" }
    return bytes
}
