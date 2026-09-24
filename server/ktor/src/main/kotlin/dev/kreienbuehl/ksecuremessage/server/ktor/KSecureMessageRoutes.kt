package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.server.SecureMessageServer
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.request.receiveText
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import kotlinx.serialization.json.Json

/**
 * KSecureMessage HTTP API v1, see docs/prekey-publication.md. The
 * application must install ContentNegotiation with JSON. Routes only map
 * HTTP to [SecureMessageServer]; validation, conflicts and atomicity live
 * behind it.
 */
fun Route.kSecureMessageRoutes(server: SecureMessageServer) {
    put("/v1/devices/{user}/{device}/prekeys") {
        val publication = try {
            Json.decodeFromString<PreKeyPublicationRequest>(call.receiveText()).toPublication(call.deviceAddress())
        } catch (e: IllegalArgumentException) {
            // Malformed JSON (SerializationException), bad Base64 or a negative ID.
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_PUBLICATION)
        }
        try {
            server.publishPreKeys(publication)
            call.respond(HttpStatusCode.NoContent)
        } catch (e: PreKeyPublicationException) {
            when (e) {
                is PreKeyPublicationException.InvalidPublication -> call.respondError(HttpStatusCode.BadRequest, INVALID_PUBLICATION)
                is PreKeyPublicationException.IdentityKeyConflict -> call.respondError(HttpStatusCode.Conflict, "identity_key_conflict")
                is PreKeyPublicationException.SignedPreKeyConflict -> call.respondError(HttpStatusCode.Conflict, "signed_pre_key_conflict")
                is PreKeyPublicationException.OneTimePreKeyConflict -> call.respondError(HttpStatusCode.Conflict, "one_time_pre_key_conflict")
            }
        }
    }

    get("/v1/devices/{user}/{device}/prekey-bundle") {
        val bundle = server.fetchPreKeyBundle(call.deviceAddress())
        if (bundle == null) call.respondError(HttpStatusCode.NotFound, "device_not_found")
        else call.respond(bundle.toResponse())
    }

    post("/v1/messages") {
        server.relay(call.receive<EncryptedEnvelope>())
        call.respond(HttpStatusCode.Accepted)
    }

    get("/v1/devices/{user}/{device}/messages") {
        call.respond(server.receive(call.deviceAddress()))
    }
}

private const val INVALID_PUBLICATION = "invalid_publication"

private suspend fun ApplicationCall.respondError(status: HttpStatusCode, error: String) =
    respond(status, ErrorResponse(error))

private fun ApplicationCall.deviceAddress(): DeviceAddress = DeviceAddress(
    userId = UserId(requireNotNull(parameters["user"])),
    deviceId = DeviceId(requireNotNull(parameters["device"])),
)
