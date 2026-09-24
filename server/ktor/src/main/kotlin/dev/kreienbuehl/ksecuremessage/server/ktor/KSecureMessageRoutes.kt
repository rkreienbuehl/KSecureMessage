package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.server.SecureMessageServer
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post

fun Route.kSecureMessageRoutes(server: SecureMessageServer) {
    post("/prekeys") {
        server.publishPreKeys(call.receive<PreKeyBundle>())
        call.respond(HttpStatusCode.NoContent)
    }

    get("/users/{user}/devices/{device}/prekeys") {
        val address = call.deviceAddress()
        val bundle = server.getPreKeys(address)
        if (bundle == null) call.respond(HttpStatusCode.NotFound)
        else call.respond(bundle)
    }

    post("/messages") {
        server.relay(call.receive<EncryptedEnvelope>())
        call.respond(HttpStatusCode.Accepted)
    }

    get("/users/{user}/devices/{device}/messages") {
        call.respond(server.receive(call.deviceAddress()))
    }
}

private fun io.ktor.server.application.ApplicationCall.deviceAddress(): DeviceAddress = DeviceAddress(
    userId = UserId(requireNotNull(parameters["user"])),
    deviceId = DeviceId(requireNotNull(parameters["device"])),
)
