package dev.kreienbuehl.ksecuremessage.client.ktor

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.serialization.kotlinx.json.json

class KtorSecureMessageTransport(
    private val baseUrl: String,
    private val client: HttpClient = HttpClient {
        install(ContentNegotiation) { json() }
    },
) : SecureMessageTransport {

    override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle =
        client.get("$baseUrl/users/${address.userId.value}/devices/${address.deviceId.value}/prekeys").body()

    override suspend fun send(envelope: EncryptedEnvelope) {
        client.post("$baseUrl/messages") { setBody(envelope) }
    }

    override suspend fun receive(address: DeviceAddress): List<EncryptedEnvelope> =
        client.get("$baseUrl/users/${address.userId.value}/devices/${address.deviceId.value}/messages").body()
}
