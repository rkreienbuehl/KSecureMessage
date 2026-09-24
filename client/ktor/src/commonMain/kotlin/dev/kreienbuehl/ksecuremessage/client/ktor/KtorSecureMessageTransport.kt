package dev.kreienbuehl.ksecuremessage.client.ktor

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.Reason
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.encodeURLPathPart
import io.ktor.http.isSuccess
import io.ktor.serialization.kotlinx.json.json

/**
 * [SecureMessageTransport] over the KSecureMessage HTTP API v1. [client] must
 * have [ContentNegotiation] with JSON installed. Routes and bodies are
 * described in docs/prekey-publication.md.
 */
class KtorSecureMessageTransport(
    private val baseUrl: String,
    private val client: HttpClient = HttpClient {
        install(ContentNegotiation) { json() }
    },
) : SecureMessageTransport {

    override suspend fun publishPreKeys(publication: PreKeyPublication) {
        val response = client.put("${device(publication.address)}/prekeys") {
            contentType(ContentType.Application.Json)
            setBody(publication.toRequest())
        }
        when {
            response.status.isSuccess() -> Unit
            response.status == HttpStatusCode.BadRequest || response.status == HttpStatusCode.Conflict ->
                throw SecureMessageTransportException.PublicationRejected(response.rejectionReason())
            else -> throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
        }
    }

    /**
     * The returned bundle's address is always [address]; the server's
     * response carries none. The bundle is not trusted here: the protocol
     * engine verifies it before X3DH.
     */
    override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle {
        val response = client.get("${device(address)}/prekey-bundle")
        return when (response.status) {
            HttpStatusCode.OK -> try {
                response.body<PreKeyBundleResponse>().toBundle(address)
            } catch (e: IllegalArgumentException) {
                throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
            }
            HttpStatusCode.NotFound -> throw SecureMessageTransportException.DeviceNotFound(address)
            else -> throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
        }
    }

    override suspend fun send(envelope: EncryptedEnvelope) {
        val response = client.post("$baseUrl/v1/messages") {
            contentType(ContentType.Application.Json)
            setBody(envelope)
        }
        if (!response.status.isSuccess()) throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
    }

    override suspend fun receive(address: DeviceAddress): List<EncryptedEnvelope> {
        val response = client.get("${device(address)}/messages")
        if (!response.status.isSuccess()) throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
        return response.body()
    }

    private fun device(address: DeviceAddress) =
        "$baseUrl/v1/devices/${address.userId.value.encodeURLPathPart()}/${address.deviceId.value.encodeURLPathPart()}"

    private suspend fun HttpResponse.rejectionReason(): Reason {
        val error = runCatching { body<ErrorResponse>().error }.getOrNull()
        return when (error) {
            "identity_key_conflict" -> Reason.IDENTITY_KEY_CONFLICT
            "signed_pre_key_conflict" -> Reason.SIGNED_PRE_KEY_CONFLICT
            "one_time_pre_key_conflict" -> Reason.ONE_TIME_PRE_KEY_CONFLICT
            else -> Reason.INVALID_PUBLICATION
        }
    }
}
