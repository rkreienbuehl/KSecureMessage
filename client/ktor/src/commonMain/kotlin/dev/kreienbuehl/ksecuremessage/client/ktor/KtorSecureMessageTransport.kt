package dev.kreienbuehl.ksecuremessage.client.ktor

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.AuthenticationFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.Reason
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryFailure
import dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.ByteArrayContent
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64

/**
 * [SecureMessageTransport] over the KSecureMessage HTTP API v1. [client] must
 * have [ContentNegotiation] with JSON installed. Routes and bodies are
 * described in docs/prekey-publication.md, authentication in
 * docs/server-authentication.md.
 *
 * Authenticated requests are built from their exact body bytes: the JSON is
 * encoded here, signed together with the method and canonical path, and sent
 * unchanged, so the server hashes what was signed. Each attempt is signed
 * anew (fresh timestamp and nonce).
 */
class KtorSecureMessageTransport(
    private val baseUrl: String,
    private val client: HttpClient = HttpClient {
        install(ContentNegotiation) { json() }
    },
) : SecureMessageTransport {

    override suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner) {
        val body = Json.encodeToString(DeviceRegistrationRequest(Base64.encode(registration.publicKey))).encodeToByteArray()
        val response = authenticated(HttpMethod.Put, registration.address, ServerApiPaths.REGISTRATION, body, signer)
        when {
            response.status.isSuccess() -> Unit
            response.status == HttpStatusCode.Conflict -> throw SecureMessageTransportException.DeviceRegistrationConflict()
            response.status == HttpStatusCode.BadRequest -> throw SecureMessageTransportException.RegistrationRejected()
            else -> throw response.unexpected()
        }
    }

    override suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization) {
        val target = authorization.request.target
        val body = Json.encodeToString(authorization.toRequest()).encodeToByteArray()
        val response = client.request(baseUrl + ServerApiPaths.device(target, ServerApiPaths.REGISTRATION_RECOVERY)) {
            method = HttpMethod.Put
            setBody(ByteArrayContent(body, ContentType.Application.Json))
        }
        if (response.status.isSuccess()) return
        val failure = when (runCatching { response.body<ErrorResponse>().error }.getOrNull()) {
            "invalid_recovery" -> RecoveryFailure.INVALID_REQUEST
            "recovery_self_authorization" -> RecoveryFailure.SELF_AUTHORIZATION
            "recovery_cross_user" -> RecoveryFailure.CROSS_USER
            "recovery_authorizer_not_registered" -> RecoveryFailure.AUTHORIZER_NOT_REGISTERED
            "recovery_target_not_registered" -> RecoveryFailure.TARGET_NOT_REGISTERED
            "expired_authentication" -> RecoveryFailure.EXPIRED
            "invalid_recovery_proof" -> RecoveryFailure.INVALID_PROOF
            "authentication_replay" -> RecoveryFailure.REPLAY
            "recovery_conflict" -> RecoveryFailure.CONFLICT
            else -> throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
        }
        throw SecureMessageTransportException.DeviceRecoveryRejected(failure)
    }

    override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) {
        val body = Json.encodeToString(publication.toRequest()).encodeToByteArray()
        val response = authenticated(HttpMethod.Put, publication.address, ServerApiPaths.PRE_KEYS, body, signer)
        when {
            response.status.isSuccess() -> Unit
            response.status == HttpStatusCode.BadRequest || response.status == HttpStatusCode.Conflict ->
                throw SecureMessageTransportException.PublicationRejected(response.rejectionReason())
            else -> throw response.unexpected()
        }
    }

    /**
     * The returned bundle's address is always [address]; the server's
     * response carries none. The bundle is not trusted here: the protocol
     * engine verifies it before X3DH.
     */
    override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle {
        val response = client.get(baseUrl + ServerApiPaths.device(address, ServerApiPaths.PRE_KEY_BUNDLE))
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

    override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope> {
        val response = authenticated(HttpMethod.Get, address, ServerApiPaths.MESSAGES, body = null, signer)
        if (!response.status.isSuccess()) throw response.unexpected()
        return response.body()
    }

    /** Signs and sends one device-scoped request. [body] `null` sends no body; its hash is that of no bytes. */
    private suspend fun authenticated(
        method: HttpMethod,
        address: DeviceAddress,
        endpoint: String,
        body: ByteArray?,
        signer: ServerRequestSigner,
    ): HttpResponse {
        val path = ServerApiPaths.device(address, endpoint)
        val authentication = signer.sign(ServerRequest(address, method.value, path, body ?: ByteArray(0)))
        return client.request(baseUrl + path) {
            this.method = method
            header(AuthHeaders.VERSION, AuthHeaders.CURRENT_VERSION)
            header(AuthHeaders.TIMESTAMP, authentication.timestamp.toEpochMilliseconds().toString())
            header(AuthHeaders.NONCE, Base64.encode(authentication.nonce.bytes))
            header(AuthHeaders.SIGNATURE, Base64.encode(authentication.signature))
            if (body != null) setBody(ByteArrayContent(body, ContentType.Application.Json))
        }
    }

    /** 401 becomes [SecureMessageTransportException.AuthenticationFailed]; anything else is unexpected. */
    private suspend fun HttpResponse.unexpected(): SecureMessageTransportException {
        if (status != HttpStatusCode.Unauthorized) return SecureMessageTransportException.UnexpectedResponse(status.value)
        val failure = when (runCatching { body<ErrorResponse>().error }.getOrNull()) {
            "missing_authentication" -> AuthenticationFailure.MISSING
            "expired_authentication" -> AuthenticationFailure.EXPIRED
            "authentication_replay" -> AuthenticationFailure.REPLAY
            "device_not_registered" -> AuthenticationFailure.NOT_REGISTERED
            else -> AuthenticationFailure.INVALID
        }
        return SecureMessageTransportException.AuthenticationFailed(failure)
    }

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
