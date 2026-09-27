package dev.kreienbuehl.ksecuremessage.client.ktor

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.AuthenticationFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.LastDeviceRecoveryFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.Reason
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryKeyFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryKeyResetFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryKeyTransitionFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RotationFailure
import dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceAuthenticationRegistrationStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQuery
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
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
import kotlin.time.Instant

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
            "device_auth_epoch_exhausted" -> RecoveryFailure.EPOCH_EXHAUSTED
            else -> throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
        }
        throw SecureMessageTransportException.DeviceRecoveryRejected(failure)
    }

    override suspend fun registrationStatus(address: DeviceAddress, signer: ServerRequestSigner): DeviceAuthenticationRegistrationStatus {
        val response = authenticated(HttpMethod.Get, address, ServerApiPaths.REGISTRATION, body = null, signer)
        if (response.status != HttpStatusCode.OK) throw response.unexpected()
        val body = try {
            response.body<DeviceRegistrationStateResponse>()
        } catch (e: IllegalArgumentException) {
            throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
        }
        if (body.authEpoch < 1) throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
        return DeviceAuthenticationRegistrationStatus(body.authEpoch, Instant.fromEpochMilliseconds(body.authKeyInstalledAt))
    }

    override suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization) {
        val address = authorization.statement.address
        val body = Json.encodeToString(authorization.toRequest()).encodeToByteArray()
        val response = client.request(baseUrl + ServerApiPaths.device(address, ServerApiPaths.REGISTRATION_ROTATION)) {
            method = HttpMethod.Put
            setBody(ByteArrayContent(body, ContentType.Application.Json))
        }
        if (response.status.isSuccess()) return
        val failure = when (runCatching { response.body<ErrorResponse>().error }.getOrNull()) {
            "invalid_device_auth_rotation" -> RotationFailure.INVALID_REQUEST
            "device_auth_rotation_not_registered" -> RotationFailure.NOT_REGISTERED
            "expired_authentication" -> RotationFailure.EXPIRED
            "invalid_device_auth_rotation_proof" -> RotationFailure.INVALID_PROOF
            "authentication_replay" -> RotationFailure.REPLAY
            "device_auth_rotation_conflict" -> RotationFailure.CONFLICT
            "device_auth_epoch_exhausted" -> RotationFailure.EPOCH_EXHAUSTED
            else -> throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
        }
        throw SecureMessageTransportException.DeviceAuthenticationRotationRejected(failure)
    }

    override suspend fun registerLastDeviceRecoveryKey(
        address: DeviceAddress,
        registration: LastDeviceRecoveryKeyRegistration,
        signer: ServerRequestSigner,
    ) {
        val body = Json.encodeToString(registration.toRequest()).encodeToByteArray()
        val response = authenticated(HttpMethod.Put, address, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY, body, signer)
        when {
            response.status.isSuccess() -> Unit
            response.status == HttpStatusCode.Conflict -> throw SecureMessageTransportException.LastDeviceRecoveryKeyRejected(
                if (runCatching { response.body<ErrorResponse>().error }.getOrNull() == "recovery_key_epoch_exhausted") {
                    RecoveryKeyFailure.EPOCH_EXHAUSTED
                } else {
                    RecoveryKeyFailure.CONFLICT
                },
            )
            response.status == HttpStatusCode.BadRequest ->
                throw SecureMessageTransportException.LastDeviceRecoveryKeyRejected(RecoveryKeyFailure.INVALID)
            else -> throw response.unexpected()
        }
    }

    override suspend fun lastDeviceRecoveryKeyStatus(address: DeviceAddress, signer: ServerRequestSigner): LastDeviceRecoveryKeyStatus {
        val response = authenticated(HttpMethod.Get, address, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY, body = null, signer)
        if (response.status != HttpStatusCode.OK) throw response.unexpected()
        return try {
            response.body<LastDeviceRecoveryKeyStatusResponse>().toStatus()
        } catch (e: IllegalArgumentException) {
            throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
        }
    }

    override suspend fun rotateLastDeviceRecoveryKey(authorization: RecoveryKeyRotationAuthorization, signer: ServerRequestSigner) {
        val body = Json.encodeToString(authorization.toRequest()).encodeToByteArray()
        val response = authenticated(
            HttpMethod.Put, authorization.statement.authorizer, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_ROTATION, body, signer,
        )
        if (response.status.isSuccess()) return
        val failure = response.recoveryKeyTransitionFailure("rotation") ?: throw response.unexpected()
        throw SecureMessageTransportException.RecoveryKeyRotationRejected(failure)
    }

    override suspend fun revokeLastDeviceRecoveryKey(authorization: RecoveryKeyRevocationAuthorization, signer: ServerRequestSigner) {
        val body = Json.encodeToString(authorization.toRequest()).encodeToByteArray()
        val response = authenticated(
            HttpMethod.Put, authorization.statement.authorizer, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_REVOCATION, body, signer,
        )
        if (response.status.isSuccess()) return
        val failure = response.recoveryKeyTransitionFailure("revocation") ?: throw response.unexpected()
        throw SecureMessageTransportException.RecoveryKeyRevocationRejected(failure)
    }

    /** The recovery key [kind] (`rotation`, `revocation`) failure, or `null` for anything else (ServerAuth failures included). */
    private suspend fun HttpResponse.recoveryKeyTransitionFailure(kind: String): RecoveryKeyTransitionFailure? =
        when (runCatching { body<ErrorResponse>().error }.getOrNull()) {
            "invalid_recovery_key_$kind" -> RecoveryKeyTransitionFailure.INVALID_REQUEST
            "recovery_key_not_configured" -> RecoveryKeyTransitionFailure.NOT_CONFIGURED
            "recovery_key_${kind}_expired" -> RecoveryKeyTransitionFailure.EXPIRED
            "recovery_key_${kind}_invalid_proof" -> RecoveryKeyTransitionFailure.INVALID_PROOF
            "recovery_key_${kind}_replay" -> RecoveryKeyTransitionFailure.REPLAY
            "recovery_key_${kind}_conflict" -> RecoveryKeyTransitionFailure.CONFLICT
            "recovery_key_epoch_exhausted" -> RecoveryKeyTransitionFailure.EPOCH_EXHAUSTED
            else -> null
        }

    override suspend fun requestLastDeviceRecoveryKeyReset(address: DeviceAddress, signer: ServerRequestSigner): RecoveryKeyResetStatus.Pending {
        val response = authenticated(HttpMethod.Put, address, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET, body = null, signer)
        if (response.status != HttpStatusCode.Created && response.status != HttpStatusCode.OK) {
            throw response.recoveryKeyResetRejected() ?: response.unexpected()
        }
        return response.resetStatus(address.userId) as? RecoveryKeyResetStatus.Pending
            ?: throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
    }

    override suspend fun lastDeviceRecoveryKeyResetStatus(address: DeviceAddress, signer: ServerRequestSigner): RecoveryKeyResetStatus {
        val response = authenticated(HttpMethod.Get, address, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET, body = null, signer)
        if (response.status != HttpStatusCode.OK) throw response.unexpected()
        return response.resetStatus(address.userId)
    }

    override suspend fun completeLastDeviceRecoveryKeyReset(authorization: RecoveryKeyResetCompletionAuthorization, signer: ServerRequestSigner) {
        val body = Json.encodeToString(authorization.toRequest()).encodeToByteArray()
        val response = authenticated(
            HttpMethod.Put, authorization.statement.completer, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET_COMPLETION, body, signer,
        )
        if (response.status.isSuccess()) return
        throw response.recoveryKeyResetRejected() ?: response.unexpected()
    }

    override suspend fun cancelLastDeviceRecoveryKeyReset(address: DeviceAddress, resetId: RecoveryKeyResetId, signer: ServerRequestSigner) {
        val body = Json.encodeToString(RecoveryKeyResetCancellationRequestDto(Base64.encode(resetId.bytes))).encodeToByteArray()
        val response = authenticated(HttpMethod.Put, address, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET_CANCELLATION, body, signer)
        if (response.status.isSuccess()) return
        throw response.recoveryKeyResetRejected() ?: response.unexpected()
    }

    override suspend fun lastDeviceRecoveryKeyResetStatusByRecoveryKey(query: RecoveryKeyResetStatusQuery): RecoveryKeyResetStatus {
        val userId = query.statement.userId
        val body = Json.encodeToString(query.toRequest()).encodeToByteArray()
        val response = client.request(baseUrl + ServerApiPaths.user(userId, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET_STATUS)) {
            method = HttpMethod.Post
            setBody(ByteArrayContent(body, ContentType.Application.Json))
        }
        if (response.status != HttpStatusCode.OK) {
            throw response.recoveryKeyResetRejected() ?: SecureMessageTransportException.UnexpectedResponse(response.status.value)
        }
        return response.resetStatus(userId)
    }

    override suspend fun cancelLastDeviceRecoveryKeyResetByRecoveryKey(authorization: RecoveryKeyResetCancellationAuthorization) {
        val body = Json.encodeToString(authorization.toRequest()).encodeToByteArray()
        val response = client.request(
            baseUrl + ServerApiPaths.user(authorization.statement.userId, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET_CANCELLATION),
        ) {
            method = HttpMethod.Put
            setBody(ByteArrayContent(body, ContentType.Application.Json))
        }
        if (response.status.isSuccess()) return
        throw response.recoveryKeyResetRejected() ?: SecureMessageTransportException.UnexpectedResponse(response.status.value)
    }

    private suspend fun HttpResponse.resetStatus(userId: dev.kreienbuehl.ksecuremessage.model.UserId): RecoveryKeyResetStatus = try {
        body<RecoveryKeyResetStatusResponse>().toStatus(userId)
    } catch (e: IllegalArgumentException) {
        throw SecureMessageTransportException.UnexpectedResponse(status.value)
    }

    /** The reset failure, or `null` for anything else (ServerAuth failures included). */
    private suspend fun HttpResponse.recoveryKeyResetRejected(): SecureMessageTransportException? {
        val failure = when (runCatching { body<ErrorResponse>().error }.getOrNull()) {
            "recovery_key_reset_not_available" -> RecoveryKeyResetFailure.NOT_AVAILABLE
            "recovery_key_not_configured" -> RecoveryKeyResetFailure.NOT_CONFIGURED
            "recovery_key_reset_not_pending" -> RecoveryKeyResetFailure.NOT_PENDING
            "recovery_key_reset_not_yet_eligible" -> RecoveryKeyResetFailure.NOT_YET_ELIGIBLE
            "recovery_key_reset_conflict" -> RecoveryKeyResetFailure.CONFLICT
            "invalid_recovery_key_reset" -> RecoveryKeyResetFailure.INVALID_REQUEST
            "recovery_key_reset_invalid_proof" -> RecoveryKeyResetFailure.INVALID_PROOF
            "recovery_key_reset_expired" -> RecoveryKeyResetFailure.EXPIRED
            "recovery_key_epoch_exhausted" -> RecoveryKeyResetFailure.EPOCH_EXHAUSTED
            else -> return null
        }
        return SecureMessageTransportException.RecoveryKeyResetRejected(failure)
    }

    override suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge {
        val response = client.request(baseUrl + ServerApiPaths.device(target, ServerApiPaths.LAST_DEVICE_RECOVERY_CHALLENGE)) {
            method = HttpMethod.Post
        }
        if (response.status != HttpStatusCode.OK) throw response.lastDeviceRecoveryRejected()
        return try {
            response.body<LastDeviceRecoveryChallengeResponse>().toChallenge(target)
        } catch (e: IllegalArgumentException) {
            throw SecureMessageTransportException.UnexpectedResponse(response.status.value)
        }
    }

    override suspend fun recoverLastDevice(authorization: LastDeviceRecoveryAuthorization) {
        val target = authorization.statement.target
        val body = Json.encodeToString(authorization.toRequest()).encodeToByteArray()
        val response = client.request(baseUrl + ServerApiPaths.device(target, ServerApiPaths.LAST_DEVICE_RECOVERY)) {
            method = HttpMethod.Put
            setBody(ByteArrayContent(body, ContentType.Application.Json))
        }
        if (!response.status.isSuccess()) throw response.lastDeviceRecoveryRejected()
    }

    private suspend fun HttpResponse.lastDeviceRecoveryRejected(): SecureMessageTransportException {
        val failure = when (runCatching { body<ErrorResponse>().error }.getOrNull()) {
            "invalid_last_device_recovery" -> LastDeviceRecoveryFailure.INVALID_REQUEST
            "last_device_recovery_not_configured" -> LastDeviceRecoveryFailure.NOT_CONFIGURED
            "last_device_recovery_target_not_registered" -> LastDeviceRecoveryFailure.TARGET_NOT_REGISTERED
            "last_device_recovery_challenge_invalid" -> LastDeviceRecoveryFailure.CHALLENGE_INVALID
            "last_device_recovery_expired" -> LastDeviceRecoveryFailure.EXPIRED
            "last_device_recovery_proof_invalid" -> LastDeviceRecoveryFailure.INVALID_PROOF
            "last_device_recovery_conflict" -> LastDeviceRecoveryFailure.CONFLICT
            "device_auth_epoch_exhausted" -> LastDeviceRecoveryFailure.EPOCH_EXHAUSTED
            else -> return SecureMessageTransportException.UnexpectedResponse(status.value)
        }
        return SecureMessageTransportException.LastDeviceRecoveryRejected(failure)
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
