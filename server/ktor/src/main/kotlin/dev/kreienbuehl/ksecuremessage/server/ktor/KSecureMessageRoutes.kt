package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.server.DeviceAuthenticationException
import dev.kreienbuehl.ksecuremessage.server.DeviceAuthenticationRotationException
import dev.kreienbuehl.ksecuremessage.server.DeviceRecoveryException
import dev.kreienbuehl.ksecuremessage.server.DeviceRegistrationAuthorizationFailedException
import dev.kreienbuehl.ksecuremessage.server.EnvelopeSenderMismatchException
import dev.kreienbuehl.ksecuremessage.server.LastDeviceRecoveryException
import dev.kreienbuehl.ksecuremessage.server.ProtectedEndpoint
import dev.kreienbuehl.ksecuremessage.server.RecoveryKeyLifecycleException
import dev.kreienbuehl.ksecuremessage.server.RecoveryKeyResetException
import dev.kreienbuehl.ksecuremessage.server.SecureMessageServer
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryKeyException
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
import kotlin.time.Instant

/**
 * KSecureMessage HTTP API v1, see docs/prekey-publication.md and
 * docs/server-authentication.md. The application must install
 * ContentNegotiation with JSON. Routes only map HTTP to
 * [SecureMessageServer]; authentication, validation, conflicts and atomicity
 * live behind it.
 *
 * Device recovery (docs/device-recovery.md), routine device authentication
 * key rotation (docs/device-authentication-rotation.md) and last-device
 * recovery (docs/last-device-recovery.md) carry their own two signatures in
 * the body and no authentication headers. Registering the last-device
 * recovery key is ServerAuth-signed; issuing a last-device recovery challenge
 * is public. The delayed recovery key reset (docs/recovery-key-reset.md) is
 * ServerAuth-signed on its device routes; its two user-scoped routes
 * (`/v1/users/{user}/…`, status query and cancellation) carry the current
 * recovery key's signature in the body instead, for a holder of the offline
 * key without a working device.
 *
 * Registration, prekey publication, message submission and mailbox drain
 * are authenticated by the device: the signature covers the exact body
 * bytes, so those routes read the raw body and authenticate it before
 * parsing anything that is acted on. A request that fails authentication
 * gets 401 and changes nothing. Registration additionally needs the host
 * application's authorization (403 `registration_not_authorized`), and a
 * submitted envelope's sender must be the authenticated device (403
 * `sender_mismatch`). Only prekey bundle fetch is public. Unexpected
 * failures of the server or its storage get 500 with `internal_error` and no
 * details. Request-supplied identifiers are logged only escaped
 * ([logSafe]).
 *
 * [registrationContext] is required: it gives the registration route the
 * host's authentication context of the call (for example the principal the
 * host's own authentication established), which [server] passes to its
 * [dev.kreienbuehl.ksecuremessage.server.DeviceRegistrationAuthorizer]
 * (S1.1, finding N1). The routes never read, log or return the context.
 */
fun <C : Any> Route.kSecureMessageRoutes(server: SecureMessageServer<C>, registrationContext: DeviceRegistrationContextExtractor<C>) {
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
            // Host code: its failures are reported without message or context.
            val context = try {
                registrationContext.extract(call)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return@put call.respondRegistrationAuthorizationFailure(e)
            }
            val created = server.registerDevice(context, registration, body, call.authentication())
            call.respond(if (created) HttpStatusCode.Created else HttpStatusCode.NoContent)
        } catch (e: DeviceRegistrationAuthorizationFailedException) {
            call.respondRegistrationAuthorizationFailure(e.cause)
        } catch (e: DeviceAuthenticationException) {
            call.respondAuthenticationError(e)
        } catch (e: DeviceRegistrationException) {
            when (e) {
                is DeviceRegistrationException.InvalidRegistration -> call.respondError(HttpStatusCode.BadRequest, INVALID_REGISTRATION)
                is DeviceRegistrationException.Conflict -> call.respondError(HttpStatusCode.Conflict, "device_registration_conflict")
                // Authentication passed; the host established no context or did not allow this membership.
                is DeviceRegistrationException.NotAuthorized -> call.respondError(HttpStatusCode.Forbidden, "registration_not_authorized")
            }
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    // Device recovery (docs/device-recovery.md): not ServerAuth-signed. The
    // body carries the authorizer's signature and the replacement key's proof
    // of possession over the binary recovery statement; the server verifies
    // both before anything is changed.
    put("/v1/devices/{user}/{device}/registration/recovery") {
        val target = call.deviceAddress()
        val authorization = try {
            Json.decodeFromString<DeviceRecoveryRequestDto>(call.receive<ByteArray>().decodeToString()).toAuthorization(target)
        } catch (e: IllegalArgumentException) {
            // Malformed JSON (SerializationException), non-canonical Base64, sizes, negative timestamp.
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_RECOVERY)
        }
        val authorizer = authorization.request.authorizer
        try {
            val outcome = server.recoverDevice(authorization)
            call.application.log.info("Device recovery of ${target.forLog()} authorized by ${authorizer.forLog()}: ${outcome.name.lowercase()}")
            call.respond(HttpStatusCode.NoContent)
        } catch (e: DeviceRecoveryException) {
            val (status, error) = when (e) {
                is DeviceRecoveryException.InvalidRecovery -> HttpStatusCode.BadRequest to INVALID_RECOVERY
                is DeviceRecoveryException.SelfAuthorization -> HttpStatusCode.Forbidden to "recovery_self_authorization"
                is DeviceRecoveryException.CrossUser -> HttpStatusCode.Forbidden to "recovery_cross_user"
                is DeviceRecoveryException.AuthorizerNotRegistered -> HttpStatusCode.Unauthorized to "recovery_authorizer_not_registered"
                is DeviceRecoveryException.TargetNotRegistered -> HttpStatusCode.NotFound to "recovery_target_not_registered"
                is DeviceRecoveryException.Expired -> HttpStatusCode.Unauthorized to "expired_authentication"
                is DeviceRecoveryException.InvalidProof -> HttpStatusCode.Unauthorized to "invalid_recovery_proof"
                is DeviceRecoveryException.Replay -> HttpStatusCode.Unauthorized to "authentication_replay"
                is DeviceRecoveryException.Conflict -> HttpStatusCode.Conflict to "recovery_conflict"
                is DeviceRecoveryException.EpochExhausted -> HttpStatusCode.Conflict to EPOCH_EXHAUSTED
            }
            // Addresses and the failure category only: never keys, signatures or the body.
            call.application.log.info("Device recovery of ${target.forLog()} authorized by ${authorizer.forLog()} rejected: $error")
            call.respondError(status, error)
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    // The device's own registration state: the epoch for building a rotation
    // statement and the key installation time for the application's rotation
    // policy (docs/device-authentication-rotation.md).
    get("/v1/devices/{user}/{device}/registration") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        val device = try {
            server.authenticate(address, ProtectedEndpoint.READ_REGISTRATION, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@get call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@get call.respondInternalError(e)
        }
        val status = try {
            server.registrationStatus(device)
        } catch (e: Exception) {
            return@get call.respondInternalError(e)
        }
        call.respond(DeviceRegistrationStateResponse(status.authEpoch, status.authKeyInstalledAt.toEpochMilliseconds()))
    }

    // Routine device authentication key rotation
    // (docs/device-authentication-rotation.md): not ServerAuth-signed. The
    // body carries the current key's authorization and the replacement key's
    // proof of possession over the binary rotation statement; the server
    // verifies both before anything is changed.
    put("/v1/devices/{user}/{device}/registration/rotation") {
        val address = call.deviceAddress()
        val authorization = try {
            Json.decodeFromString<DeviceAuthenticationRotationRequestDto>(call.receive<ByteArray>().decodeToString()).toAuthorization(address)
        } catch (e: IllegalArgumentException) {
            // Malformed JSON (SerializationException), non-canonical Base64, sizes, epoch, timestamp, same key.
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_ROTATION)
        }
        try {
            val outcome = server.rotateDeviceAuthenticationKey(address, authorization)
            call.application.log.info("Device authentication rotation of ${address.forLog()}: ${outcome.name.lowercase()}")
            call.respond(HttpStatusCode.NoContent)
        } catch (e: DeviceAuthenticationRotationException) {
            val (status, error) = when (e) {
                is DeviceAuthenticationRotationException.InvalidRotation -> HttpStatusCode.BadRequest to INVALID_ROTATION
                is DeviceAuthenticationRotationException.NotRegistered -> HttpStatusCode.NotFound to "device_auth_rotation_not_registered"
                is DeviceAuthenticationRotationException.Expired -> HttpStatusCode.Unauthorized to "expired_authentication"
                is DeviceAuthenticationRotationException.InvalidProof -> HttpStatusCode.Unauthorized to "invalid_device_auth_rotation_proof"
                is DeviceAuthenticationRotationException.Replay -> HttpStatusCode.Unauthorized to "authentication_replay"
                is DeviceAuthenticationRotationException.Conflict -> HttpStatusCode.Conflict to "device_auth_rotation_conflict"
                is DeviceAuthenticationRotationException.EpochExhausted -> HttpStatusCode.Conflict to EPOCH_EXHAUSTED
            }
            // Address and the failure category only: never keys, signatures or the body.
            call.application.log.info("Device authentication rotation of ${address.forLog()} rejected: $error")
            call.respondError(status, error)
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    // Last-device recovery key registration (docs/last-device-recovery.md):
    // ServerAuth-signed by a registered device of the user; the body is
    // authenticated before it is parsed.
    put("/v1/devices/{user}/{device}/last-device-recovery/key") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        val device = try {
            server.authenticate(address, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@put call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@put call.respondInternalError(e)
        }
        val registration = try {
            Json.decodeFromString<LastDeviceRecoveryKeyRequest>(body.decodeToString()).toRegistration(address)
        } catch (e: IllegalArgumentException) {
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_RECOVERY_KEY)
        }
        try {
            val created = server.registerLastDeviceRecoveryKey(device, registration)
            call.application.log.info("Last-device recovery key of ${address.userId.forLog()} registered by ${address.forLog()}: ${if (created) "created" else "unchanged"}")
            call.respond(if (created) HttpStatusCode.Created else HttpStatusCode.NoContent)
        } catch (e: LastDeviceRecoveryException.InvalidKeyRegistration) {
            call.respondError(HttpStatusCode.BadRequest, INVALID_RECOVERY_KEY)
        } catch (e: LastDeviceRecoveryKeyException.Conflict) {
            call.application.log.info("Last-device recovery key of ${address.userId.forLog()} rejected: conflict")
            call.respondError(HttpStatusCode.Conflict, "last_device_recovery_key_conflict")
        } catch (e: LastDeviceRecoveryKeyException.EpochExhausted) {
            call.application.log.info("Last-device recovery key of ${address.userId.forLog()} rejected: epoch exhausted")
            call.respondError(HttpStatusCode.Conflict, RECOVERY_KEY_EPOCH_EXHAUSTED)
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    // The user's recovery key state (docs/recovery-key-lifecycle.md), for a
    // registered device of the user: ServerAuth-signed.
    get("/v1/devices/{user}/{device}/last-device-recovery/key") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        val device = try {
            server.authenticate(address, ProtectedEndpoint.READ_LAST_DEVICE_RECOVERY_KEY, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@get call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@get call.respondInternalError(e)
        }
        val status = try {
            server.lastDeviceRecoveryKeyStatus(device)
        } catch (e: Exception) {
            return@get call.respondInternalError(e)
        }
        call.respond(status.toResponse())
    }

    // Recovery key rotation (docs/recovery-key-lifecycle.md): two
    // authorities. ServerAuth by the path's device (authenticated before the
    // body is parsed), and in the body the current recovery key's signature
    // and the new key's proof of possession over the binary statement, which
    // names that device.
    put("/v1/devices/{user}/{device}/last-device-recovery/key/rotation") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        val device = try {
            server.authenticate(address, ProtectedEndpoint.ROTATE_LAST_DEVICE_RECOVERY_KEY, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@put call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@put call.respondInternalError(e)
        }
        val authorization = try {
            Json.decodeFromString<RecoveryKeyRotationRequestDto>(body.decodeToString()).toAuthorization(address)
        } catch (e: IllegalArgumentException) {
            // Malformed JSON (SerializationException), non-canonical Base64, sizes, epoch, timestamp, same key.
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_RECOVERY_KEY_ROTATION)
        }
        try {
            val outcome = server.rotateLastDeviceRecoveryKey(device, authorization)
            call.application.log.info("Recovery key rotation of ${address.userId.forLog()} authorized by ${address.forLog()}: ${outcome.name.lowercase()}")
            call.respond(HttpStatusCode.NoContent)
        } catch (e: RecoveryKeyLifecycleException) {
            call.respondRecoveryKeyLifecycleError(address, "rotation", e)
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    // Recovery key revocation (docs/recovery-key-lifecycle.md): the same two
    // authorities as a rotation, without a new key.
    put("/v1/devices/{user}/{device}/last-device-recovery/key/revocation") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        val device = try {
            server.authenticate(address, ProtectedEndpoint.REVOKE_LAST_DEVICE_RECOVERY_KEY, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@put call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@put call.respondInternalError(e)
        }
        val authorization = try {
            Json.decodeFromString<RecoveryKeyRevocationRequestDto>(body.decodeToString()).toAuthorization(address)
        } catch (e: IllegalArgumentException) {
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_RECOVERY_KEY_REVOCATION)
        }
        try {
            val outcome = server.revokeLastDeviceRecoveryKey(device, authorization)
            call.application.log.info("Recovery key revocation of ${address.userId.forLog()} authorized by ${address.forLog()}: ${outcome.name.lowercase()}")
            call.respond(HttpStatusCode.NoContent)
        } catch (e: RecoveryKeyLifecycleException) {
            call.respondRecoveryKeyLifecycleError(address, "revocation", e)
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    // Delayed recovery key reset (docs/recovery-key-reset.md). Request: an
    // empty body, ServerAuth-signed. The server alone chooses the reset ID,
    // the request time and the eligibility time; an existing reset is
    // returned unchanged (200), a new one with 201.
    put("/v1/devices/{user}/{device}/last-device-recovery/key/reset") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        val device = try {
            server.authenticate(address, ProtectedEndpoint.REQUEST_LAST_DEVICE_RECOVERY_KEY_RESET, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@put call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@put call.respondInternalError(e)
        }
        try {
            val outcome = server.requestLastDeviceRecoveryKeyReset(device)
            call.application.log.info("Recovery key reset of ${address.userId.forLog()} requested by ${address.forLog()}: ${if (outcome.created) "created" else "existing"}")
            call.respond(if (outcome.created) HttpStatusCode.Created else HttpStatusCode.OK, (outcome.reset as RecoveryKeyResetStatus).toResponse())
        } catch (e: RecoveryKeyResetException) {
            call.respondRecoveryKeyResetError(address.userId, e)
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    // The user's pending reset, for every registered device of the user: ServerAuth-signed.
    get("/v1/devices/{user}/{device}/last-device-recovery/key/reset") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        val device = try {
            server.authenticate(address, ProtectedEndpoint.READ_LAST_DEVICE_RECOVERY_KEY_RESET, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@get call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@get call.respondInternalError(e)
        }
        val status = try {
            server.lastDeviceRecoveryKeyResetStatus(device)
        } catch (e: Exception) {
            return@get call.respondInternalError(e)
        }
        call.respond(status.toResponse())
    }

    // Completion: ServerAuth by the path's device, and in the body the new
    // key's proof of possession over the binary completion statement, which
    // names that device and the pending reset.
    put("/v1/devices/{user}/{device}/last-device-recovery/key/reset/completion") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        val device = try {
            server.authenticate(address, ProtectedEndpoint.COMPLETE_LAST_DEVICE_RECOVERY_KEY_RESET, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@put call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@put call.respondInternalError(e)
        }
        val authorization = try {
            Json.decodeFromString<RecoveryKeyResetCompletionRequestDto>(body.decodeToString()).toAuthorization(address)
        } catch (e: IllegalArgumentException) {
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_RECOVERY_KEY_RESET)
        }
        try {
            val outcome = server.completeLastDeviceRecoveryKeyReset(device, authorization)
            call.application.log.info("Recovery key reset of ${address.userId.forLog()} completed by ${address.forLog()}: ${outcome.name.lowercase()}")
            call.respond(HttpStatusCode.NoContent)
        } catch (e: RecoveryKeyResetException) {
            call.respondRecoveryKeyResetError(address.userId, e)
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    // Cancellation by a registered device of the user: ServerAuth-signed; the body names the reset.
    put("/v1/devices/{user}/{device}/last-device-recovery/key/reset/cancellation") {
        val address = call.deviceAddress()
        val body = call.receive<ByteArray>()
        val device = try {
            server.authenticate(address, ProtectedEndpoint.CANCEL_LAST_DEVICE_RECOVERY_KEY_RESET, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@put call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@put call.respondInternalError(e)
        }
        val resetId = try {
            Json.decodeFromString<RecoveryKeyResetCancellationRequestDto>(body.decodeToString()).toResetId()
        } catch (e: IllegalArgumentException) {
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_RECOVERY_KEY_RESET)
        }
        try {
            server.cancelLastDeviceRecoveryKeyReset(device, resetId)
            call.application.log.info("Recovery key reset of ${address.userId.forLog()} cancelled by ${address.forLog()}")
            call.respond(HttpStatusCode.NoContent)
        } catch (e: RecoveryKeyResetException) {
            call.respondRecoveryKeyResetError(address.userId, e)
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    // Status query by the current recovery key (no device, not ServerAuth-signed).
    post("/v1/users/{user}/last-device-recovery/key/reset/status") {
        val userId = UserId(requireNotNull(call.parameters["user"]))
        val query = try {
            Json.decodeFromString<RecoveryKeyResetStatusQueryDto>(call.receive<ByteArray>().decodeToString()).toQuery(userId)
        } catch (e: IllegalArgumentException) {
            return@post call.respondError(HttpStatusCode.BadRequest, INVALID_RECOVERY_KEY_RESET)
        }
        val status = try {
            server.lastDeviceRecoveryKeyResetStatusByRecoveryKey(query)
        } catch (e: RecoveryKeyResetException) {
            return@post call.respondRecoveryKeyResetError(userId, e)
        } catch (e: Exception) {
            return@post call.respondInternalError(e)
        }
        call.respond(status.toResponse())
    }

    // Cancellation by the current recovery key (no device, not ServerAuth-signed).
    put("/v1/users/{user}/last-device-recovery/key/reset/cancellation") {
        val userId = UserId(requireNotNull(call.parameters["user"]))
        val authorization = try {
            Json.decodeFromString<RecoveryKeyResetRecoveryKeyCancellationRequestDto>(call.receive<ByteArray>().decodeToString()).toAuthorization(userId)
        } catch (e: IllegalArgumentException) {
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_RECOVERY_KEY_RESET)
        }
        try {
            server.cancelLastDeviceRecoveryKeyResetByRecoveryKey(authorization)
            call.application.log.info("Recovery key reset of ${userId.forLog()} cancelled by the recovery key")
            call.respond(HttpStatusCode.NoContent)
        } catch (e: RecoveryKeyResetException) {
            call.respondRecoveryKeyResetError(userId, e)
        } catch (e: Exception) {
            call.respondInternalError(e)
        }
    }

    // A last-device recovery challenge for the target (public). Returns the
    // outstanding challenge while it is valid, so repeated requests never
    // invalidate each other.
    post("/v1/devices/{user}/{device}/last-device-recovery/challenge") {
        val target = call.deviceAddress()
        val challenge = try {
            server.lastDeviceRecoveryChallenge(target)
        } catch (e: LastDeviceRecoveryException) {
            return@post call.respondLastDeviceRecoveryError(target, e)
        } catch (e: Exception) {
            return@post call.respondInternalError(e)
        }
        call.respond(challenge.toResponse())
    }

    // Last-device recovery (docs/last-device-recovery.md): not ServerAuth-signed.
    // The body carries the offline recovery key's signature and the replacement
    // key's proof of possession over the binary recovery statement, which
    // binds the server-issued challenge; the server verifies both before
    // anything is changed.
    put("/v1/devices/{user}/{device}/last-device-recovery") {
        val target = call.deviceAddress()
        val authorization = try {
            Json.decodeFromString<LastDeviceRecoveryRequestDto>(call.receive<ByteArray>().decodeToString()).toAuthorization(target)
        } catch (e: IllegalArgumentException) {
            // Malformed JSON (SerializationException), non-canonical Base64, sizes, epoch, expiry, same key.
            return@put call.respondError(HttpStatusCode.BadRequest, INVALID_LAST_DEVICE_RECOVERY)
        }
        try {
            val outcome = server.recoverLastDevice(target, authorization)
            call.application.log.info("Last-device recovery of ${target.forLog()}: ${outcome.name.lowercase()}")
            call.respond(HttpStatusCode.NoContent)
        } catch (e: LastDeviceRecoveryException) {
            call.respondLastDeviceRecoveryError(target, e)
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

    // Signed by the sending device (S1, docs/server-authentication.md): the
    // device header names the signer, the request is authenticated with its
    // registered key before the body is parsed, and the envelope's sender
    // must be exactly that device.
    post("/v1/messages") {
        val body = call.receive<ByteArray>()
        val device = try {
            val address = call.submittingDevice() ?: throw DeviceAuthenticationException.MissingAuthentication()
            server.authenticate(address, ProtectedEndpoint.SEND_MESSAGE, body, call.authentication())
        } catch (e: DeviceAuthenticationException) {
            return@post call.respondAuthenticationError(e)
        } catch (e: Exception) {
            return@post call.respondInternalError(e)
        }
        val envelope = try {
            Json.decodeFromString<EncryptedEnvelope>(body.decodeToString())
        } catch (e: IllegalArgumentException) {
            return@post call.respondError(HttpStatusCode.BadRequest, "invalid_envelope")
        }
        try {
            // Returns once the envelope is stored, so 202 is never sent for an envelope that was not.
            server.relay(device, envelope)
        } catch (e: EnvelopeSenderMismatchException) {
            return@post call.respondError(HttpStatusCode.Forbidden, "sender_mismatch")
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
private const val INVALID_RECOVERY = "invalid_recovery"
private const val INVALID_ROTATION = "invalid_device_auth_rotation"
private const val EPOCH_EXHAUSTED = "device_auth_epoch_exhausted"
private const val INVALID_RECOVERY_KEY = "invalid_last_device_recovery_key"
private const val INVALID_LAST_DEVICE_RECOVERY = "invalid_last_device_recovery"
private const val INVALID_RECOVERY_KEY_ROTATION = "invalid_recovery_key_rotation"
private const val INVALID_RECOVERY_KEY_REVOCATION = "invalid_recovery_key_revocation"
private const val RECOVERY_KEY_EPOCH_EXHAUSTED = "recovery_key_epoch_exhausted"
private const val INVALID_RECOVERY_KEY_RESET = "invalid_recovery_key_reset"

/** The user and the failure category only are logged: never keys, signatures, reset IDs or the body. */
private suspend fun ApplicationCall.respondRecoveryKeyResetError(userId: UserId, e: RecoveryKeyResetException) {
    val (status, error) = when (e) {
        is RecoveryKeyResetException.NotAvailable -> HttpStatusCode.NotFound to "recovery_key_reset_not_available"
        is RecoveryKeyResetException.NotConfigured -> HttpStatusCode.NotFound to "recovery_key_not_configured"
        is RecoveryKeyResetException.NotPending -> HttpStatusCode.NotFound to "recovery_key_reset_not_pending"
        is RecoveryKeyResetException.NotYetEligible -> HttpStatusCode.Conflict to "recovery_key_reset_not_yet_eligible"
        is RecoveryKeyResetException.Conflict -> HttpStatusCode.Conflict to "recovery_key_reset_conflict"
        is RecoveryKeyResetException.InvalidRequest -> HttpStatusCode.BadRequest to INVALID_RECOVERY_KEY_RESET
        is RecoveryKeyResetException.InvalidProof -> HttpStatusCode.Unauthorized to "recovery_key_reset_invalid_proof"
        is RecoveryKeyResetException.Expired -> HttpStatusCode.Unauthorized to "recovery_key_reset_expired"
        is RecoveryKeyResetException.EpochExhausted -> HttpStatusCode.Conflict to RECOVERY_KEY_EPOCH_EXHAUSTED
    }
    application.log.info("Recovery key reset operation of ${userId.forLog()} rejected: $error")
    respondError(status, error)
}

/**
 * [kind] is `rotation` or `revocation`. The user, the authorizing device and
 * the failure category only are logged: never keys, signatures or the body.
 */
private suspend fun ApplicationCall.respondRecoveryKeyLifecycleError(authorizer: DeviceAddress, kind: String, e: RecoveryKeyLifecycleException) {
    val (status, error) = when (e) {
        is RecoveryKeyLifecycleException.InvalidRequest -> HttpStatusCode.BadRequest to "invalid_recovery_key_$kind"
        is RecoveryKeyLifecycleException.NotConfigured -> HttpStatusCode.NotFound to "recovery_key_not_configured"
        is RecoveryKeyLifecycleException.Expired -> HttpStatusCode.Unauthorized to "recovery_key_${kind}_expired"
        is RecoveryKeyLifecycleException.InvalidProof -> HttpStatusCode.Unauthorized to "recovery_key_${kind}_invalid_proof"
        is RecoveryKeyLifecycleException.Replay -> HttpStatusCode.Unauthorized to "recovery_key_${kind}_replay"
        is RecoveryKeyLifecycleException.Conflict -> HttpStatusCode.Conflict to "recovery_key_${kind}_conflict"
        is RecoveryKeyLifecycleException.EpochExhausted -> HttpStatusCode.Conflict to RECOVERY_KEY_EPOCH_EXHAUSTED
    }
    application.log.info("Recovery key $kind of ${authorizer.userId.forLog()} authorized by ${authorizer.forLog()} rejected: $error")
    respondError(status, error)
}

/** Target address and the failure category only are logged: never keys, signatures, challenges or the body. */
private suspend fun ApplicationCall.respondLastDeviceRecoveryError(target: DeviceAddress, e: LastDeviceRecoveryException) {
    val (status, error) = when (e) {
        is LastDeviceRecoveryException.InvalidRequest -> HttpStatusCode.BadRequest to INVALID_LAST_DEVICE_RECOVERY
        is LastDeviceRecoveryException.InvalidKeyRegistration -> HttpStatusCode.BadRequest to INVALID_RECOVERY_KEY
        is LastDeviceRecoveryException.NotConfigured -> HttpStatusCode.NotFound to "last_device_recovery_not_configured"
        is LastDeviceRecoveryException.TargetNotRegistered -> HttpStatusCode.NotFound to "last_device_recovery_target_not_registered"
        is LastDeviceRecoveryException.ChallengeInvalid -> HttpStatusCode.Unauthorized to "last_device_recovery_challenge_invalid"
        is LastDeviceRecoveryException.Expired -> HttpStatusCode.Unauthorized to "last_device_recovery_expired"
        is LastDeviceRecoveryException.InvalidProof -> HttpStatusCode.Unauthorized to "last_device_recovery_proof_invalid"
        is LastDeviceRecoveryException.Conflict -> HttpStatusCode.Conflict to "last_device_recovery_conflict"
        is LastDeviceRecoveryException.EpochExhausted -> HttpStatusCode.Conflict to EPOCH_EXHAUSTED
    }
    application.log.info("Last-device recovery of ${target.forLog()} rejected: $error")
    respondError(status, error)
}

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

/**
 * The host's context extractor or registration authorizer threw: a generic
 * 500. The log names only the exception class, never its message, stack or
 * cause, because host exceptions may carry the request's authentication
 * context (account names, tokens).
 */
private suspend fun ApplicationCall.respondRegistrationAuthorizationFailure(hostFailure: Throwable?) {
    if (hostFailure is CancellationException) throw hostFailure
    application.log.error("Registration authorization failed (${hostFailure?.let { it::class.qualifiedName }})")
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

/**
 * The device named by [AuthHeaders.DEVICE] on a message submission, or
 * `null` if the header is absent. Throws
 * [DeviceAuthenticationException.InvalidAuthentication] if it is repeated or
 * not a canonical encoding ([ServerApiPaths.decodeDevice]).
 */
private fun ApplicationCall.submittingDevice(): DeviceAddress? {
    val values = request.headers.getAll(AuthHeaders.DEVICE) ?: return null
    val value = values.singleOrNull() ?: throw DeviceAuthenticationException.InvalidAuthentication()
    return ServerApiPaths.decodeDevice(value) ?: throw DeviceAuthenticationException.InvalidAuthentication()
}

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

private fun decodeBase64(value: String): ByteArray = decodeCanonicalBase64(value)
