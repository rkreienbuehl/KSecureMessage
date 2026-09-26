package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Device-scoped operations that require the registered device's
 * authentication. Each one fixes the HTTP method and the canonical path the
 * signature must cover (docs/server-authentication.md).
 */
enum class ProtectedEndpoint(val method: String, val endpoint: String) {
    /** `PUT /v1/devices/{user}/{device}/prekeys` */
    PUBLISH_PRE_KEYS("PUT", ServerApiPaths.PRE_KEYS),

    /** `GET /v1/devices/{user}/{device}/messages` */
    DRAIN_MAILBOX("GET", ServerApiPaths.MESSAGES),

    /** `GET /v1/devices/{user}/{device}/registration`: the device's own registration state. */
    READ_REGISTRATION("GET", ServerApiPaths.REGISTRATION),

    /** `PUT /v1/devices/{user}/{device}/last-device-recovery/key`: registers the user's last-device recovery key. */
    REGISTER_LAST_DEVICE_RECOVERY_KEY("PUT", ServerApiPaths.LAST_DEVICE_RECOVERY_KEY),

    /** `GET /v1/devices/{user}/{device}/last-device-recovery/key`: the user's recovery key state (docs/recovery-key-lifecycle.md). */
    READ_LAST_DEVICE_RECOVERY_KEY("GET", ServerApiPaths.LAST_DEVICE_RECOVERY_KEY),

    /** `PUT /v1/devices/{user}/{device}/last-device-recovery/key/rotation`: rotates the user's recovery key. */
    ROTATE_LAST_DEVICE_RECOVERY_KEY("PUT", ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_ROTATION),

    /** `PUT /v1/devices/{user}/{device}/last-device-recovery/key/revocation`: revokes the user's recovery key. */
    REVOKE_LAST_DEVICE_RECOVERY_KEY("PUT", ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_REVOCATION),
}

/**
 * Proof that a request for [endpoint] on behalf of [address] passed
 * authentication and claimed its nonce. Only [DeviceAuthenticator] creates
 * one, so a protected operation cannot run without it. [registrationState]
 * is the registration whose key verified the request: an operation that
 * must still hold when it commits (a recovery key rotation or revocation)
 * compares against it.
 */
class AuthenticatedDevice internal constructor(
    val address: DeviceAddress,
    val endpoint: ProtectedEndpoint,
    internal val registrationState: DeviceRegistrationState,
)

/** A request that failed authentication. Nothing was changed except, for none of these, a nonce. */
sealed class DeviceAuthenticationException(message: String) : Exception(message) {
    /** The request carries no authentication. */
    class MissingAuthentication : DeviceAuthenticationException("Request is not authenticated")

    /** No authentication key is registered for the device. */
    class DeviceNotRegistered : DeviceAuthenticationException("Device is not registered")

    /** The timestamp is outside the validity window. */
    class ExpiredAuthentication : DeviceAuthenticationException("Request timestamp is outside the validity window")

    /** The authentication is malformed or the signature does not verify with the registered key. */
    class InvalidAuthentication : DeviceAuthenticationException("Request signature is invalid")

    /** The nonce was already accepted for this device. */
    class AuthenticationReplay : DeviceAuthenticationException("Request nonce was already used")
}

/**
 * Verifies device-authenticated requests (docs/server-authentication.md).
 *
 * A request is accepted if, in this order: it carries authentication; the
 * device has a registered key (only registration itself names its key in
 * the body); its timestamp lies within [WINDOW] of [clock]'s time, bounds
 * included; the signature over the canonical request verifies with that key;
 * and its nonce was not accepted for the device before. The nonce is claimed
 * last, in one atomic step of [nonces], so of concurrent identical requests
 * at most one is accepted. A claimed nonce stays claimed even if the
 * operation fails afterwards; clients use a fresh nonce for every attempt.
 *
 * Nonces are kept per device until their timestamp leaves the window: such a
 * request is rejected by the window check anyway.
 */
class DeviceAuthenticator(
    private val devices: DeviceRegistrationRepository,
    private val nonces: AuthenticationNonceRepository,
    private val clock: Clock = Clock.System,
) {
    /**
     * Authenticates a request of the registered device [address] for
     * [endpoint] whose HTTP body was exactly [body]. Throws
     * [DeviceAuthenticationException].
     */
    suspend fun authenticate(
        address: DeviceAddress,
        endpoint: ProtectedEndpoint,
        body: ByteArray,
        authentication: RequestAuthentication?,
    ): AuthenticatedDevice {
        authentication ?: throw DeviceAuthenticationException.MissingAuthentication()
        // Always the registered key; never one the request supplies.
        val state = devices.registrationState(address) ?: throw DeviceAuthenticationException.DeviceNotRegistered()
        val request = ServerRequest(address, endpoint.method, ServerApiPaths.device(address, endpoint.endpoint), body)
        verify(state.registration.publicKey, request, authentication)
        return AuthenticatedDevice(address, endpoint, state)
    }

    /**
     * Authenticates a registration request, `PUT /v1/devices/{user}/{device}/registration`,
     * with the key it registers, [publicKey]. The only case where the
     * verification key comes from the request: it proves the registrant
     * holds the private key. Throws [DeviceAuthenticationException].
     */
    internal suspend fun authenticateRegistration(
        address: DeviceAddress,
        publicKey: ByteArray,
        body: ByteArray,
        authentication: RequestAuthentication?,
    ) {
        authentication ?: throw DeviceAuthenticationException.MissingAuthentication()
        val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), body)
        verify(publicKey, request, authentication)
    }

    private suspend fun verify(publicKey: ByteArray, request: ServerRequest, authentication: RequestAuthentication) {
        val now = Instant.fromEpochMilliseconds(clock.now().toEpochMilliseconds())
        val timestamp = authentication.timestamp
        if (timestamp < now - WINDOW || timestamp > now + WINDOW) throw DeviceAuthenticationException.ExpiredAuthentication()
        if (!ServerRequestAuthentication.verify(publicKey, request, authentication)) {
            throw DeviceAuthenticationException.InvalidAuthentication()
        }
        if (!nonces.claim(request.address, authentication.nonce.bytes, timestamp, pruneBefore = now - WINDOW)) {
            throw DeviceAuthenticationException.AuthenticationReplay()
        }
    }

    companion object {
        /** Accepted clock difference in each direction: `now - WINDOW <= timestamp <= now + WINDOW`. */
        val WINDOW = 5.minutes
    }
}
