package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication

/**
 * The host authentication context of the tests (S1.1, finding N1): the
 * account a host would have authenticated for the request. Test-only.
 */
data class TestRegistrationPrincipal(val userId: UserId)

/**
 * Test-only [DeviceRegistrationAuthorizer] (S1, S1.1): every test states its
 * policy explicitly, and the contexts and requests the server asked about
 * are recorded. Never a production default.
 */
class TestDeviceRegistrationAuthorizer private constructor(
    private val decide: suspend (TestRegistrationPrincipal, DeviceRegistrationAuthorizationRequest) -> DeviceRegistrationAuthorizationResult,
) : DeviceRegistrationAuthorizer<TestRegistrationPrincipal> {
    private val recorded = mutableListOf<Pair<TestRegistrationPrincipal, DeviceRegistrationAuthorizationRequest>>()

    /** The requests the server asked about, in order. */
    val requests: List<DeviceRegistrationAuthorizationRequest> get() = synchronized(recorded) { recorded.map { it.second } }

    /** The contexts the server passed, in order. */
    val contexts: List<TestRegistrationPrincipal> get() = synchronized(recorded) { recorded.map { it.first } }

    override suspend fun authorize(context: TestRegistrationPrincipal, request: DeviceRegistrationAuthorizationRequest): DeviceRegistrationAuthorizationResult {
        synchronized(recorded) { recorded += context to request }
        return decide(context, request)
    }

    companion object {
        private fun decision(allowed: Boolean) =
            if (allowed) DeviceRegistrationAuthorizationResult.Authorized else DeviceRegistrationAuthorizationResult.Denied

        /** Allows every registration: for tests whose subject is not registration authorization. */
        fun allowAll() = TestDeviceRegistrationAuthorizer { _, _ -> DeviceRegistrationAuthorizationResult.Authorized }

        fun denyAll() = TestDeviceRegistrationAuthorizer { _, _ -> DeviceRegistrationAuthorizationResult.Denied }

        /** The reference policy: the authenticated principal may add devices to its own user only. */
        fun principalOwnsUser() = TestDeviceRegistrationAuthorizer { principal, request -> decision(principal.userId == request.address.userId) }

        /** Like [principalOwnsUser], but [before] runs first, for tests that hold decisions open. */
        fun principalOwnsUser(before: suspend (TestRegistrationPrincipal, DeviceRegistrationAuthorizationRequest) -> Unit) =
            TestDeviceRegistrationAuthorizer { principal, request ->
                before(principal, request)
                decision(principal.userId == request.address.userId)
            }

        /** Throws [failure] for every request, like a failing host account service. */
        fun throwing(failure: Exception = IllegalStateException("host account service unavailable: secret detail")) =
            TestDeviceRegistrationAuthorizer { _, _ -> throw failure }

        /** Allows exactly [addresses] (a host-owned device list), whoever the principal is. */
        fun allowOnly(vararg addresses: DeviceAddress) = TestDeviceRegistrationAuthorizer { _, request -> decision(request.address in addresses) }
    }
}

/**
 * Registers as the legitimate owner of the registration's user: for tests
 * whose subject is not registration authorization.
 */
suspend fun SecureMessageServer<TestRegistrationPrincipal>.registerDeviceAsUserOwner(
    registration: DeviceRegistration,
    body: ByteArray,
    authentication: RequestAuthentication?,
): Boolean = registerDevice(TestRegistrationPrincipal(registration.address.userId), registration, body, authentication)
