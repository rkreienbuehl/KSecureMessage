package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.server.DeviceRegistrationAuthorizationRequest
import dev.kreienbuehl.ksecuremessage.server.DeviceRegistrationAuthorizationResult
import dev.kreienbuehl.ksecuremessage.server.DeviceRegistrationAuthorizer

/**
 * The host authentication context of the tests (S1.1, finding N1): the
 * account a host would have authenticated for the call. Test-only.
 */
internal data class TestRegistrationPrincipal(val userId: UserId)

/** Test-only context extractors. Never production defaults. */
internal object TestRegistrationContexts {
    /** The header a test client sets to be authenticated as that user; absent means unauthenticated. */
    const val PRINCIPAL_HEADER = "X-Test-Principal"

    /**
     * Every call is authenticated as the owner of the user in its path: for
     * tests whose subject is not registration authorization.
     */
    val routeUserOwner = DeviceRegistrationContextExtractor { call ->
        call.parameters["user"]?.let { TestRegistrationPrincipal(UserId(it)) }
    }

    /** The principal named by [PRINCIPAL_HEADER], `null` without it, like a host's login check. */
    val header = DeviceRegistrationContextExtractor { call ->
        call.request.headers[PRINCIPAL_HEADER]?.let { TestRegistrationPrincipal(UserId(it)) }
    }
}

/**
 * Test-only [DeviceRegistrationAuthorizer] (S1, S1.1): every test states its
 * policy explicitly, and the contexts and requests the server asked about
 * are recorded. Never a production default.
 */
internal class TestDeviceRegistrationAuthorizer private constructor(
    private val decide: (TestRegistrationPrincipal, DeviceRegistrationAuthorizationRequest) -> DeviceRegistrationAuthorizationResult,
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

        /** Throws [failure] for every request, like a failing host account service. */
        fun throwing(failure: Exception = IllegalStateException("host account service unavailable: secret detail")) =
            TestDeviceRegistrationAuthorizer { _, _ -> throw failure }

        /** Allows exactly [addresses] (a host-owned device list), whoever the principal is. */
        fun allowOnly(vararg addresses: DeviceAddress) = TestDeviceRegistrationAuthorizer { _, request -> decision(request.address in addresses) }
    }
}
