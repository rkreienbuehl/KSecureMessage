package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress

/**
 * Test-only [DeviceRegistrationAuthorizer] (S1): every test states its policy
 * explicitly, and the requests the server asked about are recorded. Never a
 * production default.
 */
class TestDeviceRegistrationAuthorizer private constructor(
    private val decide: (DeviceRegistrationAuthorizationRequest) -> DeviceRegistrationAuthorizationResult,
) : DeviceRegistrationAuthorizer {
    private val recorded = mutableListOf<DeviceRegistrationAuthorizationRequest>()

    /** The requests the server asked about, in order. */
    val requests: List<DeviceRegistrationAuthorizationRequest> get() = synchronized(recorded) { recorded.toList() }

    override suspend fun authorize(request: DeviceRegistrationAuthorizationRequest): DeviceRegistrationAuthorizationResult {
        synchronized(recorded) { recorded += request }
        return decide(request)
    }

    companion object {
        /** Allows every registration: for tests whose subject is not registration authorization. */
        fun allowAll() = TestDeviceRegistrationAuthorizer { DeviceRegistrationAuthorizationResult.Authorized }

        fun denyAll() = TestDeviceRegistrationAuthorizer { DeviceRegistrationAuthorizationResult.Denied }

        /** Throws [failure] for every request, like a failing host account service. */
        fun throwing(failure: Exception = IllegalStateException("host account service unavailable: secret detail")) =
            TestDeviceRegistrationAuthorizer { throw failure }

        /** Allows exactly [addresses]. */
        fun allowOnly(vararg addresses: DeviceAddress) = TestDeviceRegistrationAuthorizer { request ->
            if (request.address in addresses) DeviceRegistrationAuthorizationResult.Authorized else DeviceRegistrationAuthorizationResult.Denied
        }
    }
}
