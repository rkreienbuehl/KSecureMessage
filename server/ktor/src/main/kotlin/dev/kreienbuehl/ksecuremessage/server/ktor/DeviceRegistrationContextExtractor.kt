package dev.kreienbuehl.ksecuremessage.server.ktor

import io.ktor.server.application.ApplicationCall

/**
 * Gives the registration route the host application's authentication
 * context of a call (S1.1, finding N1), for example the account principal
 * the host's own authentication (a session, a bearer token, an enrollment
 * grant) established for it. KSecureMessage does not authenticate accounts
 * and does not interpret [C]; the server passes it unchanged to its
 * [dev.kreienbuehl.ksecuremessage.server.DeviceRegistrationAuthorizer].
 *
 * Return `null` when the call carries no valid host authentication: the
 * registration is then refused with `403 registration_not_authorized`
 * without asking the authorizer (a retry of an already registered key still
 * succeeds, it adds no membership). Anything thrown, exceptions and errors
 * such as [AssertionError] alike, gives `500 internal_error`; its message,
 * stack and cause are neither logged nor returned. Only coroutine
 * cancellation and [VirtualMachineError]s pass through unchanged (S1.2,
 * finding N4). Never return
 * a shared anonymous context for unauthenticated calls.
 */
fun interface DeviceRegistrationContextExtractor<out C : Any> {
    suspend fun extract(call: ApplicationCall): C?
}
