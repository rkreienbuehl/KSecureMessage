package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import kotlinx.coroutines.CancellationException

/**
 * The host application's decision whether the caller of a registration may
 * add a device to a user (docs/server-authentication.md, "Registration
 * authorization"). KSecureMessage has no account system: it cannot know who
 * owns a [dev.kreienbuehl.ksecuremessage.model.UserId]. Every first
 * registration of a device address, including the first device of a user,
 * needs this authorizer's [DeviceRegistrationAuthorizationResult.Authorized]
 * in addition to the proof that the registrant holds the device
 * authentication key.
 *
 * [C] is the host's own request authentication context: the authenticated
 * account principal, a session, an OAuth subject, an enrollment grant,
 * whatever the host established for the request before KSecureMessage saw
 * it (S1.1, finding N1). The HTTP adapter obtains it from a host-supplied
 * extractor; a request without one is denied before the authorizer is
 * called. KSecureMessage never interprets, logs, serializes, stores or
 * returns the context and never puts it into a signed or hashed input: it
 * only passes it to [authorize] within the one request.
 *
 * The decision must rest only on [C], the request and state the host owns
 * (its account and device records). KSecureMessage deliberately passes no
 * view of its own registrations: "the user has no devices yet" is not
 * ownership, and a read outside the registration's atomic write would be
 * stale anyway (S1.1, finding N2).
 *
 * Registered devices of a user are authorities for that user: they can
 * authorize a device recovery (docs/device-recovery.md), register, rotate
 * and revoke the user's offline recovery key and manage its reset. Those
 * flows trust exactly the membership this authorizer approved.
 *
 * The authorizer is called only when the address has no registration yet;
 * a retry with the registered key and a request with another key (a
 * conflict) never reach it. It is called before anything is stored and
 * outside every storage transaction. Anything it throws rejects the
 * registration as a server failure
 * ([DeviceRegistrationAuthorizationFailedException]), exceptions and errors
 * such as [AssertionError] or [NotImplementedError] alike; its message is
 * never sent to the client. Only coroutine cancellation and
 * [VirtualMachineError]s (process conditions such as
 * [OutOfMemoryError]) pass through unchanged (S1.2, finding N4).
 */
fun interface DeviceRegistrationAuthorizer<in C : Any> {
    suspend fun authorize(context: C, request: DeviceRegistrationAuthorizationRequest): DeviceRegistrationAuthorizationResult
}

/**
 * A registration that passed authentication and awaits the host's decision.
 * [address] is the device address being claimed and
 * [proposedAuthenticationPublicKey] the Ed25519 device authentication public
 * key (32 bytes, a copy) whose possession the request proved. Carries no
 * secrets and no server storage objects.
 */
class DeviceRegistrationAuthorizationRequest(
    val address: DeviceAddress,
    proposedAuthenticationPublicKey: ByteArray,
) {
    private val key = proposedAuthenticationPublicKey.copyOf()

    /** A copy of the proposed device authentication public key. */
    val proposedAuthenticationPublicKey: ByteArray get() = key.copyOf()
}

/** The host's decision on a [DeviceRegistrationAuthorizationRequest]. */
sealed class DeviceRegistrationAuthorizationResult {
    /** The caller may add this device to its user. */
    data object Authorized : DeviceRegistrationAuthorizationResult()

    /**
     * The device may not register. Nothing is stored; HTTP answers
     * `403 registration_not_authorized` without any host-specific reason.
     */
    data object Denied : DeviceRegistrationAuthorizationResult()
}

/**
 * The host's [DeviceRegistrationAuthorizer] threw instead of deciding.
 * Nothing was registered. The message is fixed; the host's exception is the
 * [cause], for the host's own diagnostics only: the HTTP adapter answers
 * `500 internal_error` and logs neither its message nor the context.
 */
class DeviceRegistrationAuthorizationFailedException(cause: Throwable) :
    Exception("Device registration authorizer failed", cause)

/**
 * Runs host code ([DeviceRegistrationAuthorizer]) at the registration
 * boundary (S1.2, finding N4): rethrows [CancellationException] (coroutine
 * cancellation must propagate) and [VirtualMachineError] (process conditions
 * whose message comes from the JVM, not the host), and wraps every other
 * [Throwable], [Error]s included, in
 * [DeviceRegistrationAuthorizationFailedException], whose message is fixed.
 */
internal inline fun <T> runHostRegistrationBoundary(block: () -> T): T =
    try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (e: VirtualMachineError) {
        throw e
    } catch (e: Throwable) {
        throw DeviceRegistrationAuthorizationFailedException(e)
    }
