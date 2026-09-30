package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive

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
 * never sent to the client (S1.2, finding N4). Only genuine cancellation
 * of the calling coroutine and the process-health failures
 * [OutOfMemoryError] and [StackOverflowError] pass through unchanged; a
 * [CancellationException] thrown while the coroutine is still active,
 * [InternalError], [UnknownError] and every other [Throwable] are sanitized
 * like any other failure (S1.3, finding N7).
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
 * boundary (S1.2 finding N4, S1.3 finding N7) and classifies what it throws
 * with [classifyHostFailure].
 */
internal suspend inline fun <T> runHostRegistrationBoundary(block: () -> T): T =
    try {
        block()
    } catch (e: Throwable) {
        throw classifyHostFailure(e)
    }

/**
 * The host boundary's throwable policy (S1.3, finding N7), mirrored by
 * `runHostExtractionBoundary` in `server:ktor` (a shared helper would have to
 * be public API); both must classify every throwable identically:
 *
 * - a [CancellationException] while the calling coroutine is no longer
 *   active is genuine cancellation and propagates unchanged (structured
 *   concurrency);
 * - [OutOfMemoryError] and [StackOverflowError] are process-health failures
 *   and propagate unchanged: they are never turned into an ordinary HTTP
 *   answer, and their message is not sanitized;
 * - everything else is sanitized: wrapped in
 *   [DeviceRegistrationAuthorizationFailedException], whose message is fixed.
 *   That includes a [CancellationException] thrown by host code while the
 *   coroutine is still active (its class is no proof of cancellation),
 *   [InternalError], [UnknownError] and other [VirtualMachineError]s host code
 *   can throw with its own message, [LinkageError] and every [Exception].
 */
internal suspend fun classifyHostFailure(e: Throwable): Throwable = when {
    e is CancellationException && !currentCoroutineContext().isActive -> e
    e is OutOfMemoryError || e is StackOverflowError -> e
    else -> DeviceRegistrationAuthorizationFailedException(e)
}
