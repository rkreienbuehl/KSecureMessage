package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress

/**
 * The host application's decision whether a device may become one of a
 * user's devices (docs/server-authentication.md, "Registration
 * authorization"). KSecureMessage has no account system: it cannot know who
 * owns a [dev.kreienbuehl.ksecuremessage.model.UserId]. Every first
 * registration of a device address, including the first device of a user,
 * needs this authorizer's [DeviceRegistrationAuthorizationResult.Authorized]
 * in addition to the proof that the registrant holds the device
 * authentication key.
 *
 * Registered devices of a user are authorities for that user: they can
 * authorize a device recovery (docs/device-recovery.md), register, rotate
 * and revoke the user's offline recovery key and manage its reset. Those
 * flows trust exactly the membership this authorizer approved.
 *
 * The authorizer is called only when the address has no registration yet;
 * a retry with the registered key and a request with another key (a
 * conflict) never reach it. It is called before anything is stored. A thrown
 * exception rejects the registration as a server failure; its message is
 * never sent to the client.
 */
fun interface DeviceRegistrationAuthorizer {
    suspend fun authorize(request: DeviceRegistrationAuthorizationRequest): DeviceRegistrationAuthorizationResult
}

/**
 * A registration that passed authentication and awaits the host's decision.
 * [address] is the device address being claimed, [proposedAuthenticationPublicKey]
 * the Ed25519 device authentication public key (32 bytes, a copy) whose
 * possession the request proved, and [userState] whether the user already
 * has registered devices. Carries no secrets and no server storage objects.
 */
class DeviceRegistrationAuthorizationRequest(
    val address: DeviceAddress,
    proposedAuthenticationPublicKey: ByteArray,
    val userState: DeviceRegistrationUserState,
) {
    private val key = proposedAuthenticationPublicKey.copyOf()

    /** A copy of the proposed device authentication public key. */
    val proposedAuthenticationPublicKey: ByteArray get() = key.copyOf()
}

/** Whether the user of a registration already has registered devices. */
enum class DeviceRegistrationUserState {
    /** No device of this user is registered: the registration would create the user's first device. */
    USER_HAS_NO_REGISTERED_DEVICES,

    /** At least one other device of this user is registered. */
    USER_HAS_REGISTERED_DEVICES,
}

/** The host's decision on a [DeviceRegistrationAuthorizationRequest]. */
sealed class DeviceRegistrationAuthorizationResult {
    /** The device may become a device of its user. */
    data object Authorized : DeviceRegistrationAuthorizationResult()

    /**
     * The device may not register. Nothing is stored; HTTP answers
     * `403 registration_not_authorized` without any host-specific reason.
     */
    data object Denied : DeviceRegistrationAuthorizationResult()
}
