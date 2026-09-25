package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.PublicIdentityKey
import dev.kreienbuehl.ksecuremessage.protocol.SafetyNumber

/** Lifecycle and local-state failures of [SecureMessageClient]. Messages never contain key material. */
sealed class SecureMessageClientException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** The storage has no local identity yet. Call [SecureMessageClient.initialize] first. */
    class NotInitialized : SecureMessageClientException("Client is not initialized, call initialize() first")

    /** All prekey IDs up to `Int.MAX_VALUE` are used. IDs never wrap around. */
    class PreKeyIdsExhausted(kind: String) : SecureMessageClientException("No unused $kind IDs left")

    /**
     * The storage is damaged in a way the client does not repair: prekeys or
     * a device authentication key without a local identity (a new identity
     * would not match them), or an initialized storage whose device
     * authentication key is missing (a new key could not replace the one the
     * server has registered; docs/server-authentication.md).
     */
    class InconsistentStorage(message: String) : SecureMessageClientException(message)

    /**
     * [address] presented an identity key that differs from the one pinned on
     * first contact (see docs/identity-trust.md). Nothing was changed: the pin,
     * any existing session and the local one-time prekeys stay as they were.
     *
     * [change] names the pinned and the presented public identity key, so the
     * application can show the change, compare
     * [SecureMessageClient.safetyNumber] for it with the other device and, only
     * if the user decides so, pass it to
     * [SecureMessageClient.acceptRemoteIdentityChange]
     * (docs/identity-verification.md). The presented key is unauthenticated:
     * it is what the message or bundle claimed. The message text contains no
     * key material.
     */
    class IdentityChanged(val change: RemoteIdentityChange) :
        SecureMessageClientException("Remote identity changed for ${change.remote}") {
        val address: DeviceAddress get() = change.remote

        /** The key pinned for [address]. */
        val pinnedIdentityKey: PublicIdentityKey get() = change.previousIdentityKey

        /** The different key [address] presented. */
        val presentedIdentityKey: PublicIdentityKey get() = change.presentedIdentityKey
    }

    /**
     * No identity key is pinned for [address] yet: there was no successful
     * first contact. Safety numbers and verification need a pin; the client
     * never fetches a bundle to create one. Nothing was changed.
     */
    class RemoteIdentityNotKnown(val address: DeviceAddress) :
        SecureMessageClientException("No identity is pinned for $address")

    /**
     * The identity pinned for [address] is not the one the call expected: an
     * identity change was accepted in the meantime (or the call was based on
     * an outdated [RemoteIdentityChange] or [SafetyNumber]). Nothing was
     * changed. Show the current state to the user again.
     */
    class RemoteIdentityConflict(val address: DeviceAddress) :
        SecureMessageClientException("The identity pinned for $address is not the expected one")

    /** A scanned safety number payload could not be decoded. Nothing was changed. */
    class InvalidSafetyNumberPayload(cause: Throwable) :
        SecureMessageClientException("Invalid safety number payload", cause)

    /**
     * [address] sent a message of a session initiation that was replaced
     * earlier or lost a simultaneous-initiation collision (see
     * docs/session-lifecycle.md). It can never become the current session
     * again, so this also rejects replays. Nothing was changed.
     */
    class StaleSessionInitiation(val address: DeviceAddress) :
        SecureMessageClientException("Stale session initiation from $address")

    /**
     * [address] started a session at the same time as this device, and this
     * device's initiation won. The message was authenticated but not
     * delivered: its session is not used. The losing initiation was retired;
     * the current session and the local one-time prekeys are unchanged. Once
     * [address] processes this device's initiation, both use one session.
     */
    class SessionCollision(val address: DeviceAddress) :
        SecureMessageClientException("Session collision with $address, message not delivered")

    /**
     * [address] sent a new session initiation that names the local signed
     * prekey [signedPreKeyId], whose grace period is over (see
     * docs/signed-prekey-lifecycle.md). Its private key is deleted or about to
     * be, so no new session can be accepted with it. Nothing was changed.
     * Existing sessions are not affected.
     */
    class ExpiredSignedPreKey(val address: DeviceAddress, val signedPreKeyId: SignedPreKeyId) :
        SecureMessageClientException("Session initiation from $address uses expired signed prekey ${signedPreKeyId.value}")

    /**
     * The transport did not take the envelope of message [messageId]; [cause]
     * is the transport's exception. The message is stored as pending: send it
     * again with [SecureMessageClient.retryPendingMessages]. The session
     * advanced for the lost envelope and is not rolled back.
     */
    class MessageNotSent(val messageId: LogicalMessageId, cause: Throwable) :
        SecureMessageClientException("Message $messageId was stored as pending but not handed to the transport", cause)

    /**
     * A device recovery request or authorization is not acceptable for this
     * device (docs/device-recovery.md): wrong device or user, self
     * authorization, outside the validity window, invalid proof of
     * possession, or not for the pending key. Nothing was changed.
     */
    class InvalidDeviceRecovery(message: String) : SecureMessageClientException(message)

    /** There is no pending device recovery: call [SecureMessageClient.prepareDeviceAuthenticationRecovery]. */
    class NoPendingDeviceRecovery : SecureMessageClientException("No device recovery is pending")
}
