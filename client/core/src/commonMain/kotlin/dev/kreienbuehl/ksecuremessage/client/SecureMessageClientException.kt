package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId

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
     * The keys themselves are not part of the exception.
     */
    class IdentityChanged(val address: DeviceAddress) :
        SecureMessageClientException("Remote identity changed for $address")

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
}
