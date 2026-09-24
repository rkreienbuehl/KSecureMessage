package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress

/** Lifecycle and local-state failures of [SecureMessageClient]. Messages never contain key material. */
sealed class SecureMessageClientException(message: String) : Exception(message) {
    /** The storage has no local identity yet. Call [SecureMessageClient.initialize] first. */
    class NotInitialized : SecureMessageClientException("Client is not initialized, call initialize() first")

    /** All prekey IDs up to `Int.MAX_VALUE` are used. IDs never wrap around. */
    class PreKeyIdsExhausted(kind: String) : SecureMessageClientException("No unused $kind IDs left")

    /**
     * The storage has prekeys but no local identity. A new identity would not
     * match them, so the client refuses to create one.
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
}
