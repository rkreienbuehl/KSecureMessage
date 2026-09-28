package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.InternalKSecureMessageApi
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication

/**
 * Shape of the public prekey material KSecureMessage publishes. Lets code
 * outside the protocol engine (the server, transports) check untrusted
 * publications without Kodium. This is a format check only: it does not
 * verify the signed prekey signature, which initiators do before X3DH.
 */
@InternalKSecureMessageApi
object PreKeyFormat {
    /** Size of an encoded public key: X25519 key followed by Ed25519 key. */
    const val PUBLIC_KEY_SIZE: Int = ProtocolConstants.PUBLIC_KEY_SIZE

    /** Size of the identity key's detached Ed25519 signature over a signed prekey. */
    const val SIGNATURE_SIZE: Int = 64

    /** Most one-time prekeys a single publication may carry. */
    const val MAX_ONE_TIME_PRE_KEYS_PER_PUBLICATION: Int = 1000

    /**
     * Throws [IllegalArgumentException] if [publication] has a key or
     * signature of the wrong size, repeats a one-time prekey ID or carries
     * too many one-time prekeys. Messages never contain key bytes.
     */
    fun validate(publication: PreKeyPublication) {
        require(publication.identityKey.size == PUBLIC_KEY_SIZE) { "Identity key has an invalid size" }
        require(publication.signedPreKey.publicKey.size == PUBLIC_KEY_SIZE) { "Signed prekey has an invalid size" }
        require(publication.signedPreKey.signature.size == SIGNATURE_SIZE) { "Signed prekey signature has an invalid size" }
        val oneTimePreKeys = publication.oneTimePreKeys
        require(oneTimePreKeys.size <= MAX_ONE_TIME_PRE_KEYS_PER_PUBLICATION) { "Too many one-time prekeys" }
        require(oneTimePreKeys.all { it.publicKey.size == PUBLIC_KEY_SIZE }) { "One-time prekey has an invalid size" }
        require(oneTimePreKeys.map { it.id }.toSet().size == oneTimePreKeys.size) { "Duplicate one-time prekey ID" }
    }
}
