package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId

// Private key material stays on the owning device. Persist it only in
// protected storage. These are plain classes, not data classes, so
// toString() never prints key bytes. Public keys are opaque byte arrays
// produced by the ProtocolEngine.

/** Long-term identity key pair of the local device. */
class LocalIdentity(
    val publicKey: ByteArray,
    val privateKey: ByteArray,
) {
    override fun toString(): String = "LocalIdentity(privateKey=<redacted>)"
}

/**
 * Signed prekey pair. [signature] is the identity key's signature over
 * [publicKey]. Keep the private key until the signed prekey is rotated out and
 * no more session-setup messages for it are expected.
 */
class SignedPreKeyPair(
    val id: SignedPreKeyId,
    val publicKey: ByteArray,
    val signature: ByteArray,
    val privateKey: ByteArray,
) {
    fun toPublic(): PublicSignedPreKey = PublicSignedPreKey(id, publicKey, signature)

    override fun toString(): String = "SignedPreKeyPair(id=$id, privateKey=<redacted>)"
}

/**
 * One-time prekey pair. Delete the private key after a session was accepted
 * with it (see [SessionAcceptanceResult.consumedOneTimePreKeyId]).
 */
class OneTimePreKeyPair(
    val id: OneTimePreKeyId,
    val publicKey: ByteArray,
    val privateKey: ByteArray,
) {
    fun toPublic(): PublicOneTimePreKey = PublicOneTimePreKey(id, publicKey)

    override fun toString(): String = "OneTimePreKeyPair(id=$id, privateKey=<redacted>)"
}
