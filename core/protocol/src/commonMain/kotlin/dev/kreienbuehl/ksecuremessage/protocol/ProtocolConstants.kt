package dev.kreienbuehl.ksecuremessage.protocol

/**
 * KSecureMessage protocol compatibility constants.
 *
 * The info strings are the HKDF domain separation labels passed to Kodium's
 * X3DH and Double Ratchet. Every existing session and every message on the
 * wire depends on them: changing a value makes all existing sessions
 * undecryptable. Introduce a new protocol version instead.
 */
internal object ProtocolConstants {
    /** HKDF info for X3DH key agreement. */
    const val X3DH_INFO = "KSecureMessage-X3DH-v1"

    /** HKDF info for the Double Ratchet root and chain KDFs. */
    const val RATCHET_INFO = "KSecureMessage-Ratchet-v1"

    /** Size of an encoded public key: X25519 key followed by Ed25519 key. */
    const val PUBLIC_KEY_SIZE = 64
}
