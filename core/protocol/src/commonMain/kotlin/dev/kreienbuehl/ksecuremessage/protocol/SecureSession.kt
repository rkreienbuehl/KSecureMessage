package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress

/**
 * Persisted state of one end-to-end session with [remote].
 *
 * [state] is opaque and owned by the [ProtocolEngine]. It contains secret
 * ratchet keys, so store it only in protected storage. Every encrypt/decrypt
 * returns a new [SecureSession]. Replace the stored one with it. Reusing an
 * older state breaks forward secrecy and causes decryption failures.
 */
data class SecureSession(
    val remote: DeviceAddress,
    val state: ByteArray,
)
