package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress

/**
 * Stable KSecureMessage representation of persisted ratchet state.
 *
 * The byte payload can be backed by Kodium's session export/import support,
 * without exposing Kodium types to storage or application code.
 */
data class SecureSession(
    val remote: DeviceAddress,
    val state: ByteArray,
)
