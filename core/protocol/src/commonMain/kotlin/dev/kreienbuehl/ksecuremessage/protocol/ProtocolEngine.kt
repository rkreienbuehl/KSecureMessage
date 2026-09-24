package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle

/**
 * High-level protocol boundary implemented with Kodium.
 *
 * Keep direct Kodium usage behind this boundary. The initial scaffold leaves
 * the implementation open because the exact persisted X3DH/ratchet wire format
 * should be decided together with your storage and envelope format.
 */
interface ProtocolEngine {
    suspend fun establishInitiatorSession(remoteBundle: PreKeyBundle): SecureSession

    suspend fun encrypt(
        session: SecureSession,
        plaintext: ByteArray,
    ): EncryptionResult

    suspend fun decrypt(
        session: SecureSession,
        ciphertext: ByteArray,
    ): DecryptionResult
}

data class EncryptionResult(
    val ciphertext: ByteArray,
    val updatedSession: SecureSession,
)

data class DecryptionResult(
    val plaintext: ByteArray,
    val updatedSession: SecureSession,
)
