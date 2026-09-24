package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle

/**
 * Intended Kodium-backed implementation.
 *
 * Kodium is already on this module's classpath. Implement this adapter after
 * fixing the application's concrete X3DH bundle and session-init wire format.
 */
class KodiumProtocolEngine : ProtocolEngine {
    override suspend fun establishInitiatorSession(remoteBundle: PreKeyBundle): SecureSession =
        TODO("Map KSecureMessage PreKeyBundle to Kodium X3DH and initialize a DoubleRatchetSession")

    override suspend fun encrypt(
        session: SecureSession,
        plaintext: ByteArray,
    ): EncryptionResult =
        TODO("Import Kodium ratchet state, encrypt, export updated state")

    override suspend fun decrypt(
        session: SecureSession,
        ciphertext: ByteArray,
    ): DecryptionResult =
        TODO("Import Kodium ratchet state, decrypt, export updated state")
}
