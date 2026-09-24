package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.CiphertextMessage
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId

/**
 * High-level protocol boundary implemented with Kodium.
 *
 * Keep direct Kodium usage behind this boundary. Engines are stateless: every
 * state change is returned as a new [SecureSession] that the caller must
 * persist (see `ClientStorage.transaction`). Failures throw [ProtocolException].
 */
interface ProtocolEngine {
    suspend fun createIdentity(): LocalIdentity

    suspend fun createSignedPreKey(identity: LocalIdentity, id: SignedPreKeyId): SignedPreKeyPair

    /** Creates [count] one-time prekeys with consecutive IDs starting at [firstId]. */
    suspend fun createOneTimePreKeys(firstId: OneTimePreKeyId, count: Int): List<OneTimePreKeyPair>

    /**
     * Verifies [remoteBundle] and starts a session as initiator. The session
     * stays pending: [encrypt] returns [PreKeyMessage]s until the first
     * message from the remote side is decrypted.
     */
    suspend fun initiateSession(localIdentity: LocalIdentity, remoteBundle: PreKeyBundle): SecureSession

    /**
     * Creates the responder side of a session from the first [message] and
     * decrypts it. The caller looks up [signedPreKey] and [oneTimePreKey] by
     * the IDs in [message]. It must delete
     * [SessionAcceptanceResult.consumedOneTimePreKeyId] once the result is
     * persisted.
     */
    suspend fun acceptSession(
        localIdentity: LocalIdentity,
        remote: DeviceAddress,
        signedPreKey: SignedPreKeyPair,
        oneTimePreKey: OneTimePreKeyPair?,
        message: PreKeyMessage,
    ): SessionAcceptanceResult

    suspend fun encrypt(
        session: SecureSession,
        plaintext: ByteArray,
    ): EncryptionResult

    /**
     * Decrypts [message] on an existing session. A [PreKeyMessage] is accepted
     * too; the initiator may send several before it sees a reply.
     */
    suspend fun decrypt(
        session: SecureSession,
        message: CiphertextMessage,
    ): DecryptionResult
}

data class EncryptionResult(
    val message: CiphertextMessage,
    val updatedSession: SecureSession,
)

data class DecryptionResult(
    val plaintext: ByteArray,
    val updatedSession: SecureSession,
)

data class SessionAcceptanceResult(
    val session: SecureSession,
    val plaintext: ByteArray,
    val consumedOneTimePreKeyId: OneTimePreKeyId?,
)
