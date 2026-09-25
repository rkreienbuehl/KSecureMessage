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

    /**
     * Creates the device authentication key pair (docs/server-authentication.md).
     * Separate from the messaging identity: it only authenticates the device
     * to the server, see [ServerRequestAuthentication].
     */
    suspend fun createDeviceAuthenticationKey(): DeviceAuthenticationKeyPair

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
     * too; the initiator may send several before it sees a reply. It must
     * belong to the initiation that created [session] (see [sessionInfo]).
     */
    suspend fun decrypt(
        session: SecureSession,
        message: CiphertextMessage,
    ): DecryptionResult

    /**
     * Describes [session] without changing it. Throws
     * [ProtocolException.InvalidSessionState] for an unreadable state.
     */
    fun sessionInfo(session: SecureSession): SessionInfo
}

/**
 * Lifecycle facts about a stored session, see docs/session-lifecycle.md.
 *
 * @property initiationId the initiation that created the session, or `null`
 *   for a session that was established before milestone 6 recorded it.
 * @property awaitingReply `true` while this device is the initiator and has
 *   not decrypted a message from the remote side yet (it still sends
 *   [PreKeyMessage]s).
 * @property acceptedSignedPreKeyId the local signed prekey this device
 *   accepted the session with as responder (docs/signed-prekey-lifecycle.md),
 *   or `null` for sessions this device initiated and for sessions stored
 *   before milestone 7.
 */
class SessionInfo(
    val initiationId: SessionInitiationId?,
    val awaitingReply: Boolean,
    val acceptedSignedPreKeyId: SignedPreKeyId? = null,
)

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
