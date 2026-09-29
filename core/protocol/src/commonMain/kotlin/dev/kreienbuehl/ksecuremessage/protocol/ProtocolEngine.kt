package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.CiphertextMessage
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
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

    /**
     * Creates an offline last-device recovery key (docs/last-device-recovery.md).
     * Separate from the messaging identity and from every device
     * authentication key; the application keeps it offline.
     */
    suspend fun createLastDeviceRecoveryKey(): LastDeviceRecoveryKey

    suspend fun createSignedPreKey(identity: LocalIdentity, id: SignedPreKeyId): SignedPreKeyPair

    /** Creates [count] one-time prekeys with consecutive IDs starting at [firstId]. */
    suspend fun createOneTimePreKeys(firstId: OneTimePreKeyId, count: Int): List<OneTimePreKeyPair>

    /**
     * Verifies [remoteBundle] and starts a session as initiator from
     * [localAddress] to the bundle's address, always with session initiation
     * version 2 (S1): the associated data binds both addresses and every
     * initiation header field (docs/session-lifecycle.md). The session stays
     * pending: [encrypt] returns [PreKeyMessage]s until the first message
     * from the remote side is decrypted.
     */
    suspend fun initiateSession(localIdentity: LocalIdentity, localAddress: DeviceAddress, remoteBundle: PreKeyBundle): SecureSession

    /**
     * Creates the responder side of a session from the first [message], sent
     * by [remote] to [localAddress], and decrypts it. Only a
     * [SessionInitiationVersion.V2] message is accepted: its transcript,
     * built from both addresses and every header field, is the associated
     * data, so a changed address or header field fails decryption and
     * nothing is created. A [SessionInitiationVersion.V1] message throws
     * [ProtocolException.InvalidMessage]. The caller looks up [signedPreKey]
     * and [oneTimePreKey] by the IDs in [message]. It must delete
     * [SessionAcceptanceResult.consumedOneTimePreKeyId] once the result is
     * persisted.
     */
    suspend fun acceptSession(
        localIdentity: LocalIdentity,
        localAddress: DeviceAddress,
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
     * Decrypts [message] on an existing session of the device whose public
     * identity key is [localIdentityKey]. A [PreKeyMessage] is accepted too;
     * the initiator may send several before it sees a reply. It must have
     * the session's initiation version, belong to the initiation that
     * created [session] (see [sessionInfo]), and the local device must be
     * the session's responder with the message's identity key as initiator;
     * otherwise [ProtocolException.InvalidMessage] is thrown.
     */
    suspend fun decrypt(
        session: SecureSession,
        message: CiphertextMessage,
        localIdentityKey: ByteArray,
    ): DecryptionResult

    /**
     * Describes [session] without changing it. Throws
     * [ProtocolException.InvalidSessionState] for an unreadable state.
     */
    fun sessionInfo(session: SecureSession): SessionInfo

    /**
     * The remote identity key [session] was established with, or `null` if
     * that cannot be told apart from the local one: exactly one of the
     * session's two identity keys must equal [localIdentityKey], and the
     * other one is returned. Never returns the local key. Used to pin a
     * session created before identity pinning (S1, finding F9).
     */
    fun sessionRemoteIdentityKey(session: SecureSession, localIdentityKey: ByteArray): ByteArray?
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
 * @property initiationVersion the session initiation format the session was
 *   created with: [SessionInitiationVersion.V1] for sessions created before
 *   S1, [SessionInitiationVersion.V2] for every newer one.
 */
class SessionInfo(
    val initiationId: SessionInitiationId?,
    val awaitingReply: Boolean,
    val acceptedSignedPreKeyId: SignedPreKeyId? = null,
    val initiationVersion: SessionInitiationVersion = SessionInitiationVersion.V2,
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
