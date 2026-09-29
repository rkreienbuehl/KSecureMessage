package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId

/**
 * X3DH data the initiator repeats in every outgoing [dev.kreienbuehl.ksecuremessage.model.PreKeyMessage]
 * until the responder has answered. Public values only.
 */
internal class PendingPreKey(
    val identityKey: ByteArray,
    val ephemeralKey: ByteArray,
    val signedPreKeyId: SignedPreKeyId,
    val oneTimePreKeyId: OneTimePreKeyId?,
)

/**
 * Content of [SecureSession.state]: local persistence framing, not a wire
 * format. [ratchet] is Kodium's own `DoubleRatchetSession.exportToArray()`
 * blob and is never interpreted here.
 *
 * [initiationVersion] is the session initiation format the session was
 * created with (S1). For [SessionInitiationVersion.V1] sessions
 * [associatedData] is `initiatorIdentityKey || responderIdentityKey`; for
 * [SessionInitiationVersion.V2] sessions it is the canonical initiation
 * transcript ([SessionInitiationId.v2Transcript]), which binds both
 * addresses and every header field. [initiatorIdentityKey] and
 * [responderIdentityKey] are the two identity keys of the session in their
 * roles; for v1 states before format 4 they are the two halves of
 * [associatedData].
 *
 * [initiation] is, for v2 sessions of either role, the initiation header the
 * session was created with, so a repeated v2 [dev.kreienbuehl.ksecuremessage.model.PreKeyMessage]
 * is matched field by field. `null` for v1 sessions.
 *
 * [origin] is the initiation that created the session (milestone 6). Version 1
 * states have no stored origin: it is derived from [pending] where that still
 * exists, and is `null` for sessions that were already established.
 *
 * [acceptedSignedPreKeyId] is the local signed prekey a responder session was
 * accepted with (milestone 7, see docs/signed-prekey-lifecycle.md). It is
 * `null` for initiator sessions and for states before version 3.
 *
 * ```
 * v4: version=0x04 | initiationVersion:u8 (0x01 | 0x02) | associatedData
 *     | initiatorIdentityKey | responderIdentityKey | pending
 *     | initiation flag:u8 [| header] | origin flag:u8 [| id[32]]
 *     | accepted flag:u8 [| signedPreKeyId:u32] | ratchet
 * v3: version=0x03 | associatedData | pending | origin flag:u8 [| id[32]]
 *     | accepted flag:u8 [| signedPreKeyId:u32] | ratchet
 * v2: version=0x02 | associatedData | pending | origin flag:u8 [| id[32]] | ratchet
 * v1: version=0x01 | associatedData | pending | ratchet
 * ```
 *
 * Versions 1–3 decode as [SessionInitiationVersion.V1] sessions; their
 * ratchet and associated data are used unchanged, so sessions established
 * before S1 keep working.
 */
internal class SessionState(
    val initiationVersion: SessionInitiationVersion,
    val associatedData: ByteArray,
    val initiatorIdentityKey: ByteArray,
    val responderIdentityKey: ByteArray,
    val pending: PendingPreKey?,
    val initiation: PendingPreKey?,
    val origin: SessionInitiationId?,
    val acceptedSignedPreKeyId: SignedPreKeyId?,
    val ratchet: ByteArray,
) {
    /** The same session with a new [ratchet] and [pending]. */
    fun advanced(pending: PendingPreKey?, ratchet: ByteArray) = SessionState(
        initiationVersion, associatedData, initiatorIdentityKey, responderIdentityKey, pending, initiation, origin, acceptedSignedPreKeyId, ratchet,
    )

    fun encode(): ByteArray {
        val out = BinaryWriter()
        out.byte(VERSION)
        out.byte(
            when (initiationVersion) {
                SessionInitiationVersion.V1 -> INITIATION_V1
                SessionInitiationVersion.V2 -> INITIATION_V2
            },
        )
        out.bytes(associatedData)
        out.bytes(initiatorIdentityKey)
        out.bytes(responderIdentityKey)
        out.header(pending)
        out.header(initiation)
        if (origin == null) {
            out.byte(0)
        } else {
            out.byte(1)
            out.fixed(origin.bytes)
        }
        if (acceptedSignedPreKeyId == null) {
            out.byte(0)
        } else {
            out.byte(1)
            out.int(acceptedSignedPreKeyId.value)
        }
        out.bytes(ratchet)
        return out.toByteArray()
    }

    private fun BinaryWriter.header(header: PendingPreKey?) {
        if (header == null) {
            byte(0)
            return
        }
        byte(1)
        bytes(header.identityKey)
        bytes(header.ephemeralKey)
        int(header.signedPreKeyId.value)
        if (header.oneTimePreKeyId == null) {
            byte(0)
        } else {
            byte(1)
            int(header.oneTimePreKeyId.value)
        }
    }

    companion object {
        private const val VERSION: Byte = 4
        private const val VERSION_3: Byte = 3
        private const val VERSION_2: Byte = 2
        private const val VERSION_1: Byte = 1

        private const val INITIATION_V1: Byte = 1
        private const val INITIATION_V2: Byte = 2

        fun decode(data: ByteArray): SessionState = try {
            val input = BinaryReader(data)
            val version = input.byte()
            if (version == VERSION) decodeV4(input) else decodeLegacy(input, version)
        } catch (e: IllegalArgumentException) {
            throw ProtocolException.InvalidSessionState("Malformed session state", e)
        } catch (e: ProtocolException.InvalidMessage) {
            throw ProtocolException.InvalidSessionState("Malformed session state", e)
        }

        private fun decodeV4(input: BinaryReader): SessionState {
            val initiationVersion = when (input.byte()) {
                INITIATION_V1 -> SessionInitiationVersion.V1
                INITIATION_V2 -> SessionInitiationVersion.V2
                else -> throw IllegalArgumentException("Unknown session initiation version")
            }
            val associatedData = input.bytes()
            val initiatorIdentityKey = input.bytes()
            val responderIdentityKey = input.bytes()
            require(initiatorIdentityKey.size == ProtocolConstants.PUBLIC_KEY_SIZE) { "Malformed identity key" }
            require(responderIdentityKey.size == ProtocolConstants.PUBLIC_KEY_SIZE) { "Malformed identity key" }
            val pending = input.header()
            val initiation = input.header()
            require((initiationVersion == SessionInitiationVersion.V2) == (initiation != null)) { "Malformed initiation header" }
            val origin = input.origin()
            if (initiationVersion == SessionInitiationVersion.V2) require(origin != null) { "Version 2 session without origin" }
            val acceptedSignedPreKeyId = input.accepted()
            val ratchet = input.bytes()
            input.requireEnd()
            return SessionState(
                initiationVersion, associatedData, initiatorIdentityKey, responderIdentityKey,
                pending, initiation, origin, acceptedSignedPreKeyId, ratchet,
            )
        }

        private fun decodeLegacy(input: BinaryReader, version: Byte): SessionState {
            if (version != VERSION_3 && version != VERSION_2 && version != VERSION_1) throw IllegalArgumentException("Unsupported session state version")
            val associatedData = input.bytes()
            require(associatedData.size == 2 * ProtocolConstants.PUBLIC_KEY_SIZE) { "Malformed associated data" }
            val pending = input.header()
            val origin = if (version == VERSION_1) {
                pending?.let { originOf(associatedData, it) }
            } else {
                input.origin()
            }
            val acceptedSignedPreKeyId = if (version == VERSION_3) input.accepted() else null
            val ratchet = input.bytes()
            input.requireEnd()
            return SessionState(
                SessionInitiationVersion.V1,
                associatedData,
                initiatorIdentityKey = associatedData.copyOfRange(0, ProtocolConstants.PUBLIC_KEY_SIZE),
                responderIdentityKey = associatedData.copyOfRange(ProtocolConstants.PUBLIC_KEY_SIZE, associatedData.size),
                pending = pending,
                initiation = null,
                origin = origin,
                acceptedSignedPreKeyId = acceptedSignedPreKeyId,
                ratchet = ratchet,
            )
        }

        private fun BinaryReader.header(): PendingPreKey? = when (byte()) {
            0.toByte() -> null
            1.toByte() -> PendingPreKey(
                identityKey = bytes(),
                ephemeralKey = bytes(),
                signedPreKeyId = SignedPreKeyId(int()),
                oneTimePreKeyId = when (byte()) {
                    0.toByte() -> null
                    1.toByte() -> OneTimePreKeyId(int())
                    else -> throw IllegalArgumentException("Malformed session state")
                },
            )
            else -> throw IllegalArgumentException("Malformed session state")
        }

        private fun BinaryReader.origin(): SessionInitiationId? = when (byte()) {
            0.toByte() -> null
            1.toByte() -> SessionInitiationId(fixed(SessionInitiationId.SIZE))
            else -> throw IllegalArgumentException("Malformed session state")
        }

        private fun BinaryReader.accepted(): SignedPreKeyId? = when (byte()) {
            0.toByte() -> null
            1.toByte() -> SignedPreKeyId(int())
            else -> throw IllegalArgumentException("Malformed session state")
        }

        /** The v1 initiation of a pending initiator session, from the data it repeats in every message. */
        fun originOf(associatedData: ByteArray, pending: PendingPreKey): SessionInitiationId {
            require(associatedData.size == 2 * ProtocolConstants.PUBLIC_KEY_SIZE) { "Malformed associated data" }
            return SessionInitiationId.derive(
                initiatorIdentityKey = pending.identityKey,
                responderIdentityKey = associatedData.copyOfRange(ProtocolConstants.PUBLIC_KEY_SIZE, associatedData.size),
                ephemeralKey = pending.ephemeralKey,
                signedPreKeyId = pending.signedPreKeyId,
                oneTimePreKeyId = pending.oneTimePreKeyId,
            )
        }
    }
}
