package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
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
 * blob and is never interpreted here. [associatedData] is
 * `initiatorIdentityKey || responderIdentityKey` for both roles.
 *
 * [origin] is the initiation that created the session (milestone 6). Version 1
 * states have no stored origin: it is derived from [pending] where that still
 * exists, and is `null` for sessions that were already established.
 *
 * ```
 * v2: version=0x02 | associatedData | pending | origin flag:u8 [| id[32]] | ratchet
 * v1: version=0x01 | associatedData | pending | ratchet
 * ```
 */
internal class SessionState(
    val associatedData: ByteArray,
    val pending: PendingPreKey?,
    val origin: SessionInitiationId?,
    val ratchet: ByteArray,
) {
    fun encode(): ByteArray {
        val out = BinaryWriter()
        out.byte(VERSION)
        out.bytes(associatedData)
        if (pending == null) {
            out.byte(0)
        } else {
            out.byte(1)
            out.bytes(pending.identityKey)
            out.bytes(pending.ephemeralKey)
            out.int(pending.signedPreKeyId.value)
            if (pending.oneTimePreKeyId == null) {
                out.byte(0)
            } else {
                out.byte(1)
                out.int(pending.oneTimePreKeyId.value)
            }
        }
        if (origin == null) {
            out.byte(0)
        } else {
            out.byte(1)
            out.fixed(origin.bytes)
        }
        out.bytes(ratchet)
        return out.toByteArray()
    }

    companion object {
        private const val VERSION: Byte = 2
        private const val VERSION_1: Byte = 1

        fun decode(data: ByteArray): SessionState = try {
            val input = BinaryReader(data)
            val version = input.byte()
            if (version != VERSION && version != VERSION_1) throw IllegalArgumentException("Unsupported session state version")
            val associatedData = input.bytes()
            val pending = when (input.byte()) {
                0.toByte() -> null
                1.toByte() -> PendingPreKey(
                    identityKey = input.bytes(),
                    ephemeralKey = input.bytes(),
                    signedPreKeyId = SignedPreKeyId(input.int()),
                    oneTimePreKeyId = when (input.byte()) {
                        0.toByte() -> null
                        1.toByte() -> OneTimePreKeyId(input.int())
                        else -> throw IllegalArgumentException("Malformed session state")
                    },
                )
                else -> throw IllegalArgumentException("Malformed session state")
            }
            val origin = if (version == VERSION) {
                when (input.byte()) {
                    0.toByte() -> null
                    1.toByte() -> SessionInitiationId(input.fixed(SessionInitiationId.SIZE))
                    else -> throw IllegalArgumentException("Malformed session state")
                }
            } else {
                pending?.let { originOf(associatedData, it) }
            }
            val ratchet = input.bytes()
            input.requireEnd()
            SessionState(associatedData, pending, origin, ratchet)
        } catch (e: IllegalArgumentException) {
            throw ProtocolException.InvalidSessionState("Malformed session state", e)
        } catch (e: ProtocolException.InvalidMessage) {
            throw ProtocolException.InvalidSessionState("Malformed session state", e)
        }

        /** The initiation of a pending initiator session, from the data it repeats in every message. */
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
