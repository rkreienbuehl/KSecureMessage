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
 * blob and is never interpreted here.
 */
internal class SessionState(
    val associatedData: ByteArray,
    val pending: PendingPreKey?,
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
        out.bytes(ratchet)
        return out.toByteArray()
    }

    companion object {
        private const val VERSION: Byte = 1

        fun decode(data: ByteArray): SessionState = try {
            val input = BinaryReader(data)
            if (input.byte() != VERSION) throw IllegalArgumentException("Unsupported session state version")
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
            val ratchet = input.bytes()
            input.requireEnd()
            SessionState(associatedData, pending, ratchet)
        } catch (e: IllegalArgumentException) {
            throw ProtocolException.InvalidSessionState("Malformed session state", e)
        }
    }
}
