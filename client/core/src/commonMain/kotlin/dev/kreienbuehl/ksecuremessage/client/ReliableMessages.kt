package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId

/**
 * Result of [SecureMessageClient.send]: the logical message and the envelope
 * of its first attempt. Retries use new envelopes with the same [id].
 */
class SentMessage(val id: LogicalMessageId, val envelope: EncryptedEnvelope)

/** A sent message that [recipient] has not acknowledged yet. [plaintext] is a copy. */
class PendingMessage(val recipient: DeviceAddress, val id: LogicalMessageId, val plaintext: ByteArray)

/** Outcome of [SecureMessageClient.decrypt] (docs/message-reliability.md). */
sealed interface ReceiveResult {
    val sender: DeviceAddress
    val id: LogicalMessageId

    /**
     * A new application message. Returned once per ([sender], [id]).
     * [ackSent] is `false` if the acknowledgement could not be sent; the
     * sender will retry, and the retry is acknowledged.
     */
    class Message(
        override val sender: DeviceAddress,
        override val id: LogicalMessageId,
        val plaintext: ByteArray,
        val ackSent: Boolean,
    ) : ReceiveResult

    /**
     * A message that was already returned as [Message] once, sent again by
     * [sender]. Its plaintext is not delivered again; it was acknowledged
     * again ([ackSent]).
     */
    class Duplicate(
        override val sender: DeviceAddress,
        override val id: LogicalMessageId,
        val ackSent: Boolean,
    ) : ReceiveResult

    /**
     * [sender] acknowledged message [id]. [cleared] is `true` if it was
     * pending for [sender] and is now removed; `false` for a repeated or
     * unknown acknowledgement, which is harmless.
     */
    class Acknowledgement(
        override val sender: DeviceAddress,
        override val id: LogicalMessageId,
        val cleared: Boolean,
    ) : ReceiveResult
}
