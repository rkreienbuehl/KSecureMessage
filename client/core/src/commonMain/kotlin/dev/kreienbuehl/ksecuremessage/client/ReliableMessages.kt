package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * Result of [SecureMessageClient.send]: the logical message and the envelope
 * of its first attempt. Retries use new envelopes with the same [id].
 */
class SentMessage(val id: LogicalMessageId, val envelope: EncryptedEnvelope)

/**
 * A sent message that [recipient] has not acknowledged yet
 * (docs/outbound-message-lifecycle.md). [plaintext] is a copy.
 *
 * @property sequence local send order of pending messages, across all
 *   recipients. Stable across restarts and never reused; not a cryptographic
 *   value.
 */
class PendingMessage(
    val recipient: DeviceAddress,
    val id: LogicalMessageId,
    val sequence: Long,
    val plaintext: ByteArray,
)

/**
 * One page of [SecureMessageClient.pendingMessages]
 * (docs/outbound-message-lifecycle.md): [messages] in ascending
 * [PendingMessage.sequence] order.
 *
 * [nextAfterSequence] is the sequence of the last message if more pending
 * messages existed when the page was read; pass it as `afterSequence` for the
 * next page. `null` means the enumeration reached the end; messages sent
 * later have higher sequence numbers, so to see them, continue after the last
 * sequence you received.
 */
class PendingMessagePage(val messages: List<PendingMessage>, val nextAfterSequence: Long?) {
    companion object {
        /** The largest page [SecureMessageClient.pendingMessages] returns. */
        const val MAX_SIZE: Int = 100
    }
}

/**
 * What [SecureMessageClient.abandonPendingMessage] did
 * (docs/outbound-message-lifecycle.md). Abandoning is local: nothing is sent,
 * and it is not a recall.
 */
enum class AbandonStatus {
    /** The message was pending; this call removed it. It is never sent again. */
    ABANDONED,

    /**
     * The message was not pending: acknowledged, abandoned before, or never
     * sent to this recipient. Nothing changed; the client does not remember
     * which it was.
     */
    NOT_PENDING,
}

/**
 * A received application message that waits for the application's decision
 * (docs/application-delivery.md, docs/message-discard.md). It is delivered
 * again, by [SecureMessageClient.decrypt] and
 * [SecureMessageClient.pendingReceivedMessages], until the application
 * finalizes it with [SecureMessageClient.commitReceivedMessage] or
 * [SecureMessageClient.discardReceivedMessage].
 *
 * ([sender], [id]) identifies the message; applications should use it as the
 * idempotency key of their own processing. [plaintext] is a copy.
 *
 * @property sequence local order in which this device accepted pending
 *   messages. Stable across restarts; not an order across senders or a
 *   sender's send order.
 * @property receivedAt when this device first accepted the message (local clock).
 */
class ReceivedMessage(
    val sender: DeviceAddress,
    val id: LogicalMessageId,
    val sequence: Long,
    val receivedAt: Instant,
    val plaintext: ByteArray,
)

/**
 * One page of [SecureMessageClient.pendingReceivedMessages]
 * (docs/message-discard.md): [messages] in ascending
 * [ReceivedMessage.sequence] order.
 *
 * [nextAfterSequence] is the sequence of the last message if more pending
 * messages existed when the page was read; pass it as `afterSequence` for the
 * next page. `null` means the enumeration reached the end; messages accepted
 * later have higher sequence numbers, so to see them, continue after the
 * last sequence you received.
 */
class PendingReceivedPage(val messages: List<ReceivedMessage>, val nextAfterSequence: Long?) {
    companion object {
        /** The largest page [SecureMessageClient.pendingReceivedMessages] returns. */
        const val MAX_SIZE: Int = 100
    }
}

/** Outcome of [SecureMessageClient.decrypt] (docs/message-reliability.md, docs/application-delivery.md). */
sealed interface ReceiveResult {
    val sender: DeviceAddress
    val id: LogicalMessageId

    /**
     * An application message the application has not finalized yet. It is
     * not acknowledged: the sender keeps it pending until the application
     * calls [SecureMessageClient.commitReceivedMessage] or
     * [SecureMessageClient.discardReceivedMessage]. Returned again, with the
     * same [message], for every copy the sender retries before that.
     */
    class Delivery(val message: ReceivedMessage) : ReceiveResult {
        override val sender: DeviceAddress get() = message.sender
        override val id: LogicalMessageId get() = message.id
    }

    /**
     * A message the application already committed, sent again by [sender]
     * (for example because the acknowledgement was lost). Its plaintext is not
     * delivered again; it was acknowledged again ([ackSent]).
     */
    class AlreadyCommitted(
        override val sender: DeviceAddress,
        override val id: LogicalMessageId,
        val ackSent: Boolean,
    ) : ReceiveResult

    /**
     * A message the application discarded, sent again by [sender] (for
     * example because the acknowledgement was lost). Its plaintext is not
     * delivered again (it is no longer stored); it was acknowledged again
     * ([ackSent]). The sender cannot tell this from [AlreadyCommitted].
     */
    class AlreadyDiscarded(
        override val sender: DeviceAddress,
        override val id: LogicalMessageId,
        val ackSent: Boolean,
    ) : ReceiveResult

    /**
     * [sender] acknowledged message [id]: its application finalized it
     * (committed or discarded; this device cannot tell which).
     * [cleared] is `true` if it was pending for [sender] and is now removed;
     * `false` for a repeated or unknown acknowledgement, or one for a message
     * this device abandoned, which is harmless.
     */
    class Acknowledgement(
        override val sender: DeviceAddress,
        override val id: LogicalMessageId,
        val cleared: Boolean,
    ) : ReceiveResult
}

/** What [SecureMessageClient.commitReceivedMessage] did. */
enum class CommitStatus {
    /** The message was pending; this call committed it. */
    COMMITTED,

    /** The message was committed before; nothing changed. */
    ALREADY_COMMITTED,

    /** The message was discarded before; nothing changed, it stays discarded. */
    ALREADY_DISCARDED,
}

/**
 * Result of [SecureMessageClient.commitReceivedMessage]. [ackSent] is `false`
 * if the acknowledgement could not be sent; the commit stands, and the
 * sender's next retry of the message triggers a new acknowledgement.
 */
class CommitResult(
    val sender: DeviceAddress,
    val id: LogicalMessageId,
    val status: CommitStatus,
    val ackSent: Boolean,
)

/** What [SecureMessageClient.discardReceivedMessage] did. */
enum class DiscardStatus {
    /** The message was pending; this call discarded it. */
    DISCARDED,

    /** The message was discarded before; nothing changed (the reason stays the first one). */
    ALREADY_DISCARDED,

    /** The message was committed before; nothing changed, it stays committed. */
    ALREADY_COMMITTED,
}

/**
 * Result of [SecureMessageClient.discardReceivedMessage]. [ackSent] is
 * `false` if the acknowledgement could not be sent; the discard stands, and
 * the sender's next retry of the message triggers a new acknowledgement.
 */
class DiscardResult(
    val sender: DeviceAddress,
    val id: LogicalMessageId,
    val status: DiscardStatus,
    val ackSent: Boolean,
)

/**
 * How long finalized (committed or discarded) message IDs are kept for duplicate suppression
 * (docs/application-delivery.md). Applied only by
 * [SecureMessageClient.pruneProcessedMessages]; there is no default.
 *
 * An entry is removed once its age (client clock minus commit or discard
 * time) is at least [maxAge]. [Duration.INFINITE] keeps every entry.
 */
class ProcessedInboundRetentionPolicy(val maxAge: Duration) {
    init {
        require(maxAge > Duration.ZERO) { "maxAge must be positive" }
    }
}
