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

/** A sent message that [recipient] has not acknowledged yet. [plaintext] is a copy. */
class PendingMessage(val recipient: DeviceAddress, val id: LogicalMessageId, val plaintext: ByteArray)

/**
 * A received application message that waits for the application's commit
 * (docs/application-delivery.md). It is delivered again, by
 * [SecureMessageClient.decrypt] and [SecureMessageClient.pendingReceivedMessages],
 * until [SecureMessageClient.commitReceivedMessage] is called for it.
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

/** Outcome of [SecureMessageClient.decrypt] (docs/message-reliability.md, docs/application-delivery.md). */
sealed interface ReceiveResult {
    val sender: DeviceAddress
    val id: LogicalMessageId

    /**
     * An application message the application has not committed yet. It is
     * not acknowledged: the sender keeps it pending until the application
     * calls [SecureMessageClient.commitReceivedMessage]. Returned again, with
     * the same [message], for every copy the sender retries before that.
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
     * [sender] acknowledged message [id]: its application committed it.
     * [cleared] is `true` if it was pending for [sender] and is now removed;
     * `false` for a repeated or unknown acknowledgement, which is harmless.
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

/**
 * How long committed message IDs are kept for duplicate suppression
 * (docs/application-delivery.md). Applied only by
 * [SecureMessageClient.pruneProcessedMessages]; there is no default.
 *
 * An entry is removed once its age (client clock minus commit time) is at
 * least [maxAge]. [Duration.INFINITE] keeps every entry.
 */
class ProcessedInboundRetentionPolicy(val maxAge: Duration) {
    init {
        require(maxAge > Duration.ZERO) { "maxAge must be positive" }
    }
}
