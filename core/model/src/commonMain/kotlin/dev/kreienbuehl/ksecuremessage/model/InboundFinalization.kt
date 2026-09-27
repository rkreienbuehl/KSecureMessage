package dev.kreienbuehl.ksecuremessage.model

/**
 * The terminal outcome of a received logical message (docs/message-discard.md).
 * A pending message becomes exactly one of these, once, by an explicit
 * application call; the outcome never changes afterwards.
 *
 * Local metadata only: the sender receives the same acknowledgement for both
 * and cannot tell them apart.
 */
enum class InboundFinalization {
    /** The application applied the message. */
    COMMITTED,

    /** The application decided never to apply the message. */
    DISCARDED,
}

/**
 * Why the application discarded a received message (docs/message-discard.md).
 * A closed set of codes, deliberately not free text: it is stored unencrypted
 * as local metadata and never sent to the sender. Use it for permanent
 * decisions only; a temporary failure should leave the message pending.
 */
enum class MessageDiscardReason {
    /** The application cannot interpret the content (unknown type, unsupported version, malformed). */
    UNSUPPORTED_CONTENT,

    /** The content is valid, but the application state makes it permanently inapplicable. */
    INVALID_APPLICATION_STATE,

    /** The user rejected the message. */
    USER_REJECTED,

    /** An application policy rejected the message. */
    POLICY_REJECTED,

    /** Any other permanent reason. */
    OTHER,
}
