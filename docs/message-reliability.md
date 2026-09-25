# Message reliability: logical IDs, acknowledgements, retry

Milestone 8 adds a small reliability layer on top of encrypted sessions. Its
main job: a message discarded because its session lost a
simultaneous-initiation collision ([session-lifecycle.md](session-lifecycle.md))
can be sent again on the winning session and delivered once. The same
mechanism recovers messages whose envelope or acknowledgement was lost.

It is not a durable messaging service. The server is unchanged, retries are
explicit, and no exactly-once guarantee for application side effects exists.

Code: `client/core/.../client/SecureMessageClient.kt` (`send`, `decrypt`,
`retryPendingMessages`, `pendingMessages`), `ReliableMessages.kt`,
`core/protocol/.../protocol/SecurePayloadCodec.kt`, stores in
`storage/core/.../storage/ClientStorage.kt`.

> **Plaintext at rest.** Client storage now contains the plaintext of every
> sent message until the recipient acknowledges it
> (`PendingOutboundStore`). No adapter encrypts it. Protect the database like
> the key material it already holds ([storage.md](storage.md#sensitive-data-at-rest)).

## Four different events

| Event | Meaning | Clears pending? |
|---|---|---|
| Transport accepted the envelope (`send` returns, HTTP 202) | the relay queued one ciphertext | no |
| Recipient decrypted the ciphertext | ratchet step succeeded | no |
| Recipient accepted the logical message | frame valid, marked processed, returned once as `ReceiveResult.Message` | no |
| Sender processed the recipient's acknowledgement | encrypted ACK arrived on the session | **yes** |

## Logical message ID vs. envelope ID

- `LogicalMessageId` (`core:model`): 16 random bytes (`kotlin.uuid.Uuid.random()`),
  chosen by the sending client for one application message. It travels
  **inside** the encrypted payload and never changes when the message is
  encrypted again.
- `MessageId` (`EncryptedEnvelope.id`): one transport attempt. Every
  encryption (first send, every retry, every ACK) gets a new random envelope
  ID.

```
logical message M ── encrypt on losing session A ──> envelope E1
                  └─ retry on winning session B  ──> envelope E2   (E1 != E2, M == M)
```

The ID is scoped by device: dedup is keyed by (sender `DeviceAddress`,
`LogicalMessageId`), pending messages and ACKs by (recipient
`DeviceAddress`, `LogicalMessageId`). The same raw ID from two devices is two
messages. IDs are not derived from plaintext, time or row IDs.

## Reliability frame (SecurePayload v1)

Every ratchet plaintext of a milestone 8 client is exactly one frame. The
frame is encrypted; the server sees neither IDs, ACK relations, message types
nor retries. The outer ciphertext wire format ([wire-format.md](wire-format.md))
is unchanged.

```
ApplicationMessage: version=0x01 | type=0x01 | messageId[16] | length:u32 | body
Acknowledgement:    version=0x01 | type=0x02 | messageId[16]
```

- `length` is unsigned 32-bit big-endian, `0..MAX_BODY_SIZE`
  (`MAX_BODY_SIZE` = 196 608 bytes = 192 KiB). An empty body is allowed.
  The largest frame is 196 630 bytes; after Kodium's ratchet overhead it
  stays below `CiphertextMessageCodec.MAX_RATCHET_PAYLOAD_SIZE` (256 KiB),
  checked by `SecurePayloadCodecTest.maximalFrameFitsTheWireFormat`.
- Any 16 bytes are a valid ID.
- Decoding rejects, without allocating more than the input: input larger
  than the largest frame (`MessageTooLarge`), unknown version
  (`UnsupportedSecurePayloadVersion`), truncation, unknown type, a length
  above the limit, and trailing bytes (`MalformedSecurePayload`).
- Encoding is deterministic; an oversized body fails with `MessageTooLarge`
  before anything is stored.

Frozen vectors (`SecurePayloadCodecTest`, written by hand):

| Frame | Hex |
|---|---|
| ApplicationMessage, ID `000102…0f`, body `"hi"` | `0101 000102030405060708090a0b0c0d0e0f 00000002 6869` |
| Acknowledgement, ID `000102…0f` | `0102 000102030405060708090a0b0c0d0e0f` |
| ApplicationMessage, ID all zero, empty body | `0101 00000000000000000000000000000000 00000000` |
| Acknowledgement, ID all `ff` | `0102 ffffffffffffffffffffffffffffffff` |

### Compatibility

Milestone 8 is a compatibility break of the **decrypted plaintext only**.
Clients before milestone 8 encrypt raw application bytes; arbitrary bytes can
look like a frame, so there is no detection heuristic, and the unauthenticated
`EncryptedEnvelope.protocolVersion` is not used to tell them apart (a relay
could change it). A plaintext that is not a valid frame fails with
`MalformedSecurePayload` or `UnsupportedSecurePayloadVersion`; the receive
transaction rolls back (no session step, no pin, no one-time prekey use, no
processed marker) and nothing is delivered or acknowledged. **Peers must
upgrade together.** Identities, sessions, pins, prekeys and retired
initiations stored before the upgrade stay valid.

## Sending

`send(remote, plaintext): SentMessage` (under the client's send mutex):

1. Generate a `LogicalMessageId`, encode the frame (size check).
2. Fetch a prekey bundle if there is no session (outside any transaction).
3. **One transaction:** store the frame as pending, encrypt it on the current
   or new session, store the advanced session.
4. After the commit, hand the envelope to the transport.

An exception other than `MessageNotSent` means nothing was stored. If the
hand-off fails, `send` throws `SecureMessageClientException.MessageNotSent(messageId, cause)`
with the transport's exception as cause; the message stays pending and the
session stays advanced (it is never rewound; the unused ratchet index is a
skipped message for the recipient).

## Receiving

`decrypt(envelope): ReceiveResult` runs the session rules of milestones 5–7
unchanged, then, in the same transaction, decodes the frame:

- **ApplicationMessage, ID not processed for this sender:** mark processed,
  return `ReceiveResult.Message(sender, id, plaintext, ackSent)`.
- **ApplicationMessage, ID already processed:** return
  `ReceiveResult.Duplicate(sender, id, ackSent)` without the plaintext.
- **Acknowledgement:** remove the pending message (recipient = this sender,
  id) and return `ReceiveResult.Acknowledgement(sender, id, cleared)`.
  `cleared = false` for an unknown or repeated ACK, which is harmless.
  ACKs are never acknowledged.

For `Message` and `Duplicate` the client then sends an encrypted ACK frame
to the sender, after the commit, through the same send mutex and transport as
any message, on the **existing** session only (it never fetches a bundle or
starts a session) and never stored as pending. If that fails for any reason
other than cancellation, `ackSent` is `false` and the call still succeeds: the
processed marker stays and the sender's next retry triggers a new ACK.
`CancellationException` propagates.

Nothing is acknowledged, and nothing is marked processed, when the receive
fails: decryption failure, `IdentityChanged`, `StaleSessionInitiation`,
`ExpiredSignedPreKey`, a malformed frame, a storage failure, and
`SessionCollision` (the losing message's plaintext is discarded unread; that
is exactly the message its sender must resend).

## What an ACK means

An ACK for M from device B proves: B decrypted M on a session authenticated
by B's pinned identity, the frame was valid, and B recorded M as processed
(now or earlier). It does **not** mean that B's application stored,
displayed or read M. There are no read receipts or delivered/read UI states.

ACK authenticity comes from the session: an ACK is only accepted after
decryption, and it only clears a message that was sent **to the ACK's
sender**. Bob cannot clear Alice's pending message to Carol.

## Delivery guarantee

`decrypt` returns each (sender, logical ID) at most once. The processed
marker commits together with the ratchet step before `decrypt` returns. If
the application crashes after that and before it handled the plaintext, the
message is lost for the application: dedup suppresses the sender's retries.
KSecureMessage has no application commit callback, so exactly-once
application side effects are not provided. Before milestone 8 the same
window existed (the ratchet step committed before the plaintext was
returned).

Transport attempts are at least once (the sender may retry any number of
times); logical delivery through `decrypt` is at most once.

## Retry

`retryPendingMessages(remote): List<LogicalMessageId>` (under the send
mutex):

1. Read the pending IDs for `remote` in send order.
2. For each: fetch a bundle if there is no session (outside transactions);
   in one transaction, skip it if it was acknowledged meanwhile, else encrypt
   the stored frame **fresh** under the current session and store the
   session; hand the new envelope (new `MessageId`) to the transport.
3. Stop at the first hand-off failure with `MessageNotSent`; later messages
   are not sent ahead of it. Encryption failures are thrown unchanged and
   leave that message pending and the session unchanged.

It returns the IDs handed off. Nothing becomes delivered through a retry;
messages stay pending until their ACK. Old ciphertext is never reused. There
is no scheduler: the application decides when to call it, for example after
processing received envelopes, after a `SessionCollision`, or when it
suspects a lost ACK. `pendingMessages(remote)` lists what is still pending
(with plaintext copies).

**Readiness.** A retry always encrypts on the session the client has now.
The client never keeps a session it knows lost a collision: the winning
`PreKeyMessage` replaces it in the same transaction. Before that message
arrives, the client cannot tell whether its pending initiation lost; a retry
then produces another `PreKeyMessage` of the losing initiation, which the
winner rejects with `StaleSessionInitiation`, without ACK. The message stays
pending; the only cost is a wasted envelope. The client does not refuse to
retry while its session awaits a reply, because a lost first ACK looks
exactly the same locally and must be recoverable.

### Order

Pending messages carry a local `sequence` (persisted, strictly increasing,
never reused); retries send them in that order. It is reliability metadata,
not cryptographic freshness, and plays no part in collision decisions.
Envelopes still follow the per (sender, recipient) FIFO contract of
[transport-ordering.md](transport-ordering.md): sends, retries and ACKs all
go through the one send mutex. ACKs are independent of each other: ACK(M2)
clears M2 even if M1 is still pending.

## Collision recovery walk-through

Alice and Bob start sessions at the same time. Suppose Bob's initiation `b`
has the smaller ID and wins; Alice's first message A1 went out on `a`.

1. Bob decrypts A1's `PreKeyMessage`: collision lost by `a`. Bob
   authenticates it, discards the plaintext, retires `a` and throws
   `SessionCollision`. No ACK, nothing processed. Alice's A1 stays pending.
2. Alice decrypts Bob's B1 on `b`: she replaces her pending session with `b`,
   returns B1 and sends ACK(B1) as a `RatchetMessage` on `b`.
3. Bob decrypts ACK(B1): B1 is no longer pending. The sessions converged.
4. Alice calls `retryPendingMessages(BOB)`: A1's stored frame (same logical
   ID) is encrypted fresh on `b` into a new envelope.
5. Bob decrypts it: A1 is new for (Alice, A1), marked processed, returned
   once, ACK(A1) sent.
6. Alice decrypts ACK(A1): A1 is removed from pending storage.

If Alice retried between steps 1 and 2, Bob would reject the retry as
`StaleSessionInitiation` and A1 would stay pending. Both winners, both
delivery orders and a restart before the retry are tested in
`MessageCollisionRecoveryTest`; the same flow over SQLite with restarts in
`SqlDelightPersistenceTest.collisionLostMessageIsRecoveredAfterRestart`.

## Crash windows

Sender:

- *Crash before the send transaction commits:* nothing was stored, nothing
  sent. The application did not get a `SentMessage` and sends again.
- *Crash after the commit, before the hand-off* (the session advanced, the
  envelope is gone): the message is pending; a retry sends fresh ciphertext
  on the current state.
- *Crash after the transport accepted the envelope, before the ACK:* the
  message stays pending; a retry may deliver it twice to the recipient,
  whose dedup returns it once.

Receiver:

- *Crash inside the receive transaction:* rolled back; the envelope can be
  decrypted again if the application still has it, otherwise the sender's
  retry delivers the message.
- *Crash after the commit (processed marker stored), before the ACK:* the
  sender's retry is a `Duplicate`, not delivered again, and triggers another
  ACK.
- *Crash after `decrypt` returned, before the application handled it:* the
  message is lost for the application (see "Delivery guarantee").

ACKs are not stored for resending. If an ACK is lost and the sender never
retries, the sender keeps the message pending indefinitely; the recovery path
is the sender's explicit retry.

## Storage

- `PendingOutboundStore`: (recipient, id) → sequence and encoded
  ApplicationMessage frame. Stored in the same transaction as the first
  encryption; removed only by a valid ACK from that recipient. The frame, not
  the ciphertext, is kept, so every retry encrypts the same bytes fresh and
  the logical ID cannot drift. No tombstone after removal.
- `ProcessedInboundStore`: (sender, id) set. Written in the same transaction
  as the ratchet step. **Kept forever**: without server delivery expiry, any
  old message could still be retried, so time-based pruning could redeliver
  it. This grows with the number of received messages.

SQLDelight schema version 5 (`4.sqm`) adds `pending_outbound_message` and
`processed_inbound_message`; see [storage.md](storage.md).

## API changes (breaking)

- `send(remote, plaintext)` returns `SentMessage(id, envelope)` and stores
  the message as pending; it throws `MessageNotSent` after a failed hand-off.
- `decrypt(envelope)` returns `ReceiveResult` (`Message`, `Duplicate`,
  `Acknowledgement`) instead of `ByteArray`, and sends ACKs.
- New: `retryPendingMessages(remote)`, `pendingMessages(remote)`.
- The raw session layer (`encryptRaw`, `sendRaw`, `decryptRaw`: raw
  plaintext, no frame, no ACK) is `internal`. The public `encrypt` is gone:
  an envelope encrypted outside the reliability layer would not be
  acknowledged or resent.
- Server, HTTP API, transport interface, `ProtocolEngine`, the ciphertext
  wire format, info strings and `SessionInitiationId` are unchanged.

## Limitations

- No exactly-once application side effects; no application commit API.
- Processed IDs are never pruned.
- Pending plaintext is stored unencrypted.
- Retry is explicit; no background scheduler, no automatic retry after
  convergence.
- A lost ACK is only recovered by a sender retry.
- No persistent server mailbox, no server delivery receipts, no read
  receipts.
