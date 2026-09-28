# Explicit discard and pending-inbound pagination

Milestone 20 kept every received message pending until the application
committed it ([application-delivery.md](application-delivery.md)). A message
the application can never apply (unknown content type, a state it cannot
reach, a user or policy rejection) therefore stayed pending forever, and
`pendingReceivedMessages` loaded every pending plaintext at once.

Milestone 21 adds:

- **explicit discard**: a second terminal outcome, chosen by the application
  for exactly one message, durable and immutable;
- **cursor pagination** of pending messages, bounded page size, plus a count;
- a broadened ACK meaning: the receiving application durably **finalized**
  the message.

Core rule: **a pending message never disappears automatically.** The
application picks one terminal outcome explicitly, or the message stays
pending indefinitely:

```
PENDING
├── commitReceivedMessage  ──> COMMITTED
└── discardReceivedMessage ──> DISCARDED
```

There is no automatic discard, no pending TTL, no background cleanup, no
bulk discard, no server-side dead-letter state and no sender-visible
rejection. Client only: no server, HTTP, transport, wire, SecurePayload, ACK
frame or record format change.

Code: `client/core/.../client/SecureMessageClient.kt`
(`discardReceivedMessage`, `commitReceivedMessage`, `pendingReceivedMessages`,
`pendingReceivedMessageCount`, `decrypt`), `ReliableMessages.kt`
(`PendingReceivedMessagePage`, `DiscardResult`, `DiscardStatus`,
`CommitStatus.ALREADY_DISCARDED`, `ReceiveResult.AlreadyDiscarded`),
`core/model/.../model/InboundFinalization.kt` (`InboundFinalization`,
`MessageDiscardReason`), stores in `storage/core/.../storage/ClientStorage.kt`.

## Terminal states

| State | Stored | Copy of the message (sender retry), same body | Same logical ID, other body |
|---|---|---|---|
| PENDING | sealed frame (plaintext), sequence, `received_at` | `ReceiveResult.Delivery` again, no ACK | `LogicalMessageConflict`, no ACK |
| COMMITTED | tombstone: finalization 0, `finalizedAt`, sealed digest | `ReceiveResult.AlreadyCommitted`, no plaintext, **ACK again** | `LogicalMessageConflict`, no ACK |
| DISCARDED | tombstone: finalization 1, `finalizedAt`, sealed digest, discard reason; **no plaintext** | `ReceiveResult.AlreadyDiscarded`, no plaintext, **ACK again** | `LogicalMessageConflict`, no ACK |
| pruned tombstone | nothing | decrypted as a new message | — |

The outcome never changes: a tombstone is never replaced (storage throws on a
second `markCommitted`/`markDiscarded` for the same sender and ID), a commit
of a discarded message reports `ALREADY_DISCARDED`, a discard of a committed
message reports `ALREADY_COMMITTED`.

## Public API

```kotlin
suspend fun discardReceivedMessage(message: ReceivedMessage, reason: MessageDiscardReason): DiscardResult
suspend fun discardReceivedMessage(sender: DeviceAddress, id: LogicalMessageId, reason: MessageDiscardReason): DiscardResult
class DiscardResult(sender, id, status: DiscardStatus, ackSent: Boolean)
enum class DiscardStatus { DISCARDED, ALREADY_DISCARDED, ALREADY_COMMITTED }

suspend fun commitReceivedMessage(...): CommitResult
enum class CommitStatus { COMMITTED, ALREADY_COMMITTED, ALREADY_DISCARDED }

suspend fun pendingReceivedMessages(afterSequence: Long? = null, limit: Int, sender: DeviceAddress? = null): PendingReceivedMessagePage
class PendingReceivedMessagePage(messages: List<ReceivedMessage>, nextAfterSequence: Long?) { MAX_SIZE = 100 }
suspend fun pendingReceivedMessageCount(sender: DeviceAddress? = null): Long

sealed interface ReceiveResult { Delivery, AlreadyCommitted, AlreadyDiscarded /* M21 */, Acknowledgement }

suspend fun pruneProcessedMessages(policy: ProcessedInboundRetentionPolicy): Int   // both outcomes
```

A message is identified by (sender `DeviceAddress`, `LogicalMessageId`),
exactly as for commit; the plaintext is never an input. An ID that is neither
pending nor finalized (never received, or its tombstone was pruned) throws
`ReceivedMessageNotPending` and records nothing: no tombstone is created from
nothing. Repeated calls are idempotent and send the ACK again.

**Breaking change.** The unbounded `pendingReceivedMessages(sender)` list is
gone; the page is the only enumeration. `ReceiveResult` gained a subtype, so
exhaustive `when` expressions need a branch for `AlreadyDiscarded`.

## Discard reason

`MessageDiscardReason` is a closed enum: `UNSUPPORTED_CONTENT`,
`INVALID_APPLICATION_STATE`, `USER_REJECTED`, `POLICY_REJECTED`, `OTHER`.
Deliberately no free text, so no diagnostic blob, plaintext or secret can end
up in it. It is stored as an unencrypted integer code (1–5), local metadata
only: it is never sent to the sender, and it is deleted together with the
tombstone (no separate audit history). A repeated discard keeps the first
reason.

## ACK meaning

After milestone 21 an ACK means: **the receiving application durably
finalized the logical message and will not have it redelivered.** Finalized
is COMMITTED or DISCARDED. It does not mean displayed, read, or that a
business operation succeeded.

This is a deliberate evolution of milestone 20 (where the ACK meant
"committed"). The ACK frame (SecurePayload v1, type 0x02) is unchanged, so the
sender learns only "finalized": it cannot tell a commit from a discard and
never learns the reason. The sender clears its pending outbound entry on the
ACK whatever the outcome; a sender-visible rejection would be a separate
protocol feature.

## Transactions

Discard is one client storage transaction:

1. load the pending message (opening its sealed frame);
2. compute `ApplicationMessageDigest` of the body, zero the body;
3. remove the pending row (the plaintext is gone);
4. insert the tombstone: finalization DISCARDED, digest, `finalizedAt` =
   client clock, reason.

A failure in any step rolls back all of them: the message stays pending and
no tombstone exists (`MessageDiscardTest.failedTombstoneRollsBackTheDiscard`,
`ClientStorageContractTest.rolledBackDiscardKeepsThePendingMessage`). Only
after the commit, outside any storage transaction, the ACK is encrypted on
the existing session and handed off under the send mutex. An ACK failure never
undoes the discard: `ackSent = false`, and the sender's next retry is
answered with `AlreadyDiscarded` and a new ACK. If neither pending nor a
tombstone exists, nothing is written.

## Concurrency

Commit, discard and receive are storage transactions, which the adapters
serialize:

- **commit vs discard:** exactly one wins; the loser sees the winner's
  tombstone (`ALREADY_DISCARDED` / `ALREADY_COMMITTED`). The outcome never
  flips.
- **two discards:** one `DISCARDED`, the others `ALREADY_DISCARDED`; each
  sends an ACK, which is harmless (`cleared = false` for the repeats).
- **retry vs discard:** either the retry runs first (the pending message is
  delivered again, no ACK, then the discard finalizes it) or the discard runs
  first (the retry sees the tombstone: `AlreadyDiscarded` and ACK). Once a
  receive has seen the tombstone it never redelivers.

Tests: `MessageDiscardTest` (in-memory) and
`MessageDiscardStorageTest.commitRacingADiscardOnOneDatabaseHasOneWinner`
(SQLDelight).

## Pagination

`pendingReceivedMessages(afterSequence, limit, sender)`:

- **cursor:** `ReceivedMessage.sequence`, the persisted, strictly increasing,
  never reused local acceptance sequence. A page holds messages with
  `sequence > afterSequence` (from the start if `null`); never an offset.
- **order:** ascending sequence.
- **size:** `1 <= limit <= PendingReceivedMessagePage.MAX_SIZE` (100); other values
  and a negative `afterSequence` throw `IllegalArgumentException`.
- **next page:** `nextAfterSequence` is the last returned sequence when more
  pending messages existed at read time, else `null`.
- **sender filter:** optional; the cursor stays the global sequence (no
  per-sender sequence space), so a cursor from one filter works with another.

Each page is its own transaction; an enumeration is not a snapshot. Messages
finalized between pages do not shift later pages and no message is returned
twice (the cursor excludes everything up to the last one seen). Messages
accepted during an enumeration get higher sequence numbers and may appear on
later pages. After `nextAfterSequence == null`, resuming later from the last
sequence seen returns only messages accepted since.

Only the returned records are opened and decrypted; `pendingReceivedMessageCount`
opens none. A damaged pending record makes every page containing it fail
with `StorageEncryptionException` (fail closed); it cannot be discarded
either, because the discard needs its body for the digest.

## Recommended application flow

```
Delivery (decrypt or a pendingReceivedMessages page)
  → try to apply it in the application's own transaction, idempotently by (sender, id)
  → success                               → commitReceivedMessage
  → permanently unprocessable / rejected  → (archive it yourself if needed) → discardReceivedMessage(reason)
  → temporary failure                     → leave it pending; retry later
```

Do not discard for transient failures (network, locked database, missing
dependency that may arrive): a discard is irreversible and the sender stops
retrying once it receives the ACK.

## Dead-letter terminology

The library has no dead-letter queue, local or on the server. "Dead-letter"
here means only: a durable DISCARDED terminal tombstone. The plaintext is
**not** moved anywhere; the discard deletes it, which bounds sensitive local
storage. An application that wants to keep rejected content must store it
itself before calling `discardReceivedMessage`.

## Retention

Committed and discarded tombstones share the one explicit retention policy:
`pruneProcessedMessages(ProcessedInboundRetentionPolicy(maxAge))` removes
every tombstone with `finalizedAt <= now − maxAge` (maxAge rounded up to
milliseconds), whatever its outcome. It never touches pending messages, and
nothing calls it implicitly. After a discarded tombstone is pruned, a later
copy of that logical ID is accepted as a new message, exactly as for a
pruned committed one; its discard reason is gone with it.

## Storage and migration

`ProcessedInboundStore` holds the terminal tombstone:
`ProcessedInboundMessage(sender, id, finalization, digest, finalizedAt,
discardReason)`, written by `markCommitted` or `markDiscarded`, pruned by
`pruneFinalizedAtOrBefore`. `PendingInboundStore` gained `page(afterSequence,
limit, sender)` and `count(sender)`; the unbounded `list` calls are gone.

SQLDelight schema version 14 (`13.sqm`):

- `processed_inbound_message.finalization INTEGER NOT NULL DEFAULT 0 CHECK (finalization IN (0, 1))`;
- `processed_inbound_message.discard_reason INTEGER CHECK ((finalization = 0 AND discard_reason IS NULL) OR (finalization = 1 AND discard_reason IS NOT NULL AND discard_reason BETWEEN 1 AND 5))`;
- index `pending_inbound_message_sender (sender_user_id, sender_device_id, sequence)`.

The column `committed_at` keeps its name; it holds the finalization time of
both outcomes. The digest of a discarded message is the same record type 12
as for a committed one (same associated data: sender and logical ID); no new
record type or format. Finalization and reason are plaintext metadata and
not bound into the associated data, like `committed_at`: someone with write
access to the database file could flip them (record-level encryption, see
[storage-encryption.md](storage-encryption.md)). Storage key rotation
re-encrypts discarded digests like committed ones.

Migration from version 13: every existing row gets finalization 0
(COMMITTED) and a `NULL` reason; `committed_at`, `sealed_digest` and all
pending rows stay byte for byte unchanged, retention behaves as before, and
no row becomes DISCARDED. Legacy rows from before milestone 20 (no digest)
stay committed and are acknowledged by ID. A fresh database has the same
columns, constraints and indexes (`SqlDelightMigrationTest.migratedSchemaEqualsNewSchema`);
frozen fixture `Version13Schema`
(`MessageDiscardStorageTest.version13DatabaseMigratesProcessedRowsAsCommitted`).

Fail closed: an unknown finalization or reason code, or a combination the
constraints forbid (only possible in a damaged or foreign database), throws
`IllegalStateException` on read. Such a row is never treated as absent,
never redelivered and never acknowledged. A damaged sealed digest fails
with `StorageEncryptionException`, without ACK.

`InMemoryClientStorage` implements the same contract (outcome, reason,
immutability, pagination, rollback, copies) without encryption.

## Limitations

- A discard is irreversible once finalized.
- The sender cannot distinguish a commit from a discard; there is no negative
  ACK or rejection protocol.
- No automatic pending expiry: pending messages still grow without bound if
  the application never decides.
- The discard reason is local metadata only, a closed set of codes.
- Processed retention eventually lets an old logical ID be accepted again,
  for discarded messages as for committed ones.
- No exactly-once application side effects; no read receipts; no sealed
  sender.
- A damaged pending record blocks every page that contains it and cannot be
  discarded; there is no raw removal API.
