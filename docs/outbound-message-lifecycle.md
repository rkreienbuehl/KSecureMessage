# Pending outbound pagination and explicit abandon

Milestone 8 keeps every sent message pending, with its plaintext (sealed at
rest), until the recipient acknowledges it
([message-reliability.md](message-reliability.md)). A recipient that never
acknowledges (gone, never finalizes, lost its device) left those messages
pending forever, and `pendingMessages(remote)` loaded all of them at once.

Milestone 22 is the sender-side counterpart of milestone 21
([message-discard.md](message-discard.md)):

- **cursor pagination** of pending sent messages, bounded page size, plus a
  count;
- **explicit abandon**: the application removes exactly one pending message
  it no longer wants delivered.

```
PENDING_OUTBOUND
├── ACK from the recipient  ──> removed (the recipient's application finalized it)
└── abandonPendingMessage   ──> removed (this application gave up; local only)
```

Both end the same way locally: the row, plaintext included, is deleted. The
client keeps no tombstone and does not remember which of the two happened.
An application that needs that history records it itself.

There is no automatic expiry, no background abandon, no retry scheduler, no
bulk abandon, no abandon reason, no recall and no negative ACK. Client only:
no server, HTTP, transport, wire, SecurePayload, ACK frame or record format
change.

Code: `client/core/.../client/SecureMessageClient.kt`
(`pendingMessages`, `pendingMessageCount`, `abandonPendingMessage`,
`retryPendingMessages`), `ReliableMessages.kt` (`PendingMessage`,
`PendingMessagePage`, `AbandonStatus`), `PendingOutboundStore` in
`storage/core/.../storage/ClientStorage.kt`.

## Public API

```kotlin
suspend fun pendingMessages(afterSequence: Long? = null, limit: Int, recipient: DeviceAddress? = null): PendingMessagePage
suspend fun pendingMessageCount(recipient: DeviceAddress? = null): Long
suspend fun abandonPendingMessage(message: PendingMessage): AbandonStatus
suspend fun abandonPendingMessage(recipient: DeviceAddress, id: LogicalMessageId): AbandonStatus
suspend fun retryPendingMessages(remote: DeviceAddress): List<LogicalMessageId>   // unchanged signature

class PendingMessage(recipient, id, sequence, plaintext)   // plaintext is a copy
class PendingMessagePage(messages: List<PendingMessage>, nextAfterSequence: Long?) { MAX_SIZE = 100 }
enum class AbandonStatus { ABANDONED, NOT_PENDING }
```

Breaking: the unbounded `pendingMessages(remote)` is gone (use
`pendingMessages(limit = …, recipient = remote)` and follow the cursor), and
`PendingMessage` gained `sequence`. `PendingOutboundStore.list` is replaced
by `page` and `count`. All of them need an initialized client
(`NotInitialized`).

## Pagination

- **Cursor:** the persisted pending sequence number, one global sequence
  across recipients, strictly increasing and never reused (also after ACKs,
  abandons and restarts). A page returns messages with `sequence >
  afterSequence` (from the start if `null`) in ascending order. Never
  `OFFSET`.
- **Page size:** `1..PendingMessagePage.MAX_SIZE` (100); other limits and a
  negative cursor throw `IllegalArgumentException`. The client reads
  `limit + 1` rows to know whether another page exists; `nextAfterSequence`
  is the last returned sequence then, else `null`.
- **Recipient filter:** optional; it uses the same global cursor, so a
  filtered enumeration can continue from any sequence.
- **Mutation between pages:** each page is its own transaction; an
  enumeration is not a snapshot. Messages acknowledged or abandoned after a
  page do not shift later pages (no skips, no repeats). Messages sent
  meanwhile have higher sequence numbers and appear on later pages; after
  `nextAfterSequence == null`, continue after the last sequence seen to find
  them.
- **Storage:** only the returned records are opened; counting opens none.
  SQLDelight uses `WHERE sequence > ? ORDER BY sequence LIMIT ?` (plus the
  recipient predicate on the index added in schema version 15).

## Abandon

`abandonPendingMessage(recipient, id)` removes the pending entry for exactly
(recipient, logical ID) in one storage transaction and returns
`ABANDONED`. If it is not pending (acknowledged, abandoned before, never
sent to that recipient) nothing changes and it returns `NOT_PENDING`.

It is **local only**:

- no network call of any kind (no envelope, no bundle fetch), no new frame
  type (no CANCEL, RECALL, NACK or ABANDON), no server call;
- the session, other pending messages, other recipients, pending and
  processed inbound state, session initiations and identity pins are not
  touched; nothing is rewound;
- it is **not a recall**: envelopes already handed to the transport stay in
  the recipient's mailbox. The recipient can still decrypt, commit or discard
  the message and acknowledge it. The sender cannot know whether the
  recipient already processed it.

A failed removal rolls back: the message stays pending. Abandon works in
every pending situation: after a failed initial hand-off (`MessageNotSent`,
no envelope ever left), after a retry whose encryption failed, and while a
collision has not converged yet (see below).

### ACK after abandon

An ACK for an abandoned message finds nothing pending:
`ReceiveResult.Acknowledgement(cleared = false)`, the same as a repeated
ACK. Nothing is recreated and nothing is thrown. This is the expected
outcome whenever the recipient finalizes a copy that was sent before the
abandon.

## Concurrency

- **ACK vs abandon:** both remove the same row inside a storage transaction;
  exactly one removal wins. ACK first: `cleared = true`, then abandon
  `NOT_PENDING`. Abandon first: `ABANDONED`, then the ACK `cleared = false`.
- **Abandon vs abandon:** one `ABANDONED`, every other `NOT_PENDING`.
- **Retry vs abandon:** abandon runs under the client's send mutex, like
  `send`, `retryPendingMessages`, ACK sends and `acceptRemoteIdentityChange`,
  so it never runs between the steps of a send or retry: it waits until a
  running one has handed off its envelopes. Retry wins first: the retry
  encrypts and hands off the message, then the abandon removes it; that
  envelope can still be delivered, later retries skip it. Abandon wins first:
  the retry never sees it and never encrypts it. The ratchet state is never
  rolled back; the storage transaction never spans the network hand-off.
- **Retry vs ACK:** unchanged: each retry step reads the next pending message
  after its cursor in its own transaction, so a message acknowledged
  meanwhile is skipped.
- **Pagination under mutation:** see [Pagination](#pagination).

`retryPendingMessages` reads one message per transaction (the next pending
one after the last it sent) and fetches a bundle only when a message waits
and there is no session. It keeps its order and its stop at the first failed
hand-off.

## Collisions and identity changes

A message sent on an initiation that lost a simultaneous-initiation collision
stays pending until the sessions converge and the sender retries
([message-reliability.md](message-reliability.md#collision-recovery-walk-through)).
Abandoned before convergence, it is simply gone: the retry after convergence
does not send it, and the winning session keeps working. The same holds for
messages kept across an accepted identity change.

## Storage

- No new table, column, sealed record type or record format. Abandon deletes
  the existing sealed `pending_outbound_message` row (KSMR record type 5,
  unchanged AD) without opening it; storage key rotation covers the table as
  before.
- Sequence numbers come from `AUTOINCREMENT`, so they are never reused after
  an abandon, also across restarts (in-memory: a high-water mark).
- SQLDelight client schema version 15 (`14.sqm`) adds only the index
  `pending_outbound_message_recipient (recipient_user_id,
  recipient_device_id, sequence)`; frozen fixture `Version14Schema`. The
  milestone 9 plaintext migration (`LegacyPlaintextMigration`), which rebuilds
  the table, recreates the index.
- **Logical deletion only.** An abandon removes the row from the live
  database. SQLite free pages, the WAL or rollback journal, backups and file
  system snapshots can still contain the old sealed record; that is
  ciphertext, not application plaintext, as long as the milestone 9
  protections hold ([storage-encryption.md](storage-encryption.md)). No
  forensic erasure is claimed.

## Limitations

- Abandon is not recall; already sent envelopes may still be delivered and
  finalized.
- The sender cannot know whether the recipient already processed an abandoned
  message.
- No automatic pending expiry, no retry scheduler, no background cleanup: if
  the application never decides, pending sent messages still grow without
  bound.
- No negative ACK and no sender-visible receiver discard reason.
- Logical deletion, not forensic erasure.
- No sealed sender.
