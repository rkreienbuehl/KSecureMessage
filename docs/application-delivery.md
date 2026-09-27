# Application delivery: commit boundary and processed-ID retention

Milestone 20 separates two things milestone 8 treated as one: the client
accepting a message cryptographically, and the application having durably
applied it. A received message now stays pending in client storage until the
application explicitly commits it, is delivered again until then, and is
acknowledged only after the commit. Processed IDs are kept for duplicate
suppression until the application prunes them with an explicit retention
policy.

The guarantee is:

- **at-least-once application delivery until explicit commit**,
- deduplicated protocol handling (one pending entry per sender and logical
  ID; committed IDs acknowledged, not delivered again),
- **an ACK means that the receiving application committed the message.**

Milestone 21 adds a second terminal outcome, explicit discard, and cursor
pagination of pending messages; see [message-discard.md](message-discard.md).
Since then an ACK means that the receiving application durably **finalized**
the message (committed or discarded). The sections below describe the commit
path; everything said about a committed tombstone holds for a discarded one
unless message-discard.md says otherwise.

It is **not** exactly-once processing. The application still owns its own
durable transaction, and there is a gap between that transaction and the
library commit (see [Crash windows](#crash-windows)).

Code: `client/core/.../client/SecureMessageClient.kt` (`decrypt`,
`pendingReceivedMessages`, `commitReceivedMessage`, `pruneProcessedMessages`),
`ReliableMessages.kt`, stores in `storage/core/.../storage/ClientStorage.kt`
(`PendingInboundStore`, `ProcessedInboundStore`),
`core/protocol/.../protocol/ApplicationMessageDigest.kt`. No server, HTTP,
transport, wire or frame change: the ACK frame is the milestone 8 frame, only
its timing and meaning change.

## Lifecycle

```
RECEIVED ──decrypt──> PENDING_APPLICATION_COMMIT ──commitReceivedMessage──> PROCESSED ──> ACK sent
            (one tx: ratchet step + pending)          (one tx: pending removed +          (after the tx,
                                                        processed written)                 outside it)
```

| Phase | Stored | A copy of the same logical message (sender retry) | Same logical ID, other body |
|---|---|---|---|
| RECEIVED (before the receive transaction commits) | nothing | decrypted as new | — |
| PENDING_APPLICATION_COMMIT | sealed frame, sequence, `received_at` | `ReceiveResult.Delivery` again, same `ReceivedMessage` (same sequence and receive time); no second row; **no ACK** | `LogicalMessageConflict`; nothing changes |
| PROCESSED | commit time, sealed body digest | `ReceiveResult.AlreadyCommitted`, no plaintext; **ACK sent again** | `LogicalMessageConflict`, no ACK (legacy rows without digest: treated as the same message) |
| pruned (after retention) | nothing | decrypted as new (see [Retention](#processed-id-retention)) | — |

Every duplicate still advances the ratchet: the sender's retry is a fresh
encryption under a later ratchet state, the logical ID ties the copies
together, and the ratchet is never rewound. A conflict throws inside the
receive transaction, so that ratchet step rolls back like a malformed frame.

## Public API

```kotlin
sealed interface ReceiveResult {
    class Delivery(val message: ReceivedMessage)                         // new or still pending
    class AlreadyCommitted(sender, id, val ackSent: Boolean)             // committed before
    class Acknowledgement(sender, id, val cleared: Boolean)              // unchanged
}
class ReceivedMessage(sender, id, sequence: Long, receivedAt: Instant, plaintext: ByteArray)

suspend fun decrypt(envelope): ReceiveResult
suspend fun pendingReceivedMessages(afterSequence: Long? = null, limit: Int, sender: DeviceAddress? = null): PendingReceivedPage  // M21
suspend fun commitReceivedMessage(message: ReceivedMessage): CommitResult
suspend fun commitReceivedMessage(sender: DeviceAddress, id: LogicalMessageId): CommitResult
class CommitResult(sender, id, status: CommitStatus /* COMMITTED, ALREADY_COMMITTED, ALREADY_DISCARDED (M21) */, ackSent: Boolean)
suspend fun pruneProcessedMessages(policy: ProcessedInboundRetentionPolicy): Int
class ProcessedInboundRetentionPolicy(maxAge: Duration)   // maxAge > 0, INFINITE = keep
```

**Breaking changes.** `ReceiveResult.Message` (returned once, ACKed at once)
and `ReceiveResult.Duplicate` are gone; they are replaced by `Delivery` and
`AlreadyCommitted`. `decrypt` no longer acknowledges new application
messages. A peer that still runs milestones 8–19 interoperates on the wire;
only its ACK semantics are the old ones.

Commit authorization is (sender, logical ID); the plaintext is not an input,
so a caller cannot commit a message by presenting other bytes. A commit of an
ID that is neither pending nor committed (never received, or its processed
entry was pruned) throws `ReceivedMessageNotPending` and changes nothing.
Committing twice is idempotent: `ALREADY_COMMITTED`, and the ACK is sent
again, which helps an application that is unsure whether its first commit
call completed.

Milestone 21 replaced the unbounded list with a page (at most
`PendingReceivedPage.MAX_SIZE` = 100 messages, cursor = the last sequence
seen; see [message-discard.md](message-discard.md#pagination)) and added
`ReceiveResult.AlreadyDiscarded`, `discardReceivedMessage` and
`pendingReceivedMessageCount`.

`pendingReceivedMessages` lists in `sequence` order: the local order in which
this device first accepted pending messages. It is persisted, strictly
increasing and never reused. It is **not** a new messaging order guarantee:
across senders it only reflects local acceptance; per sender, envelopes are
still processed in the transport order of [transport-ordering.md](transport-ordering.md).
Returned plaintext is always a copy.

## Transactions

Receive (one client storage transaction, inside `decrypt`):

1. session handling of milestones 5–7 (decrypt, identity checks, session
   acceptance or replacement, OTPK removal);
2. decode the frame;
3. processed? → compare digest, `AlreadyCommitted`;
4. pending? → open the stored frame, compare the body in constant time,
   `Delivery` of the stored message;
5. else store the frame as pending inbound (`received_at` = client clock,
   whole milliseconds) and store the advanced session.

`Delivery` is returned only after that commit. No ACK.

Commit (one transaction): load the pending message, compute its digest,
remove it, write the processed entry (digest, `committed_at` = client clock).
Either both writes happen or neither: a failure keeps the message pending and
unprocessed (`MessageReliabilityAtomicityTest`). Only after the commit, the
ACK is encrypted on the existing session and handed to the transport, under
the send mutex, outside any storage transaction. An ACK failure never undoes
the commit: `ackSent = false`, the processed entry stays, the pending entry
stays removed.

All receive and commit steps run as storage transactions, which the adapters
serialize, so concurrent duplicate receives converge on one pending row, two
concurrent commits give one `COMMITTED` and one `ALREADY_COMMITTED`, and a
commit racing a retry yields either "redelivered, then ACK by the commit" or
"ACK only" (`ApplicationDeliveryTest` concurrency tests).

## Recommended application flow

```
Delivery received (decrypt or pendingReceivedMessages)
  → open the application's own durable transaction
  → apply the change idempotently, keyed by (sender DeviceAddress, LogicalMessageId)
  → commit the application transaction
  → commitReceivedMessage(sender, id)
```

A message the application can never apply is discarded instead of committed
([message-discard.md](message-discard.md#recommended-application-flow)); a
temporary failure leaves it pending.

On start, call `initialize()`, then page through `pendingReceivedMessages`
and process what is there: a message persisted before a crash stays there even if its
sender never retries. The library cannot make the application's database and
its own storage commit atomically; a future adapter or callback bridge could,
milestone 20 does not.

## Crash windows

Receiver:

| Crash point | State | What happens next |
|---|---|---|
| Before the receive transaction commits | nothing persisted | the sender's retry (or the same envelope, if the application kept it) decrypts again |
| After the receive commit, before `Delivery` reached the application | pending | `pendingReceivedMessages` after restart, and every sender retry, deliver it again |
| After `Delivery`, before the application's own commit | pending | delivered again; the application applies it for the first time |
| After the application's commit, before `commitReceivedMessage` | pending | **delivered again**; the application must recognize (sender, ID) as applied; this is why there is no exactly-once promise |
| After the library commit, before the ACK was handed off (or the ACK is lost) | processed | no redelivery; the sender keeps the message pending, its retry is answered with `AlreadyCommitted` and a new ACK |

Sender: unchanged from [message-reliability.md](message-reliability.md#crash-windows),
except that a message now stays pending until the recipient's application
commits it, which can take longer. There is still no automatic retry.

## ACK meaning

After milestone 20, an ACK for M from B means: B decrypted M on a session
authenticated by B's pinned identity, the frame was valid, and **B's
application called `commitReceivedMessage` for M** (now or earlier). Since
milestone 21 the last part reads: B's application durably finalized M, by
`commitReceivedMessage` or `discardReceivedMessage`, and B will not
redeliver it; A cannot tell which ([message-discard.md](message-discard.md#ack-meaning)). It is
not a read receipt. The ACK frame format (SecurePayload v1, type 0x02) is
unchanged. Retries before the commit are never acknowledged, so the sender's
pending entry survives until the application commit.

## Same logical ID, different body

A correct sender never reuses a logical ID for another body. If it happens
(bug or attack by a peer holding the session):

- **before the commit:** the retry's body is compared with the stored pending
  body (constant time). A difference throws `LogicalMessageConflict`; the
  pending body is not overwritten, nothing is processed or acknowledged, and
  the ratchet step of the offending envelope rolls back.
- **after the commit:** the processed entry keeps
  `ApplicationMessageDigest` of the committed body; a different digest throws
  `LogicalMessageConflict` without ACK. An ACK is sent only for the same body.
- **legacy entries** (committed before milestone 20) have no digest; a copy
  with that ID counts as committed and is acknowledged whatever its body.
  This lasts until the entry is pruned.

`ApplicationMessageDigest` v1 = SHA-256(`u32 len | "KSecureMessage-ProcessedMessage-v1" | u32 len | body`),
frozen vectors in `ApplicationMessageDigestTest` (empty body
`7d44197a…caa10`, `"hello"` `ff761c42…26e54`). It is a local storage
construction, never sent.

## Storage

- `PendingInboundStore`: (sender, logical ID) → sequence, `received_at`,
  the SecurePayload ApplicationMessage frame. Unique per (sender, ID); a
  second `store` throws. Never expires.
- `ProcessedInboundStore`: (sender, logical ID) → finalization (M21),
  `finalizedAt`, digest, discard reason (M21). `markCommitted` and
  `markDiscarded` never replace an entry.
- SQLDelight schema version 13 (`12.sqm`): `pending_inbound_message`
  (`sequence` AUTOINCREMENT, sender, `message_id`, `received_at`,
  `sealed_frame`, unique per sender and ID) and
  `processed_inbound_message.committed_at` (indexed) and `sealed_digest`.
- Encryption ([storage-encryption.md](storage-encryption.md)): the pending
  frame is record type 11, the digest record type 12 (`version:u8 = 1 |
  digest[32]`); both bind sender user, sender device and logical ID in the
  associated data, so a record copied to another row or type fails. Frozen
  vectors in `StorageCipherTest`. Sequence, IDs, `received_at` and
  `committed_at` stay plaintext metadata (needed for ordering and pruning).
  A damaged record fails with `StorageEncryptionException` on decrypt of a
  copy, enumeration and commit; it is never treated as missing, deleted,
  processed or acknowledged.
- Storage key rotation re-encrypts both columns (`SEALED_COLUMNS`).
- `InMemoryClientStorage` implements the same contract without encryption
  and without legacy rows.

### Migration

Rows of `processed_inbound_message` from schema version 12 keep their IDs;
`committed_at` and `sealed_digest` are `NULL`. The next `initialize()` stamps
`committed_at` once with the client clock (only `NULL` values, never
rewritten), so legacy IDs get a full retention period from the upgrade on;
entries without a commit time are never pruned. Digests cannot be
reconstructed and stay `NULL`. The migration is a plain SQLDelight migration
and fails or succeeds as a whole; frozen fixture `Version12Schema`.

## Processed-ID retention

`pruneProcessedMessages(ProcessedInboundRetentionPolicy(maxAge))` removes
every processed entry whose age (client clock now − `committedAt`) is at least
`maxAge`: exactly, entries with `committedAt <= now − maxAge`, with `maxAge`
rounded up to whole milliseconds (the stored precision). An age equal to
`maxAge` is pruned; one millisecond less is kept. `Duration.INFINITE` prunes
nothing. There is **no default**: the application chooses the period and when
to call it. Nothing prunes implicitly (not `initialize`, `decrypt`, commit),
there is no scheduler, and pending inbound messages are never pruned.

The clock is the injected client wall clock, not a secure or monotonic timer.
A clock set back computes an earlier cutoff and prunes less (negative ages
keep entries); a clock set forward prunes earlier.

**Security consequence.** After an entry is pruned, a copy of that message is
no longer recognized as committed: it is delivered again as new. The
retention bound is about logical reliability deduplication, not cryptographic
replay protection: the ratchet independently rejects a replayed envelope
(used message keys), so what can come back is a fresh retry by the sender,
not an old ciphertext. Choose a retention longer than any sender keeps
retrying.

## Limitations

- Application side effects are not exactly once; apply messages
  idempotently keyed by (sender, logical ID).
- The commit is an explicit application call; forgetting it keeps the sender
  retrying and the message pending.
- Pending inbound messages grow without bound until the application commits
  or discards them (milestone 21); there is no expiry.
- Processed retention uses the wall clock; old logical IDs are accepted again
  after their retention expired.
- No automatic pruning or retry scheduler; no server-side commit tracking; no
  read receipts; no sealed sender.
- Legacy processed entries have no digest, so a body mismatch for them is
  not detected.
