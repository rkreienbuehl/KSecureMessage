# Session lifecycle: replacement, simultaneous initiation, replay

This document describes what a KSecureMessage client does when a remote device
starts a new session while a session with it already exists (milestone 6).

Code: `client/core/.../client/SecureMessageClient.kt` (`receivePreKeyMessage`),
`core/protocol/.../protocol/SessionInitiationId.kt`, `SessionState.kt`.
Storage contract: `SessionInitiationStore` in `storage/core/.../storage/ClientStorage.kt`.

Identity continuity and session continuity are separate. A device with the
same pinned identity may legitimately set up a new session, for example after
it lost its session state or when both sides start a session at the same
time. A device that presents a different identity key is still rejected with
`IdentityChanged`, before any of the rules below run
([identity-trust.md](identity-trust.md)).

The wire format is unchanged: everything here uses data that wire v1 already
carries ([wire-format.md](wire-format.md)).

## Session initiations

A session initiation is one X3DH key agreement. Wire v1 `PreKeyMessage`s carry
its public inputs: the initiator's identity key and ephemeral key, and the
IDs of the responder's signed prekey and optional one-time prekey. The
responder's identity key is known locally, and the ratchet associated data
binds both identity keys.

The header fields are authenticated only by session acceptance. All of them
feed X3DH, so the first ratchet message decrypts only if they are the values
the initiator used. `decrypt` on an existing session does **not** authenticate
them: the ratchet associated data covers only the two identity keys, so an
attacker could swap the ephemeral key in a repeated `PreKeyMessage` and it
would still decrypt. The client therefore only records an initiation after
`acceptSession` succeeded with it.

### `SessionInitiationId`

A 32-byte identifier for one initiation, `SHA-256` over this encoding:

```
u32 length of domain  | domain = "KSecureMessage-SessionInitiation-v1" (UTF-8, 35 bytes)
initiatorIdentityKey  | 64 bytes
responderIdentityKey  | 64 bytes
ephemeralKey          | 64 bytes (the initiator's X3DH base key)
signedPreKeyId        | u32
oneTimePreKey flag    | u8: 0x00 absent, 0x01 present
[oneTimePreKeyId]     | u32, only if the flag is 0x01
```

All integers are big-endian. Every field has a fixed size, so the encoding is
unambiguous. The domain separator exists only for this purpose. The X3DH and
ratchet HKDF info strings are unchanged. SHA-256 is
`org.kotlincrypto.hash:sha2`, pure Kotlin on all targets, and the code has no
Kodium imports.

The ephemeral key makes the ID unique for each initiation. Two initiations that
name the same one-time prekey, or the same signed prekey, still have different
IDs. The ID is ordered by unsigned lexicographic byte comparison. That order
only breaks ties between competing initiations. It says nothing about which
one is newer.

Frozen vectors (`SessionInitiationIdTest`, computed independently with Python
`hashlib`): initiator key bytes `00..3f`, responder key bytes `40..7f`,
ephemeral key bytes `80..bf`, signed prekey ID 7:

| One-time prekey | ID |
|---|---|
| 42 | `745b4451b3e2779db9dd15f4c3ba749abb1543017356b89497ba24ef5ab55ef0` |
| absent | `e2e3a6c8d278e888b5a8d35e75ba090bb98977612b29d2a9d12ecfcf6c621d2a` |
| absent, identity keys swapped | `2dc699b7e3b54a776f7339de031c6548e45a2a6ae98154d16d85ad231f978787` |

### Session origin

Every session stores the ID of the initiation that created it (its *origin*)
in its local state (`SecureSession.state`, format version 2 and later). The initiator
computes it when it sets up the session, and the responder computes it after
the first message decrypted. Both get the same value.
`ProtocolEngine.sessionInfo(session)` returns the origin and whether the
session is still `awaitingReply`, which is true for an initiator that has not
decrypted anything yet.

## Rules for an incoming `PreKeyMessage`

All steps run in one `ClientStorage.transaction`, in this order. `x` is the
ID of the incoming initiation.

| # | Situation | Result |
|---|---|---|
| 1 | Sender identity differs from the pin | `IdentityChanged`, nothing changes |
| 2 | Session exists and its origin is `x` | decrypt on the existing session: repeated `PreKeyMessage`s of the current initiation, in any order |
| 3 | `x` is retired for the sender | `StaleSessionInitiation`, no crypto, nothing changes |
| 4 | No session | accept `x` (first contact, or after local session loss) |
| 5 | Session exists but no pin (stored before milestone 5) | decrypt on the existing session only, never replaced |
| 6 | Session from before milestone 6 (no origin) | replaced only if `x` names a one-time prekey that is still stored, otherwise decrypt on the existing session |
| 7 | Own session awaiting reply (origin `c`), `x > c` | collision lost by `x`: authenticate `x`, retire it, `SessionCollision` |
| 8 | Otherwise (established session, or own pending session with `x < c`) | accept `x` and replace the session, retire its origin |

"Accept" runs `ProtocolEngine.acceptSession` with the local prekeys the
message names. A signed prekey whose grace period is over, or that was
deleted, fails with `SecureMessageClientException.ExpiredSignedPreKey`
(milestone 7, see [signed-prekey-lifecycle.md](signed-prekey-lifecycle.md)).
A signed prekey ID that was never issued, or a one-time prekey that is
already consumed, fails with `ProtocolException.InvalidMessage`. A message
that does not decrypt fails too. In all cases nothing is written. Step 7
authenticates the losing initiation the same way, so an expired signed prekey
fails there too and nothing is retired.

After a replacement, `encrypt` uses the new session. If the replaced session
was the local device's own pending initiation, its prekey data is gone with
it, so no more `PreKeyMessage`s are sent for the losing initiation.

## Simultaneous initiation

Alice and Bob trust each other, have no session, and both start one before
either sees the other's first message. Each has an outbound session that is
awaiting reply, and then receives the other's `PreKeyMessage`.

**Rule: the initiation with the smaller `SessionInitiationId` wins.**

Both sides compare the same two IDs. Alice derives her own ID from her
persisted pending prekey data and Bob's from his message. Bob does the same
with the roles swapped. The IDs are computed from the same authenticated
fields on both sides, so the decisions complement each other:

- The side whose own initiation is smaller keeps its session and rejects the
  incoming one (step 7).
- The side whose own initiation is larger accepts the incoming one and
  discards its own (step 8).

The order in which the two `PreKeyMessage`s arrive, timestamps and addresses
play no part. Replies on the winning session must not overtake the losing
`PreKeyMessage`, see [transport-ordering.md](transport-ordering.md). The
pending ID is re-derived from stored state, so a restart between sending and
receiving gives the same decision. Pending sessions stored in the version 1
state format still have the prekey data to derive it. After both messages are
processed, the winner is still awaiting its first reply. Its next messages
are `PreKeyMessage`s of the winning initiation, which the other side decrypts
under step 2. The first message in the other direction completes the switch.

### The losing initiation's messages

A losing `PreKeyMessage` carries an application message. The winner
authenticates it with `acceptSession`, because only an authenticated
initiation may be retired. The resulting plaintext and session state are
wiped and discarded. The winner then retires the initiation and returns
`SecureMessageClientException.SessionCollision(address)` after the
transaction commits. The exception contains no IDs, keys or plaintext. The
current session, the pin and the one-time prekey stay unchanged. Later
`PreKeyMessage`s of the same losing initiation fail with
`StaleSessionInitiation`.

These messages are not delivered and not acknowledged. Since milestone 8 the
sender keeps every application message pending until the recipient's
encrypted acknowledgement arrives, so it can send the lost message again on
the winning session with `retryPendingMessages`, with the same logical
message ID; the recipient delivers it once. See
[message-reliability.md](message-reliability.md#collision-recovery-walk-through).
The collision rule itself is unchanged: no acknowledgement, no processed
marker, plaintext discarded unread.

## Replay and rollback protection

A captured `PreKeyMessage` stays cryptographically valid for as long as the
responder keeps the signed prekey it names. Since milestone 7 that is bounded
by the signed prekey grace period
([signed-prekey-lifecycle.md](signed-prekey-lifecycle.md)), but within it a
replayed old initiation would replace a newer session without protection.

The protection is a persistent set of **retired initiations** per remote
`DeviceAddress` (`ClientStorage.sessionInitiations`). An initiation is retired:

- when its session is replaced (step 8 retires the old origin), and
- when it loses a collision (step 7).

A retired initiation is rejected before any crypto (step 3), whether a
session currently exists or not. The current initiation is never retired, and
its duplicates go to the existing session (step 2), where an already-used
ratchet message fails to decrypt and changes nothing. That is how the
supported repetition of `PreKeyMessage`s (the initiator repeats until it sees
a reply) differs from a replay.

Initiations that used a one-time prekey have a second, independent
protection: accepting them consumed the private one-time prekey, so they
cannot be accepted again.

Retirement is not ordered by age: a random ID says nothing about age, so no
high-water mark is used. The set grows by one entry per session replacement
or lost collision. It does not grow with the number of messages.

Since milestone 7 each entry also records the local signed prekey that
accepting the initiation needs, when known. Once that signed prekey is
deleted after its grace period, the initiation can no longer be accepted
and `initialize()` removes the entry. Entries without a local signed prekey
(initiations this device started, entries from before milestone 7) are kept.
The rule and why it is safe are in
[signed-prekey-lifecycle.md](signed-prekey-lifecycle.md#pruning-retired-initiations).

## Atomicity

Each of these commits in the same transaction as the crypto work, or not at
all:

- **Replacement:** new session, retired old origin, removal of the consumed
  one-time prekey. The pin is already present (step 5).
- **First contact:** new session, one-time prekey removal, pin (unchanged
  from milestone 5).
- **Lost collision:** retired initiation only. The session and the one-time
  prekey are untouched.

`SessionCollision` is thrown after the commit, so the retirement is kept.
Every other failure, including a storage failure in any of the writes above,
rolls back everything: the old session bytes, the pin, the one-time prekeys
and the retired set stay as they were, and the old session keeps working.
`SessionReplacementAtomicityTest` injects failures into each write.

The one-time prekey of a rejected initiation (lost collision, stale, failed
decryption) is never consumed. The server already handed it out, so it will
not be used by anyone else. It remains in the local inventory.

## Persistence and compatibility

Local session state format version 2 appends the origin to version 1.
Version 3 (milestone 7) adds the local signed prekey a responder session was
accepted with, used to prune retired initiations
([signed-prekey-lifecycle.md](signed-prekey-lifecycle.md)):

```
v3: version=0x03 | associatedData | pending | origin flag:u8 [| id[32]] | accepted flag:u8 [| signedPreKeyId:u32] | ratchet
v2: version=0x02 | associatedData | pending | origin flag:u8 (0x00/0x01) [| id[32]] | ratchet
v1: version=0x01 | associatedData | pending | ratchet
```

Kodium's exported ratchet blob is carried unchanged. Version 1 and 2 states
stay readable and are rewritten as version 3 on their next update. A version
2 state has no accepted signed prekey, so its origin is retired without one
and never pruned. Version 1 states:

| Stored before milestone 6 | Behavior |
|---|---|
| Pending initiator session | origin derived exactly from the stored prekey data; collisions work as for new sessions |
| Established session | origin unknown (never guessed); step 6 |
| Session without a pin (before milestone 5) | never replaced (step 5); see [identity-trust.md](identity-trust.md#sessions-from-before-pinning) |

`storage:client:sqldelight` schema version 3 adds the `retired_session_initiation`
table (`2.sqm`, add only). The migration keeps identities, prekeys, sessions
and pins. Schema version 4 (`3.sqm`) adds the nullable `signed_pre_key_id`
column. `storage:client:inmemory` keeps the set in its transactional state.

## Limitations

- **Withheld initiations.** Wire v1 has no authenticated epoch, counter or
  timestamp. An initiation that is valid but has never reached this device
  cannot be recognized as old: for example, a server withholds it and
  releases it after a newer session was set up. It is accepted like a new one
  and replaces the current session (the retired set only covers initiations
  this device has processed). The replaced session's peer may no longer have
  that state, so the result is usually a broken session (denial of service).
  It becomes a confidentiality problem only if the attacker also holds that
  initiation's secrets. A wire v2 epoch would only partly help, because a
  peer that lost its session state has usually lost its counter too.
  Milestone 7 bounds the window: once the signed prekey the initiation names
  is past its grace period, the initiation fails with `ExpiredSignedPreKey`
  ([signed-prekey-lifecycle.md](signed-prekey-lifecycle.md)). Within the
  window (by default up to about 37 days after the bundle was fetched) it is
  still accepted. Wire v1 gives no authenticated freshness.
- **Legacy established sessions.** Their origin is unknown, so it cannot be
  retired when they are replaced. A replay of their original initiation stays
  possible if it did not use a one-time prekey. Step 6 keeps a legacy session
  from being replaced by anything that could be its own initiation.
- **Reordering.** The rules above converge only if, for each (sender,
  recipient) pair, a `PreKeyMessage` is processed before every envelope the
  sender handed to the transport after it. Otherwise a peer's reply on the
  winning session can overtake its losing `PreKeyMessage`. The late message
  then looks like a replacement and is accepted, and the two sides stay on
  different sessions. The client's `send`, the `MailboxRepository` contract
  and the application's receive loop enforce this ordering; see
  [transport-ordering.md](transport-ordering.md). A relay that breaks the
  contract can still cause the split, but only as denial of service.
- **Lost collision messages** are not delivered; they are resent only when
  the sender calls `retryPendingMessages` (milestone 8, see above).
- **Removing a session** with `SessionStore.remove` does not retire its
  initiation.
- The retired set is pruned only for entries tied to a deleted local signed
  prekey. Entries for initiations this device started, and entries from
  before milestone 7, are kept. Collision losers' one-time prekeys stay in
  the local inventory.
- No identity change or reset flow, no safety numbers, no authenticated server
  API, no persistent mailbox, no sealed sender, no encryption at rest.
