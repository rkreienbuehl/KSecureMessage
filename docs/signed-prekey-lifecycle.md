# Signed prekey lifecycle: rotation, grace period, expiry, pruning

This document describes how a KSecureMessage client rotates its signed
prekeys, how long it keeps replaced ones, and when it deletes them
(milestone 7). It also covers what deletion allows: pruning retired session
initiations.

Code: `client/core/.../client/PreKeyManager.kt`, `PreKeyConfiguration.kt`,
`SecureMessageClient.kt` (`acceptWithLocalPreKeys`).
Storage contract: `PreKeyStore` and `SessionInitiationStore` in
`storage/core/.../storage/ClientStorage.kt`.

Everything here is local lifecycle and storage. Wire v1, the codec vectors,
the X3DH and ratchet info strings, `SessionInitiationId` derivation, the
server and the HTTP API are unchanged.

## Why

A `PreKeyMessage` can be accepted as long as the responder keeps the private
signed prekey it names. Before milestone 7 no signed prekey was ever deleted.
That had two consequences:

- A valid initiation that never reached the device could be withheld and
  released at any later time, and it would still be accepted
  ([session-lifecycle.md](session-lifecycle.md#limitations)).
- Retired session initiations had to be kept forever, because any of them
  could still be replayed successfully.

Deleting a signed prekey's private key after a bounded grace period limits
both.

## States

```
current ──rotate──▶ grace ──grace period over──▶ deleted
```

| State | Stored | Published | Accepts new initiations |
|---|---|---|---|
| current | key pair, `createdAt` | yes (the only one) | yes |
| grace | key pair, `createdAt`, `replacedAt` | no | until `replacedAt + gracePeriod` |
| deleted | nothing (only the ID high-water mark) | no | never |

There is exactly one current signed prekey once `initialize()` ran. A key
whose grace period is over is deleted physically, private key included. No
metadata is kept for it: the ID high-water mark `highestSignedPreKeyId` is
enough to tell that an ID was used before.

### Persisted metadata

Per signed prekey, in addition to the key pair:

- `createdAt`: when it was stored. Drives rotation.
- `replacedAt`: when a newer key became current, which is when the grace
  period started. `null` for the current key.

The current key and the high-water mark are stored as before. Timestamps
are stored as epoch milliseconds, and the client truncates clock readings
to milliseconds, so both adapters decide the same way. The grace deadline is
not stored: it is `replacedAt + signedPreKeyGracePeriod`, so a changed
configuration applies to keys already in grace. All decisions depend only on
persisted timestamps, the configuration and the current clock reading, so
they come out the same after a restart.

## Configuration

`PreKeyConfiguration`:

| Setting | Default | Meaning |
|---|---|---|
| `signedPreKeyRotationAge` | 7 days | `initialize()` rotates a current key this old |
| `signedPreKeyGracePeriod` | 30 days | how long a replaced key keeps accepting new initiations |
| `oneTimePreKeyTarget` | 100 | unchanged |

The defaults are this project's own conservative starting values. They are
not taken from Signal. A long grace period favors delayed first contacts; a
short one narrows the withheld-initiation window. Both are ordinary
constructor parameters and easy to change.

Validation:

- `signedPreKeyRotationAge` must be positive. `Duration.INFINITE` turns
  age-based rotation off; explicit `rotateSignedPreKey()` still works.
- `signedPreKeyGracePeriod` must not be negative.
  - Zero is allowed. A replaced key is refused for new initiations at once
    and deleted on the next `initialize()`. Every first-contact message that
    was in flight at rotation then fails.
  - `Duration.INFINITE` keeps replaced keys forever, the behavior before
    milestone 7.

## Maintenance

`initialize()` runs the lifecycle in its single storage transaction, after
loading or creating the identity:

1. **Stamp keys from before milestone 7** (`stampLegacySignedPreKeys(now)`,
   see [Migration](#migration)).
2. **Rotate.** If there is no current key, or the current key's age
   (`now - createdAt`) has reached `signedPreKeyRotationAge`, create a new
   one. The previous current key gets `replacedAt = now` and enters grace.
3. **Expire.** Delete every non-current key with
   `now - replacedAt >= signedPreKeyGracePeriod`.
4. **Prune.** Remove retired initiations whose signed prekey is deleted (see
   [Pruning](#pruning-retired-initiations)).
5. Refill one-time prekeys (unchanged).

`initialize()` stays idempotent and local. Applications that keep a client
running for a long time call it periodically, for example daily, and call
`publishPreKeys()` after it. Rotation and expiry never do network I/O, and
publication stays explicit.

### Rotation

`rotateSignedPreKey()` (explicit) and step 2 (age-based) do the same thing:

- The new ID is `highestSignedPreKeyId + 1`. Deleting keys never lowers the
  high-water mark, so IDs are never reused. Past `Int.MAX_VALUE` the call
  fails with `PreKeyIdsExhausted` and writes nothing.
- `storeCurrentSignedPreKey(newKey, createdAt = now)` stores the new key,
  makes it current and sets the previous key's `replacedAt` to the same
  instant, all in one transaction.
- The old key is **not** deleted at rotation, even with a zero grace period.
- `currentPreKeyBundle()` returns the new key at once. The server keeps
  serving the old one until `publishPreKeys()` uploads the new one. Only the
  current signed prekey is ever published; keys in grace stay on the device.

### Accepting an initiation

When a `PreKeyMessage` needs a new session (first contact, replacement or a
collision loser that must be authenticated), the client looks up the signed
prekey it names:

| Lookup | Result |
|---|---|
| current, or in grace with `now - replacedAt < gracePeriod` | accepted as before |
| in grace, but the grace period is over (not deleted yet) | `SecureMessageClientException.ExpiredSignedPreKey` |
| not stored, ID ≤ high-water mark (deleted) | `SecureMessageClientException.ExpiredSignedPreKey` |
| not stored, ID above the high-water mark | `ProtocolException.InvalidMessage("Unknown signed prekey")`, unchanged |

`ExpiredSignedPreKey(address, signedPreKeyId)` carries only public values.
Nothing is written: the session, the pin, the one-time prekeys and the
retired set stay as they were. The expiry is checked at lookup, so a key is
refused as soon as its grace period is over, even before maintenance deletes
it.

### Established sessions are not affected

The signed prekey is only needed to accept a new initiation. An established
Double Ratchet session never looks it up again. It keeps working after its
signed prekey expired and was deleted, in both directions and across
restarts. Repeated `PreKeyMessage`s of the **current** initiation (the
initiator repeats until it sees a reply) are decrypted on the existing
session and need no signed prekey either (session-lifecycle step 2). Expiry
never removes or replaces a session.

### Clock

Time comes from the `clock: kotlin.time.Clock` constructor parameter of
`SecureMessageClient`, `Clock.System` by default. Tests pass a manual clock
and never sleep.

Wall clocks can move backwards. The rules are:

- A negative age is never due. A clock set back neither rotates nor expires
  anything, so it can only lengthen the grace period (and delay rotation) by
  as much as it was set back.
- Deletion is final. A deleted key is physically gone, its ID stays at or
  below the high-water mark and is never allocated again, and no code path
  recreates it. Setting the clock back never makes an expired initiation
  acceptable again.
- Stored timestamps are never rewritten. A key rotated while the clock was
  behind keeps the earlier `replacedAt`.

There is no secure or monotonic clock. A device whose clock is manipulated
can keep keys longer than configured.

## Pruning retired initiations

Milestone 6 retires initiations whose session was replaced and initiations
that lost a collision, and rejects them for good
([session-lifecycle.md](session-lifecycle.md#replay-and-rollback-protection)).
Milestone 7 removes an entry once the initiation can no longer be accepted
anyway.

### What is stored

`SessionInitiationStore.retire(remote, id, signedPreKeyId)` records the
**local** signed prekey the retired initiation was accepted with:

| Retired because | `signedPreKeyId` |
|---|---|
| lost a collision | the ID in the losing `PreKeyMessage`. It is authenticated: the client accepted the message before retiring it. |
| its session was replaced, and this device had accepted that session as responder | `SessionInfo.acceptedSignedPreKeyId` of the replaced session |
| its session was replaced, and this device had initiated it | `null`: the signed prekey is the remote device's, not a local one |
| retired before milestone 7, or replaced session stored before milestone 7 | `null` |

To know the signed prekey of a replaced responder session, the local session
state gained format version 3. It stores `acceptedSignedPreKeyId` after the
origin. Version 1 and 2 states stay readable, with `null`. This is local
persistence only, not wire format.

```
v3: version=0x03 | associatedData | pending | origin flag:u8 [| id[32]] | accepted flag:u8 [| signedPreKeyId:u32] | ratchet
```

`SessionInitiationId` is unchanged. The signed prekey ID is lifecycle
metadata next to it.

### Rule

Maintenance step 4 removes all entries naming signed prekey `S` when `S` is
at or below the high-water mark and no longer stored. That means the key was
deleted, and it can never come back. Entries naming a stored key (current or
in grace) and entries with `null` are kept.

### Why this is safe

Replaying retired initiation `R` after its entry is gone goes through
`receivePreKeyMessage` (session-lifecycle steps 1–8):

1. The identity check is unchanged: a different identity still fails first.
2. "Same initiation as the current session" cannot match. `R` was retired, so
   it is not the current origin, and the only way it could become current
   again is by accepting it, which is exactly what fails below.
3. The retired check no longer triggers. That is the pruning.
4. The remaining branches either decrypt on the existing session or accept a
   new one:
   - Decrypting on the existing session fails. The engine rejects a
     `PreKeyMessage` of another initiation when the session has an origin,
     and every session stored after a retirement has one, so step 6 (no
     origin) cannot apply. Step 5 (no pin) cannot apply either: retirement
     required a pin, and pins are never removed.
   - Accepting (`acceptSession`, or `rejectLosingInitiation` for a collision)
     always calls `acceptWithLocalPreKeys`. That needs the private signed
     prekey the message names. X3DH on the responder uses the signed prekey
     in DH2 and DH3 and as the first ratchet key, with or without a one-time
     prekey.
5. The signed prekey ID is an input of `SessionInitiationId`, so `R` always
   names the same `S`. `S` is deleted, and its ID is never allocated again,
   so the lookup fails with `ExpiredSignedPreKey` and nothing is written.

A one-time prekey being consumed is **not** a sufficient condition:
initiations without a one-time prekey exist. That is why pruning keys off
the signed prekey only.

Deletion and pruning run in the same transaction. If that transaction fails,
both roll back. Because the sweep removes entries for any deleted key, not
only for keys deleted in this run, a missed prune is repaired on the next
`initialize()`. An entry left without its key would only be redundant, never
unsafe.

### What stays

- Entries with `null`: initiations this device started, and entries from
  before milestone 7. These still grow, by one per replacement of a session
  this device initiated.
- Entries whose signed prekey is current or in grace.
- The current session's origin is never touched. Pruning only removes
  retired entries.

## Migration

`storage:sqldelight` schema version 4 (`3.sqm`) only adds nullable columns:

```sql
ALTER TABLE signed_pre_key ADD COLUMN created_at INTEGER;
ALTER TABLE signed_pre_key ADD COLUMN replaced_at INTEGER;
ALTER TABLE retired_session_initiation ADD COLUMN signed_pre_key_id INTEGER;
```

Existing identities, signed and one-time prekeys, the current key, both
high-water marks, sessions, pins and retired initiations are kept, and
nothing is recreated. Upgraded rows have `NULL` timestamps and a `NULL`
signed prekey ID.

The first `initialize()` after the upgrade applies a conservative policy
(`stampLegacySignedPreKeys(now)`):

- The current key gets `createdAt = now`. Its rotation age starts at the
  upgrade.
- Every older retained key gets `createdAt = now` and `replacedAt = now`. It
  enters a full grace period that starts at the upgrade.
- Nothing is deleted on the first start. Delayed messages that name old keys
  keep working for one grace period.
- Retired initiations from before the upgrade keep `NULL` and are never
  pruned.

Until that first `initialize()`, an unstamped key is treated as not expired.
`storage:inmemory` always records timestamps.

## Limitations

- **Withheld initiations inside the grace window.** A valid initiation
  withheld by the server is still accepted while the signed prekey it names
  is current or in grace. M7 bounds the window to roughly
  `rotationAge + gracePeriod` after the bundle was fetched (37 days with the
  defaults, longer if `initialize()` runs rarely or the clock is set back).
  It does not close it.
- **No authenticated freshness.** Wire v1 carries no epoch, counter or
  timestamp. Nothing here proves that an initiation is recent.
- Rotation and expiry only happen when `initialize()` or
  `rotateSignedPreKey()` runs. Lookup refuses expired keys regardless.
- Publication after rotation is explicit. Until `publishPreKeys()` runs, the
  server serves the previous key, and its initiations use up that key's
  grace period.
- Retired initiations with `null` are not pruned.
- No secure clock.
