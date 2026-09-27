# Delayed recovery key reset (lost offline recovery key)

Milestone 23. This document covers the **exceptional** replacement of a
user's offline last-device recovery key R1 (M18, docs/last-device-recovery.md)
when R1 is **lost** while it is still active.

Normal rotation (M19, docs/recovery-key-lifecycle.md) stays the preferred
path. It needs a registered device, R1's signature and the new key's proof of
possession, and it applies immediately. A delayed reset cannot use R1,
because R1 is gone. It is therefore weaker, and it must never become a
shortcut around rotation. It compensates for the missing R1 with a
server-enforced delay, visibility to every device of the user, and
cancellation by any device or by R1 itself.

Code:

- Statements, signatures and IDs:
  - `core/protocol/.../protocol/RecoveryKeyReset.kt`:
    `RecoveryKeyResetCompletionStatement` / `…Authorization`,
    `RecoveryKeyResetCompletionId`, `RecoveryKeyResetCancellationStatement` /
    `…Authorization`, `RecoveryKeyResetStatusQueryStatement` / `…Query`, and
    `RecoveryKeyReset`;
  - the domains in `ProtocolConstants`;
  - `ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET`, `…_COMPLETION`,
    `…_CANCELLATION`, `…_STATUS` and `ServerApiPaths.user`.
- Model: `core/model/.../model/RecoveryKeyResetStatus.kt`
  (`RecoveryKeyResetId`, `RecoveryKeyResetStatus.None` / `.Pending`).
- Server contract, in `storage/core/.../storage/ServerStorage.kt`:
  - `LastDeviceRecoveryRepository.pendingRecoveryKeyReset`,
    `requestRecoveryKeyReset`, `completeRecoveryKeyReset`,
    `cancelRecoveryKeyReset`;
  - `RecoveryKeyResetRequest` / `…Result`,
    `RecoveryKeyResetCompletionTransition` / `…Result`,
    `RecoveryKeyResetCancellation` / `…Authority` / `…Result`;
  - `RecoveryKeyState.resetCompletionId`.
- Server logic:
  - `server/core/.../server/RecoveryKeyResetService.kt`
    (`RecoveryKeyResetPolicy`, `RecoveryKeyResetException`,
    `RecoveryKeyResetRequestOutcome`, `RecoveryKeyResetCompletionOutcome`);
  - `SecureMessageServer(storage, clock, recoveryKeyResetPolicy)` and its
    `requestLastDeviceRecoveryKeyReset`, `lastDeviceRecoveryKeyResetStatus`,
    `lastDeviceRecoveryKeyResetStatusByRecoveryKey`,
    `completeLastDeviceRecoveryKeyReset`, `cancelLastDeviceRecoveryKeyReset`,
    `cancelLastDeviceRecoveryKeyResetByRecoveryKey`;
  - `ProtectedEndpoint.REQUEST_/READ_/COMPLETE_/CANCEL_LAST_DEVICE_RECOVERY_KEY_RESET`.
- HTTP: `server/ktor/.../KSecureMessageRoutes.kt` and
  `client/ktor/.../KtorSecureMessageTransport.kt`.
- Client: the `SecureMessageClient` functions listed under [Client API](#client-api),
  `LastDeviceRecoveryKeyResetResult`,
  `LastDeviceRecoveryKeyResetCancellationResult`,
  `SecureMessageClientException.LastDeviceRecoveryKeyResetNotPending` and
  `SecureMessageTransportException.RecoveryKeyResetRejected`
  (`RecoveryKeyResetFailure`).

## Security model

**What protects a reset:**

- **An authenticated device of the same user** requests it and completes it,
  each time with ServerAuth v1 signed by its registered device
  authentication key. The completing device need not be the requesting one.
- **A server-enforced delay.** The request time is the server's clock, and
  the eligibility time is request time + the host's policy delay. No request
  field chooses either. A repeated request never restarts or shortens the
  delay.
- **Visibility.** Every registered device of the user can read the pending
  reset (requester, times, the key and epoch it replaces) through a signed
  status. So can the holder of R1, through a query signed by R1 that needs no
  device.
- **Veto.** Until the completion commits, any registered device of the user
  can cancel the reset, and so can R1 alone, without any device. Eligibility
  only allows a completion. It never completes anything, and cancelling after
  the eligibility time still works.
- **The new key R2 proves possession** over a statement bound to the exact
  reset, the replaced key and epoch, both times and the completing device.
- **Binding to the old state.** A completion applies only while the recovery
  key is still exactly the ACTIVE key and epoch the reset was requested for.
  Any other recovery key transition (rotation, revocation, registration)
  removes the pending reset in the same transaction.

**What it does not protect against.** The delay does **not** replace
possession of R1. Consider an attacker who controls a registered device of
the user long enough to both request and complete a reset. If no legitimate
device or R1 holder notices and cancels during the delay, that attacker
replaces the offline recovery authority. M23 mitigates only the *immediate*
takeover of that authority by a compromised device. It relies on
applications surfacing the pending reset and on users acting on it. There is
no quorum, no per-device acknowledgement and no human or account identity
proof.

Because R1 stays authoritative during the delay, a holder of a *leaked* R1
can still do everything R1 can (M18 recovery, M19 rotation, and here: cancel
the reset). That is unchanged from M19.

## Policy and clock

```kotlin
SecureMessageServer(storage, clock, recoveryKeyResetPolicy = RecoveryKeyResetPolicy(delay = 3.days))
```

- **The delay:**
  - it must be positive and finite;
  - it is rounded up to whole milliseconds;
  - `requestedAt + delay` must be representable, else the request fails
    closed.
- **No default.** Without a policy (`null`, the default), requests are
  refused with `404 recovery_key_reset_not_available`. An already pending
  reset (for example after the host removed the policy) can still be read,
  cancelled and completed.
- **Choosing the delay.** Choose it to match how often the application checks
  the status. The library ships no universal value.
- **Timing:** `requestedAt = server now` and
  `eligibleAt = requestedAt + delay`, both from the server's injected
  `Clock`. The ServerAuth timestamp only authenticates the request.
- **Eligibility boundary:** `now < eligibleAt` refuses the completion
  (`409 recovery_key_reset_not_yet_eligible`), and `now == eligibleAt`
  allows it.
- **Clock jumps.** This is wall-clock time, as everywhere else in the library.
  If the server clock moves backwards, eligibility comes later. If it jumps
  forward, a reset can become eligible early in real elapsed time. There is no
  monotonic persistence.
- **Restarts.** A restart does not restart the delay: both times are stored.
- **No scheduler.** Nothing happens automatically at `eligibleAt`.

## State machine

```text
ACTIVE R1/N
  │ request (device, ServerAuth)                         epoch unchanged, M18 challenges kept
  ▼
PENDING RESET(id, R1/N, requestedBy, requestedAt, eligibleAt)
  ├── cancel (device ServerAuth, or R1 signature)  → ACTIVE R1/N   epoch unchanged, challenges kept
  ├── M19 rotation / revocation / registration     → reset removed in the same transaction
  └── now ≥ eligibleAt + completion (device ServerAuth + R2 PoP)
        → ACTIVE R2/N+1   installedAt = completion time, all M18 challenges removed
```

- **One pending reset per user.** Concurrent requests converge: the first
  creates it, and every other request returns it unchanged (ID,
  requester, times).
- **Preconditions of a request:**
  - UNCONFIGURED and REVOKED: `404 recovery_key_not_configured`. Use normal
    registration instead.
  - Epoch `Long.MAX_VALUE`: `409 recovery_key_epoch_exhausted`, because a
    completion could never apply.
- **After a cancellation**, a new request creates a new reset with a new ID
  and a full delay.
- **After a completion**, a later lost-key reset of R2 starts a new full
  delay.
- **Terminal transitions are immutable.** After the completion, R1 can
  neither cancel (`404 recovery_key_reset_not_pending`) nor roll anything
  back.

## Formats (version 1, frozen)

Integers are big-endian and strings are `u32 length | UTF-8`. Each
construction prefixes `u32 length | domain (UTF-8)`.

The completion statement:

```text
u32 length | userId
reset ID (16)
expected recovery key epoch: i64 (>= 1)
current recovery public key (32)
new recovery public key (32)          // ≠ current
requestedAt: i64 ms (>= 0)
eligibleAt: i64 ms (> requestedAt)
u32 length | completer userId          // = userId
u32 length | completer deviceId
```

The cancellation statement:

```text
u32 length | userId
reset ID (16)
expected recovery key epoch: i64
current recovery public key (32)
requestedAt: i64 ms | eligibleAt: i64 ms
```

The status query statement:

```text
u32 length | userId
current recovery public key (32)
timestamp: i64 ms                      // ±5 minutes of server time, bounds included
```

| Construction | Domain | Operation |
|---|---|---|
| completion proof of possession | `KSecureMessage-RecoveryKeyReset-NewKeyPoP-v1` | Ed25519 by R2 |
| `RecoveryKeyResetCompletionId` | `KSecureMessage-RecoveryKeyResetId-v1` | SHA-256, 32 bytes |
| cancellation | `KSecureMessage-RecoveryKeyReset-Cancel-v1` | Ed25519 by R1 |
| status query | `KSecureMessage-RecoveryKeyResetStatusQuery-v1` | Ed25519 by R1 |

**Reset ID** (`RecoveryKeyResetId`):

- 16 bytes from the server's `SecureRandom`;
- not secret, but never printed;
- canonical text form is strict Base64url (22 characters); on the wire it is
  standard Base64.

**Completion ID** (`RecoveryKeyResetCompletionId`):

- recorded as `reset_completion_id` in the recovery key state, alongside
  `rotation_id` / `revocation_id`; at most one of the three is set;
- used for exact-retry detection only, never as an authorization;
- it names the completion, not the pending reset.

**Replay:**

- **Completion and cancellation** are single-use through the reset: the reset
  row is deleted when either commits, and a new reset gets a new ID. No
  statement nonce is persisted. The ServerAuth nonce of the device routes is
  claimed as for every protected request.
- **The status query** is read-only and has no nonce. A captured query can be
  replayed within its 5-minute window. That reveals only the response it
  already revealed.

**Domain separation.** No domain is shared with ServerAuth v1, DeviceRecovery
v1, DeviceAuthRotation v1, LastDeviceRecovery v1 (including its key PoP),
RecoveryKeyRotation v1 (both), RecoveryKeyRevocation v1, SafetyNumber v1 or
the storage domains. `core:protocol` `RecoveryKeyResetTest` checks both
directions.

**Frozen vectors.** They are in `RecoveryKeyResetTest`. They were computed
independently with Python `struct`, `hashlib` and `cryptography`'s Ed25519,
by a script that first reproduced the frozen M19 rotation vector.

- Completion cases: base, other user, other completing device, other reset
  ID, other current key, other new key, other epoch, other requestedAt, other
  eligibleAt, UTF-8.
- Cancellation cases: base, other user, other reset ID, other epoch, other
  key, other requestedAt, other eligibleAt, UTF-8.
- Status query cases: base, other user, other key, other timestamp, UTF-8.

## Server checks

- **Request.** ServerAuth, then the policy (`not_available`), then one atomic
  storage step:
  1. an ACTIVE key exists (`not_configured`);
  2. the requester's registration is unchanged (`conflict`);
  3. an existing reset is returned unchanged;
  4. the epoch is not exhausted;
  5. the reset is inserted, bound to the key and epoch read **in this
     step**.

  A rotation that commits first therefore makes the reset bind the new key.
- **Status.** ServerAuth by any registered device of the user. Returns the
  user's pending reset or `none`. Other users see only their own.
- **Status by recovery key.** A public route:
  1. an active key exists (`not_configured`);
  2. the query's key is that key (`invalid_proof`);
  3. the timestamp is inside the window (`expired`);
  4. the signature verifies with the **registered** key (`invalid_proof`).
- **Completion.** Checked in this order; nothing is changed before the last
  step:
  1. ServerAuth; the statement's completer is the authenticated device
     (`invalid_recovery_key_reset`);
  2. a state exists;
  3. **exact retry**: `reset_completion_id` is this statement's ID and the
     active key is R2; the proof is verified and the result is `204` with no
     write;
  4. the key is active;
  5. a reset with this ID is pending (`not_pending`);
  6. the statement's key, epoch and times are the reset's, and the state is
     still that key and epoch (`conflict`);
  7. `now >= eligibleAt` (`not_yet_eligible`);
  8. the R2 proof of possession verifies (`invalid_proof`);
  9. one atomic storage step repeats every comparison, including the
     completer's registration (key and auth epoch). On `CONFLICT` or
     `NOT_PENDING` the exact retry is re-checked on fresh state.
- **Device cancellation.** ServerAuth, then one atomic step: the reset with
  this ID is pending, and the device's registration is unchanged.
- **Recovery key cancellation.** A public route:
  1. a reset with this ID is pending (`not_pending`);
  2. the statement's key, epoch and times are the reset's (`conflict`);
  3. R1's signature verifies with the reset's (= registered) key
     (`invalid_proof`);
  4. one atomic step, which again requires the state to be exactly that key
     and epoch.

## Atomic storage steps

The in-memory adapter runs every step under the one authentication mutex.
The SQLDelight adapter runs each one as one SQLite transaction under its
instance mutex, never with `INSERT OR REPLACE`.

**Completion** uses the M19 compare-and-set helper:

1. a guarded `UPDATE … WHERE state AND epoch AND public_key IS expected`
   writes R2, `epoch + 1`, `installed_at = transitioned_at = now` and
   `reset_completion_id`, and clears `rotation_id` / `revocation_id`;
2. every last-device recovery challenge of the user is deleted;
3. the reset row is deleted.

**Every other recovery key transition** (rotation, revocation, first
registration, registration after revocation) also deletes the user's reset
row in its transaction.

**Cancellation** deletes only the reset row. The recovery key state, its
epoch and the challenges are untouched. No tombstone is kept.

**Invariant.** A pending reset always refers to the current ACTIVE key and
epoch. Reading it (`pendingRecoveryKeyReset`) checks this in the same step
and fails closed if it does not hold; that could only happen through tampering.

## Interaction with last-device recovery (M18)

- **Request and delay:** challenges stay valid, and R1 still recovers devices
  during the delay. A device recovery never touches the reset.
- **Cancellation:** challenges stay valid.
- **Completion:**
  - every challenge of the user is deleted atomically;
  - an R1 recovery statement fails (`401 last_device_recovery_proof_invalid`,
    or `404 …_not_configured` at storage);
  - new challenges bind R2 at epoch N+1.
- **Races** (both orders tested):
  - A device recovery of **another** device first: the completion still
    succeeds. The recovery key state did not change.
  - A device recovery of the **completing** device first: the completion
    fails (`conflict`), because the completer's registration changed. It
    succeeds when resubmitted with the new registration.
  - The completion first: the R1 recovery fails.

## Interaction with rotation and revocation (M19)

- **Rotation R1 → R3** (R1 was found again) removes the pending reset in the
  same transaction. A later completion is `not_pending` and never overwrites
  R3.
- **Revocation** removes it too. A completion then gets `not_configured` or
  `not_pending`.
- **Registration after revocation** starts without any reset. None could
  survive the revocation anyway.
- **Completion vs rotation or revocation:** exactly one wins (compare-and-set
  on key and epoch). The loser gets `conflict` or `not_pending`, and nothing
  rolls back.

## Concurrency (tested)

| Race | Result |
|---|---|
| 32 identical requests | one `Created`, 31 `Existing`, same ID and times; the delay starts once |
| two devices request at once | one reset; both observe it |
| completion vs device cancellation | exactly one wins |
| completion vs R1 cancellation | exactly one wins |
| completion vs rotation | exactly one wins; no stale overwrite |
| completion vs revocation | exactly one wins |
| completion vs last-device recovery | see above, both orders, same and other device |
| request vs rotation | the reset binds the post-rotation key, or the rotation removes it |
| cancellation vs rotation | both may succeed; no rollback |

These races are tested:

- in the storage contract (in-memory, SQLDelight in-memory, file-backed
  SQLite), with `Dispatchers.Default`;
- in `server:core`, with gated storage that holds both verified operations
  and releases them in a chosen order.

## Lost responses

- **Request:** the signed status returns the pending reset. A new request
  returns the same reset and never restarts the delay.
- **Completion:**
  - the identical request is `204` (exact retry), with no second epoch and no
    new `installedAt`;
  - the client stores no key; calling `completeLastDeviceRecoveryKeyReset(R2)`
    again reads the key status, finds R2 active and returns `ALREADY_ACTIVE`
    without sending anything;
  - the check uses the active **public key**, not the epoch.
- **Cancellation:** a retry is `404 recovery_key_reset_not_pending`. The
  client returns `NotPending` with the current key status and the current
  reset:
  - same key and epoch: the cancellation took effect;
  - a new key: a completion or rotation won.

  A cancellation never recreates a reset.

## HTTP

| Route | Auth | Success |
|---|---|---|
| `PUT /v1/devices/{u}/{d}/last-device-recovery/key/reset` (empty body) | ServerAuth | `201` created, `200` existing; body = status |
| `GET …/last-device-recovery/key/reset` | ServerAuth | `200` status |
| `PUT …/last-device-recovery/key/reset/completion` | ServerAuth + R2 PoP in body | `204` completed or exact retry |
| `PUT …/last-device-recovery/key/reset/cancellation` `{"resetId"}` | ServerAuth | `204` |
| `POST /v1/users/{u}/last-device-recovery/key/reset/status` `{"publicKey","timestamp","signature"}` | R1 signature only | `200` status |
| `PUT /v1/users/{u}/last-device-recovery/key/reset/cancellation` `{"resetId","publicKey","recoveryKeyEpoch","requestedAt","eligibleAt","signature"}` | R1 signature only | `204` |

The completion body is `{"resetId","currentPublicKey","newPublicKey","recoveryKeyEpoch","requestedAt","eligibleAt","newKeyProofOfPossession"}`.
The route's device is the completer.

The status body is:

```json
{"state":"none|pending","resetId":…,"requestedByDevice":…,"requestedAt":…,"eligibleAt":…,"recoveryKeyEpoch":…,"recoveryPublicKey":…}
```

Every field is always present, and `null` unless `pending`. The requester is
a device of the route's user.

Errors:

| Status | Code |
|---|---|
| 400 | `invalid_recovery_key_reset` |
| 401 | ServerAuth codes |
| 401 | `recovery_key_reset_invalid_proof` |
| 401 | `recovery_key_reset_expired` |
| 404 | `recovery_key_reset_not_available` |
| 404 | `recovery_key_not_configured` |
| 404 | `recovery_key_reset_not_pending` |
| 409 | `recovery_key_reset_not_yet_eligible` |
| 409 | `recovery_key_reset_conflict` |
| 409 | `recovery_key_epoch_exhausted` |
| 500 | `internal_error` |

Logs carry the user or address and the outcome only, never keys, signatures,
reset IDs or bodies. The public M18 challenge route reveals nothing about
resets. ServerAuth v1 and every M18/M19 route are unchanged.

## Client API

```kotlin
// R1 is lost. Any registered device:
val reset = client.requestLastDeviceRecoveryKeyReset()      // RecoveryKeyResetStatus.Pending; again = same reset
warnUser(reset)                                              // the application's job, on every device

// Every device, periodically (the library never polls):
when (val s = client.lastDeviceRecoveryKeyResetStatus()) { … }

// Veto by a device, or by the holder of R1 without any device:
client.cancelLastDeviceRecoveryKeyReset(reset)
client.lastDeviceRecoveryKeyResetStatus(r1)                  // works before initialize() / without a device key
client.cancelLastDeviceRecoveryKeyReset(r1, reset)

// After reset.eligibleAt (server time):
val r2 = client.createLastDeviceRecoveryKey()
showToUserForOfflineBackup(r2.encode()); awaitUserConfirmedBackup()   // BEFORE completing
client.completeLastDeviceRecoveryKeyReset(r2)               // COMPLETED | ALREADY_ACTIVE
```

- **Explicit only.** Nothing is called implicitly: not by `initialize`,
  `send`, `receive`, registration or recovery. There is no scheduler and no
  automatic waiting.
- **Nothing stored.** The client stores nothing new: no schema change, and no
  pending-reset key slot. The application backs up R2 before completing, as
  for a rotation.
- **Device functions** run under `deviceAuthenticationMutex` with this
  device's active key, never inside a storage transaction.
- **R1 functions** need no device key.
- **Local refusals:**
  - `LastDeviceRecoveryKeyNotConfigured`: no active key;
  - `LastDeviceRecoveryKeyResetNotPending`: no pending reset;
  - `IllegalArgumentException`: R2 is the key being reset, or an R1 that is
    not the reset's key is used to cancel.

## Persistence and migration

Server schema version 7 (`6.sqm`, `server_storage.format` = 7):

1. It rebuilds `last_device_recovery_key_state`, because SQLite cannot change
   a CHECK in place:
   - adds `reset_completion_id`;
   - the CHECK allows at most one of `rotation_id` / `revocation_id` /
     `reset_completion_id`, and no reset ID when revoked;
   - every row is copied unchanged, with `reset_completion_id` NULL; no time is
     invented.
2. It creates `last_device_recovery_key_reset`:
   - `user_id` PK;
   - `reset_id` UNIQUE, 16 bytes;
   - `requested_by_device`;
   - `expected_epoch` ≥ 1;
   - `expected_public_key`, 32 bytes;
   - `requested_at` < `eligible_at`.

   It starts empty.
3. All other tables stay unchanged.

`open` refuses formats 1–6. The frozen fixture is `ServerVersion6Schema`. The
fresh schema, the migrated schema and the rebuilt table's DDL are compared,
and the CHECK constraints are tested on both.

The server never stores private recovery material: only public keys,
signatures are verified and dropped. The SQLite file and every column are
scanned for the R1/R2 seeds in `SqlDelightServerRecoveryKeyResetTest`.

## Preservation

A reset operation changes only the recovery key state row, the reset row, the
user's M18 challenges (completion only) and, through ServerAuth, one request
nonce. Nothing else changes:

- messaging identity;
- TOFU pins, verification and safety numbers;
- sessions;
- prekeys and one-time prekey tombstones;
- mailbox;
- pending outbound, pending inbound, processed and discarded inbound
  messages;
- device authentication keys, epochs and installation times;
- storage keys.

## Limitations

- **Weaker than rotation.** It is weaker than normal R1-authorized rotation:
  the delay does not replace possession of R1.
- **A surviving compromised device wins.** A compromised registered device
  that survives the delay without anyone cancelling can reset the recovery
  authority.
- **Visibility is not push.** Status visibility is not push notification;
  applications must check and surface the reset state themselves.
- **Wall clock.** Wall-clock jumps change the effective delay.
- **R1 stays powerful.** R1 keeps its full power during the delay (M18
  recovery, rotation, cancellation).
- **No quorum.** There is no quorum and no per-device acknowledgement.
- **No identity proof.** There is no human or account ownership proof and no
  admin override.
- **No recovery of anything else.** There is no messaging identity or session
  recovery, and no automatic completion.
- **No sealed sender.**
