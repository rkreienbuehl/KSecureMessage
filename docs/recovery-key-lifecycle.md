# Recovery key lifecycle: rotation and revocation

Milestone 19. This document covers how the offline last-device recovery key
of a user (M18, docs/last-device-recovery.md) is **rotated** (replaced by a
new key) and **revoked** (removed, with no replacement), and how a new key
is registered after a revocation.

In M18 a registered recovery key could never change. A compromised or
unwanted key stayed authoritative forever. M19 closes that gap without
weakening the key.

Code:

- Statements, signatures and IDs:
  - `core/protocol/.../protocol/RecoveryKeyLifecycle.kt`: `RecoveryKeyRotationStatement`,
    `RecoveryKeyRotationAuthorization`, `RecoveryKeyRotationId`,
    `RecoveryKeyRotation`, `RecoveryKeyRevocationStatement`,
    `RecoveryKeyRevocationAuthorization`, `RecoveryKeyRevocationId`,
    `RecoveryKeyRevocation`;
  - the domains in `ProtocolConstants`;
  - `ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_ROTATION` and `_REVOCATION`.
- Status model: `core/model/.../model/LastDeviceRecoveryKeyStatus.kt`.
- Server contract, in `storage/core/.../storage/ServerStorage.kt`:
  - `LastDeviceRecoveryRepository.recoveryKeyState`, `rotateRecoveryKey`,
    `revokeRecoveryKey` and the extended `registerRecoveryKey`;
  - `RecoveryKeyState`, `RecoveryKeyStatus`;
  - `RecoveryKeyRotationTransition` / `…Result`,
    `RecoveryKeyRevocationTransition` / `…Result`;
  - `StoredLastDeviceRecoveryChallenge.recoveryKeyEpoch`;
  - `LastDeviceRecoveryKeyException.EpochExhausted`.
- Server logic:
  - `server/core/.../server/RecoveryKeyLifecycleService.kt`
    (`RecoveryKeyLifecycleException`, `RecoveryKeyRotationOutcome`,
    `RecoveryKeyRevocationOutcome`);
  - `SecureMessageServer.lastDeviceRecoveryKeyStatus` /
    `rotateLastDeviceRecoveryKey` / `revokeLastDeviceRecoveryKey`;
  - `ProtectedEndpoint.READ_LAST_DEVICE_RECOVERY_KEY`,
    `ROTATE_LAST_DEVICE_RECOVERY_KEY`, `REVOKE_LAST_DEVICE_RECOVERY_KEY`.
- HTTP:
  - `server/ktor/.../KSecureMessageRoutes.kt`;
  - `client/ktor/.../KtorSecureMessageTransport.lastDeviceRecoveryKeyStatus` /
    `rotateLastDeviceRecoveryKey` / `revokeLastDeviceRecoveryKey`.
- Client:
  - `SecureMessageClient.lastDeviceRecoveryKeyStatus`,
    `rotateLastDeviceRecoveryKey`, `revokeLastDeviceRecoveryKey`;
  - `LastDeviceRecoveryKeyRotationResult`, `LastDeviceRecoveryKeyRevocationResult`;
  - `SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured` /
    `LastDeviceRecoveryKeyMismatch`.

## Why two authorities

The offline recovery key can replace the server authentication key of every
device of its user (M18). Changing it is therefore at least as sensitive as
using it. A rotation or revocation needs **both** of the following:

- **A currently registered device of the same user.** It sends an ordinary
  ServerAuth v1 request signed with its registered device authentication
  key.
- **The current offline recovery key.** It signs a statement that names
  that exact device, the current key, the recovery key epoch, a timestamp
  and a nonce.

A rotation's new key also proves possession (it signs the same statement
under its own domain). Nobody can rotate to a key they do not hold, for
example a typo or a key the server made up.

What this protects against:

- **A compromised or stolen device alone** cannot change or remove the
  recovery authority. It cannot silently install its own recovery key, and
  it cannot lock the user out of last-device recovery. This is the main
  reason for the design.
- **A leaked recovery key alone** cannot change it through this protocol
  either. There is a caveat, though. Whoever holds the recovery key can
  first take over one of the user's devices with an M18 last-device
  recovery. That replaces the legitimate device's authentication key, which
  the legitimate device notices, because its requests start failing. The
  holder can then satisfy both authorities. The two-authority rule does not
  make the recovery key less powerful than M18 already made it. It makes the
  takeover visible and keeps a device from acting alone.

## No device-only replacement

If the current offline recovery key is **lost**, but devices still work,
M19 offers **no** way to replace it.

- A device alone cannot rotate or revoke the key: both need the current
  key's signature.
- Registration never replaces an active key: `409 last_device_recovery_key_conflict`.

This is deliberate. A device-only reset would let a compromised live device
take over the user's offline recovery authority silently. It was rejected
after the analysis above. A future milestone may add a deliberate,
policy-controlled device-only reset (for example with a delay and
notifications to all devices), but M19 does not.

## State model

The server keeps one recovery key state per user (`RecoveryKeyState`):

```text
UNCONFIGURED                         no row: the user never registered a key
ACTIVE(epoch, publicKey, installedAt, rotationId?)
REVOKED(epoch, revokedAt, revocationId)
```

**Recovery key epoch:**

- It is 1 for a first registration.
- It grows by one with every rotation, every revocation and every
  registration after a revocation.
- It never decreases and never wraps. At `Long.MAX_VALUE` every further
  transition fails closed with `recovery_key_epoch_exhausted`.
- It is independent of any device authentication epoch (`auth_epoch`).
  Device registrations, recoveries and rotations never change it, and
  recovery key transitions never change device state.

**`installedAt`:**

- It is the server time (the server's injected `Clock`, never the
  statement's timestamp) at which the active key was installed, by the
  registration or the rotation.
- Exact retries never refresh it.
- It is kept to support a future recovery key age policy.

**`transitionedAt`:** the server time of the last transition. For a revoked
key it is the revocation time (`revokedAt` in the status).

**Transition metadata:** `rotationId` / `revocationId` identify the
transition that produced the state.

- At most one of them is set.
- A registration clears both.
- They serve exact-retry detection and audit. They are never an
  authorization.

**Distinct states:** "never configured" (no row) and "revoked" (a row with
state 2 and no key) are different states. That keeps the epoch continuous
across a revocation and lets stale transitions be detected.

The server never stores private recovery material. Public keys only: no
seed, no encrypted seed, no MAC key or other value derived from the seed.
Tested: the SQLite file and every column are scanned for the seeds.

## Transitions

| From | Operation | To | Authorization |
|---|---|---|---|
| UNCONFIGURED | registration (M18 endpoint) | ACTIVE(1, R) | ServerAuth + R's registration PoP |
| ACTIVE(n, R) | registration of R again | unchanged, `204` | ServerAuth + PoP |
| ACTIVE(n, R) | registration of another key | unchanged, `409 last_device_recovery_key_conflict` | |
| ACTIVE(n, R1) | rotation R1 → R2 | ACTIVE(n+1, R2) | ServerAuth + R1 signature + R2 PoP |
| ACTIVE(n, R1) | revocation | REVOKED(n+1) | ServerAuth + R1 signature |
| REVOKED(n) | registration (M18 endpoint) | ACTIVE(n+1, R) | ServerAuth + R's registration PoP |
| REVOKED(n) | rotation or revocation | unchanged, `404 recovery_key_not_configured` | |

**Re-registration after a revocation** is explicit and authenticated. It
uses the M18 provisioning request (`PUT …/last-device-recovery/key`,
ServerAuth plus the key's own PoP). The epoch continues (n+1) and is never
reset to 1.

A device alone can register a key only when no key is active: never
configured, or revoked. Reaching the revoked state already needed the
previous key's signature. The library does not keep a list of previously
used keys, so re-registering an old key is possible. It is harmless for old
statements and challenges, because the epoch moved on.

## Rotation protocol (format v1, frozen)

Rotation statement (integers big-endian, strings `u32 length | UTF-8`):

```text
u32 length | userId
u32 length | authorizer userId          // must equal userId
u32 length | authorizer deviceId
current recovery public key (32, Ed25519)
new recovery public key (32, Ed25519)   // ≠ current
expected recovery key epoch: i64 (>= 1)
timestamp: i64, epoch milliseconds (>= 0)
nonce (16)
```

Each construction prefixes `u32 length | domain (UTF-8)`:

| Construction | Domain | Operation |
|---|---|---|
| authorization | `KSecureMessage-RecoveryKeyRotation-v1` | Ed25519 by the current recovery key |
| new key proof of possession | `KSecureMessage-RecoveryKeyRotation-NewKeyPoP-v1` | Ed25519 by the new recovery key |
| `RecoveryKeyRotationId` | `KSecureMessage-RecoveryKeyRotationId-v1` | SHA-256, 32 bytes |

**The statement binds:**

- the user;
- the exact authorizing device;
- the key being replaced (a key other than the registered one never
  verifies);
- the new key;
- the epoch (the state being replaced; a stale statement never matches
  again);
- a timestamp and a nonce (freshness, single use).

**ServerAuth v1** proves, separately and unchanged, that the device is
registered and holds its registered key.

- The request is `PUT /v1/devices/{user}/{device}/last-device-recovery/key/rotation`.
- It is signed by `{device}`. The route's device is the statement's
  authorizing device: the body does not carry it.
- The ServerAuth nonce and the statement nonce are two different random
  values, both claimed under the device.

## Revocation protocol (format v1, frozen)

Revocation statement:

```text
u32 length | userId
u32 length | authorizer userId
u32 length | authorizer deviceId
current recovery public key (32)
expected recovery key epoch: i64 (>= 1)
timestamp: i64, epoch milliseconds
nonce (16)
```

| Construction | Domain | Operation |
|---|---|---|
| authorization | `KSecureMessage-RecoveryKeyRevocation-v1` | Ed25519 by the current recovery key |
| `RecoveryKeyRevocationId` | `KSecureMessage-RecoveryKeyRevocationId-v1` | SHA-256 |

The request is `PUT /v1/devices/{user}/{device}/last-device-recovery/key/revocation`,
ServerAuth-signed by `{device}`. `PUT` with a body is used instead of
`DELETE`, so the signed body works the same way as for every other
endpoint.

## Domain separation and vectors

None of the five domains is shared with ServerAuth v1, DeviceRecovery v1,
DeviceAuthRotation v1, LastDeviceRecovery v1 (including its key PoP),
SafetyNumber v1 or the storage domain. The tests check both directions:
signatures of each of those never verify here, and ours never verify there.

Frozen vectors are in `core:protocol` `RecoveryKeyLifecycleTest`. They were
computed independently with Python `struct`, `hashlib` and `cryptography`'s
Ed25519. The same script first reproduced the frozen M18 vectors (key,
recovery signature and ID).

The rotation vectors cover:

- base;
- another user;
- another authorizer;
- another current key;
- another new key;
- another epoch;
- another timestamp;
- another nonce;
- UTF-8 identifiers.

Each case has the authorization input, the PoP input, the ID and both
signatures.

The revocation vectors cover:

- base;
- another epoch;
- another authorizer;
- another nonce;
- UTF-8 identifiers.

## Server checks

**Before parsing:** ServerAuth v1 as for every protected endpoint (present,
registered, window, signature, nonce claim). The body is authenticated
before it is parsed.

**Then `RecoveryKeyLifecycleService.rotate`, in this order.** Nothing is
changed before the last step.

1. The statement's authorizing device is the authenticated device, which
   also fixes the user. Over HTTP this always holds by construction: a
   statement signed for another device fails as `invalid_proof`.
2. The user has a recovery key state. Else `404 recovery_key_not_configured`.
3. **Exact retry.** If the state's `rotationId` is this statement's ID and
   the active key is the statement's new key, both proofs are verified. The
   current key's signature is checked with the statement's current key,
   which is no longer registered. The result is `204` with no write. This
   check deliberately comes before the freshness window: the user may take
   long to fetch an offline key, and the resubmission writes nothing and
   still needs ServerAuth and both proofs.
4. The key is active. Else `404 recovery_key_not_configured`.
5. The timestamp is within ±5 minutes of server time, bounds included.
   Else `401 recovery_key_rotation_expired`.
6. The active key and epoch are the statement's. Else
   `409 recovery_key_rotation_conflict`.
7. The current key's signature verifies with the **registered** key, and
   the new key's PoP verifies with the new key. Else
   `401 recovery_key_rotation_invalid_proof`.
8. `LastDeviceRecoveryRepository.rotateRecoveryKey`. It is one atomic step.
   If its compare-and-set fails, the exact-retry check of step 3 is repeated
   on fresh state, because an identical submission may have committed in
   between.

**Revocation** follows the same order with a single proof. Its exact retry is
"revoked, and `revocationId` is this statement's".

## Atomic storage step

`rotateRecoveryKey` / `revokeRecoveryKey` run in one SQLite transaction
(SQLDelight) or under the one authentication mutex (in-memory). They share
one private compare-and-set helper per adapter.

1. No state: `NOT_CONFIGURED`.
2. Exact retry (as above): `ALREADY_APPLIED`, no write.
3. `CONFLICT`, no write, if any of these holds:
   - the key is not active;
   - the key or the epoch differ from the expected ones;
   - the new key is the active key;
   - the authorizing device's registration (key and auth epoch) differs
     from the one the ServerAuth request was verified with
     (`AuthenticatedDevice` carries it).
4. The epoch is `Long.MAX_VALUE`: `EPOCH_EXHAUSTED`.
5. Prune nonces older than the window, and claim the statement nonce under
   the authorizing device in the `authentication_nonce` namespace (the same
   namespace as ServerAuth and M16). If it is already claimed: `REPLAY`.
6. Guarded `UPDATE … WHERE user_id AND state AND epoch AND public_key IS
   expected`: the new state, `epoch + 1`, the transition ID and the server
   times.
7. Delete **every** last-device recovery challenge of the user.

Every result except the applied one leaves everything unchanged. A failure
inside the transaction rolls back all of it, including the nonce claim.
Nonces are never cleared.

## Interaction with last-device recovery challenges

Each M18 challenge row now also stores the recovery key epoch it was issued
under (`last_device_recovery_challenge.recovery_key_epoch`).

**On rotation:**

- All outstanding challenges of the user are deleted in the same
  transaction.
- A recovery statement signed with R1 is rejected: the registered key is R2
  (`401 last_device_recovery_proof_invalid`, or `404 …_not_configured` if it
  reaches storage).
- An old challenge signed with R2 is `401 last_device_recovery_challenge_invalid`.
- A new challenge is issued under the new epoch and works with R2.

**On revocation:**

- All outstanding challenges are deleted in the same transaction. They do
  not merely expire.
- New challenge requests get `404 last_device_recovery_not_configured`, and
  so does any outstanding recovery statement.

**On re-registration:**

- Nothing outstanding survives the preceding revocation.
- New challenges are bound to the new epoch.
- A challenge from an older epoch is refused even if it somehow survived.
  The service and the storage both compare the challenge's epoch with the
  current one. This is tested by re-inserting an old challenge behind the
  storage's back.

The frozen LastDeviceRecovery v1 statement and challenge format is
unchanged. The epoch binding is server-side state only.

## Concurrency (one-winner compare-and-set, no last-write-wins)

| Race | Result |
|---|---|
| 32 identical rotation submissions | one `ROTATED`, 31 `ALREADY_APPLIED`; epoch + 1 once |
| 32 rotations R1 → different keys | exactly one winner; the rest `CONFLICT` |
| rotation vs revocation (same state) | exactly one winner; the loser `CONFLICT` |
| rotation vs last-device recovery of **another** device | both can succeed. If the rotation commits first, the recovery (signed with R1) fails with `NOT_CONFIGURED`. If the recovery commits first, the rotation still succeeds: device transitions never change the recovery key state. |
| rotation vs last-device recovery of the **authorizing** device | exactly one winner. Rotation first: the recovery fails (R1 is gone). Recovery first: the rotation's authorizer compare fails (`CONFLICT`). |
| revocation vs last-device recovery | the revocation always succeeds. Revocation first: the recovery fails (`NOT_CONFIGURED`), and the challenge is gone. Recovery first: it replaces the device key, and the revocation still removes the recovery key. With the authorizing device as the target, one winner, as for rotation. |

These races are tested:

- in the storage contract (in-memory, SQLDelight in-memory and file-backed
  SQLite);
- in `server:core`, with gated storage that holds both verified operations
  before either commits, in both orders.

## Lost responses

**Rotation.** R1 → R2 commits, the response is lost, and the same request is
sent again (with a fresh ServerAuth nonce). The result is `204`
(`ALREADY_APPLIED`). The epoch grew once, and `installedAt` is unchanged.
This works across server restarts and after the freshness window.

**Revocation.** The same retry gives `204` (`ALREADY_APPLIED`).

**Client.** The library stores neither R1 nor R2, so a client does not
resubmit the exact old request. It reads the status and compares the keys.

- **Rotation:** after a lost response or a restart,
  `rotateLastDeviceRecoveryKey(R1, R2)` is called again. The signed status
  shows R2 active, so the call returns `ALREADY_ACTIVE` and sends nothing.
  If a submission gets `CONFLICT` because another submission of the same
  rotation won, the status shows R2 and the call returns `ROTATED`.
- **Revocation:** `revokeLastDeviceRecoveryKey(R1)` on a revoked key returns
  `ALREADY_REVOKED` and sends nothing. A submission that loses to another
  device's revocation (`CONFLICT` or `NOT_CONFIGURED`) is also
  `ALREADY_REVOKED` once the status shows it revoked.

## Status endpoint

```text
GET /v1/devices/{user}/{device}/last-device-recovery/key     (ServerAuth v1, registered device of the user)
200 {"state":"unconfigured|active|revoked","recoveryKeyEpoch":N|null,
     "installedAt":T|null,"revokedAt":T|null,"activePublicKey":"<b64>"|null}
```

Every field is always present, and `null` when it does not apply:

- `activePublicKey` and `installedAt` only while `active`;
- `revokedAt` only when `revoked`;
- the epoch unless `unconfigured`.

The endpoint is limited to the user's own devices. The active public key is
returned because the client needs it:

- to resolve a lost rotation response without storing R2;
- to let the application check that an offline backup still is the active
  key (`LastDeviceRecoveryKeyStatus.Active.isKey`).

A public key is not secret.

## Client API

```kotlin
// Rotation: create, back up, then rotate. Two calls, so the backup cannot be skipped by accident.
val newKey = client.createLastDeviceRecoveryKey()
showToUserForOfflineBackup(newKey.encode())           // the application's responsibility
awaitUserConfirmedBackup()
client.rotateLastDeviceRecoveryKey(currentKey = LastDeviceRecoveryKey.decode(oldText), newKey = newKey)
// After a crash or a lost response: call again with the same keys (returns ALREADY_ACTIVE if it happened).

// Revocation (the current key is required):
client.revokeLastDeviceRecoveryKey(LastDeviceRecoveryKey.decode(oldText))

// Registration after revocation (the epoch continues):
client.registerLastDeviceRecoveryKey(client.createLastDeviceRecoveryKey())

client.lastDeviceRecoveryKeyStatus()                  // Unconfigured | Active(epoch, installedAt, publicKey) | Revoked(epoch, revokedAt)
```

**Export before activation.** Back up the new key before you rotate. Once
the server accepts the rotation, R1 recovers nothing any more. A lost R2
cannot be replaced by a device alone.

Rules of the client operations:

- Every operation is explicit. Nothing rotates, revokes or registers
  implicitly. `initialize`, `send`, `receive`, registration and recovery
  never do.
- Operations run under `deviceAuthenticationMutex`, with this device's
  active device authentication key, and never inside a storage transaction.
- The client stores nothing new. No schema change, no sealed record type.
- A device without its active device authentication key cannot do any of
  this (`NotInitialized`). Recover the device first (M14 or M18).

The client rejects locally before sending:

- no active key: `LastDeviceRecoveryKeyNotConfigured`;
- a key that is not the active one: `LastDeviceRecoveryKeyMismatch`;
- the same key twice: `IllegalArgumentException`.

Server refusals are `SecureMessageTransportException.RecoveryKeyRotationRejected` /
`RecoveryKeyRevocationRejected` (`RecoveryKeyTransitionFailure`), and
`LastDeviceRecoveryKeyRejected(EPOCH_EXHAUSTED)` for a registration at the
maximum epoch.

## HTTP summary

| Route | Auth | Success | Errors |
|---|---|---|---|
| `GET …/last-device-recovery/key` | ServerAuth v1 | `200` status | `401` auth codes |
| `PUT …/last-device-recovery/key/rotation` | ServerAuth v1 + R1 signature + R2 PoP | `204` rotated or already applied | `400 invalid_recovery_key_rotation`, `401` auth codes, `401 recovery_key_rotation_{expired,invalid_proof,replay}`, `404 recovery_key_not_configured`, `409 recovery_key_rotation_conflict`, `409 recovery_key_epoch_exhausted` |
| `PUT …/last-device-recovery/key/revocation` | ServerAuth v1 + R1 signature | `204` revoked or already applied | `400 invalid_recovery_key_revocation`, `401` auth codes, `401 recovery_key_revocation_{expired,invalid_proof,replay}`, `404 recovery_key_not_configured`, `409 recovery_key_revocation_conflict`, `409 recovery_key_epoch_exhausted` |
| `PUT …/last-device-recovery/key` (M18) | unchanged | `201` also after a revocation | additionally `409 recovery_key_epoch_exhausted` |

The statement nonce replay code (`recovery_key_*_replay`) is distinct from
ServerAuth's `authentication_replay`. The client can then tell a reused
statement from a reused request.

Unexpected failures return `500 {"error":"internal_error"}` and never carry
SQL or crypto details. Logs contain the user, the authorizing address and
the outcome only.

## Persistence and migration

Server schema version 6 (`5.sqm`, `server_storage.format` = 6):

1. It replaces `last_device_recovery_key` by `last_device_recovery_key_state`:
   `user_id` (PK), `state` (1 ACTIVE / 2 REVOKED), `epoch` (≥ 1),
   `public_key`, `installed_at`, `transitioned_at`, `rotation_id` and
   `revocation_id`. CHECK constraints tie the key and `installedAt` to the
   state and allow at most one transition ID.
2. Every existing M18 key migrates to ACTIVE at epoch 1, with
   `installed_at = transitioned_at = registered_at`. M18 recorded that as
   server time when it registered the key, which is exactly its
   installation time. No time is invented, and `open` stamps nothing new.
3. It adds `last_device_recovery_challenge.recovery_key_epoch INTEGER NOT
   NULL DEFAULT 1`. Every M18 challenge was issued under the user's first
   and only key, so binding it to epoch 1 is exact. A challenge whose user
   has no key cannot have been issued by M18. It is dropped rather than
   guessed.
4. All other rows are kept: registrations, auth epochs, installation times,
   the recovery / rotation / last-device recovery IDs, nonces, prekeys,
   tombstones, the mailbox and its sequence.

The frozen fixture is `ServerVersion5Schema`. `open` refuses formats 1–5.

**Restart behavior.** The recovery key state, the epoch and the transition
IDs are ordinary rows. After a restart:

- the active key, the epoch, `installedAt` and the revoked state are
  unchanged;
- exact retries are still recognized;
- stale statements are still rejected;
- revoked users still get no challenge.

This is tested with real file-backed restarts in `storage:server:sqldelight`
and `server:ktor`.

## Preservation

A recovery key rotation, revocation or registration changes only the
recovery key state row, the user's challenges and one nonce. Nothing else
changes:

- messaging identity;
- TOFU pins, verification state and safety numbers;
- sessions and retired initiations;
- device authentication keys, their auth epochs, installation times and
  transition IDs;
- prekeys and one-time prekey tombstones;
- mailboxes;
- pending outbound and processed inbound messages;
- storage keys.

A subsequent last-device recovery with the new key changes device
authentication, as M18 describes.

## Tests

- `core:protocol` `RecoveryKeyLifecycleTest`:
  - frozen vectors;
  - field binding;
  - wrong and swapped keys;
  - cross-domain rejection in both directions;
  - invalid values;
  - redaction.
- `storage:testing` `RecoveryKeyLifecycleRepositoryContractTest`, run on
  in-memory, SQLDelight in-memory and file-backed storage:
  - provisioning;
  - rotation and revocation compare-and-set;
  - epochs, exhaustion and `installedAt`;
  - exact retry and stale transitions;
  - the authorizer compare and nonce replay;
  - challenge invalidation;
  - re-registration;
  - preservation;
  - every race above.
- `storage:server:sqldelight`:
  - `SqlDelightServerRecoveryKeyLifecycleTest`: restarts, rollback, a stale
    challenge epoch, no private material;
  - `SqlDelightServerMigrationTest`: 1–5 → 6, fixture shape, CHECK
    constraints;
  - `SqlDelightServerStorageOpenTest`.
- `server:core` `RecoveryKeyLifecycleServerTest`:
  - both authorities;
  - the check order;
  - exact retry;
  - status;
  - M18 after rotation and revocation;
  - preservation;
  - gated races in both orders.
- `server:ktor` `RecoveryKeyLifecycleRoutesTest`:
  - status JSON;
  - error mapping;
  - malformed bodies;
  - the Ktor client;
  - a lost response;
  - restarts;
  - epoch exhaustion;
  - `internal_error`.
- `client:core` `RecoveryKeyLifecycleTest`:
  - the flows;
  - preservation of messaging state;
  - lost responses;
  - mismatch;
  - races reported;
  - M18 with the rotated key only;
  - revocation stopping M18;
  - a device without its key.

## Limitations

- Losing the current offline key still blocks rotation and revocation.
  There is no device-only replacement.
- One active recovery key per user. There is no threshold or social
  recovery and no multiple keys.
- A holder of the recovery key can take over a device through M18 and then
  rotate. The two-authority rule prevents a device from acting alone. It
  does not reduce the recovery key's power.
- There is no human or account ownership proof, and no admin override.
- There is no recovery key age policy yet (`installedAt` is recorded for
  one).
- Previously used keys are not blocklisted on re-registration.
- There is no messaging identity recovery, no session backup, no TOFU reset
  and no sealed sender.
