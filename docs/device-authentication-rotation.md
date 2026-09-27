# Routine device authentication key rotation

Milestone 16. Explains how a healthy device replaces its device
authentication key (docs/server-authentication.md) while it still holds the
current one: the current key K1 authorizes the replacement K2, and K2 proves
possession. No other device takes part.

Milestone 17 adds the server-authoritative key installation time and an
application-supplied rotation policy on top of that mechanism; see
[Key age and rotation policy](#key-age-and-rotation-policy-milestone-17).

Code:

- Rotation statement, signatures, rotation ID:
  `core/protocol/.../protocol/DeviceAuthenticationRotation.kt`
  (`DeviceAuthenticationRotation`, `DeviceAuthenticationRotationStatement`,
  `DeviceAuthenticationRotationAuthorization`, `DeviceAuthenticationRotationId`)
- Server contract: `storage/core/.../storage/ServerStorage.kt`
  (`DeviceRegistrationRepository.replaceForRotation`, `RotationReplacement`,
  `RotationReplacementResult`, `DeviceRegistrationState.rotationId`)
- Server logic: `server/core/.../server/DeviceAuthenticationRotationService.kt`
  (`DeviceAuthenticationRotationException`, `DeviceAuthenticationRotationOutcome`),
  `SecureMessageServer.rotateDeviceAuthenticationKey`,
  `SecureMessageServer.registrationStatus`, `ProtectedEndpoint.READ_REGISTRATION`
- HTTP: `server/ktor/.../KSecureMessageRoutes.kt`,
  `client/ktor/.../KtorSecureMessageTransport.rotateDeviceAuthenticationKey` /
  `registrationStatus`
- Key age and policy (M17): `DeviceAuthenticationRegistrationStatus`
  (`core:model`), `DeviceRegistrationState.authKeyInstalledAt`,
  `client/core/.../client/DeviceAuthenticationRotationPolicy.kt`
  (`DeviceAuthenticationRotationPolicy`, `DeviceAuthenticationRotationStatus`,
  `DeviceAuthenticationRotationDecision`, `DeviceAuthenticationRotationResult`),
  `SecureMessageClient.deviceAuthenticationRotationStatus`,
  `evaluateDeviceAuthenticationRotation`, `rotateDeviceAuthenticationKeyIfNeeded`
- Client: `SecureMessageClient.prepareDeviceAuthenticationRotation`,
  `completeDeviceAuthenticationRotation`, `rotateDeviceAuthenticationKey`,
  `resolveDeviceAuthenticationRotation`, `cancelDeviceAuthenticationRotation`;
  pending key in `DeviceAuthenticationKeyStore`

## Rotation versus recovery

```text
ROUTINE ROTATION (M16)                 RECOVERY (M14, docs/device-recovery.md)
current key K1 available               current key unavailable
K1 authorizes K2                       another registered same-user device authorizes
same DeviceAddress, no other device    two devices involved
PUT …/registration/rotation            PUT …/registration/recovery
KSecureMessage-DeviceAuthRotation-*    KSecureMessage-DeviceRecovery-*
```

The two are separate protocols: different domains, statements, endpoints,
services, client APIs and pending-key slots. A recovery signature never
verifies as a rotation signature and the other way round (domain
separation, tested in `DeviceAuthenticationRotationTest`). They share only
the server's storage compare-and-set on (key, epoch), so they compose and
race safely (see "Interaction with recovery").

Like recovery, rotation changes exactly one server binding,
`DeviceAddress → device authentication public key`, and never the messaging
identity, TOFU pins, verification state, safety numbers, sessions, signed or
one-time prekeys, tombstones, mailboxes, pending outbound messages or
processed logical IDs.

## Protocol

```text
K1 active
  ↓ prepareDeviceAuthenticationRotation (local, no network)
persist pending K2 (sealed, record type 9)
  ↓ completeDeviceAuthenticationRotation
GET  /v1/devices/{u}/{d}/registration   (ServerAuth v1, signed by K1) → {"authEpoch": N, "authKeyInstalledAt": T}
PUT  /v1/devices/{u}/{d}/registration/rotation
     statement (K1, K2, epoch N, timestamp, nonce)
     + authorization signed by K1 + proof of possession signed by K2
  ↓
server CAS (K1, epoch N) → (K2, epoch N+1, installed at server now), rotation ID recorded, nonce claimed
  ↓ 204
client promotes K2 (one transaction), pending cleared
```

## Cryptographic format v1 (frozen)

Rotation statement (all integers big-endian):

```text
u32 length | userId (UTF-8)
u32 length | deviceId (UTF-8)
current public key K1 (32, Ed25519)
replacement public key K2 (32, Ed25519)
expected authentication epoch: i64 (>= 1, so identical to a u64)
timestamp: i64, epoch milliseconds (>= 0)
nonce (16)
```

Each construction prefixes `u32 length | domain (UTF-8)`:

| Construction | Domain | Algorithm |
| --- | --- | --- |
| authorization | `KSecureMessage-DeviceAuthRotation-v1` | Ed25519 by K1 |
| proof of possession | `KSecureMessage-DeviceAuthRotation-PoP-v1` | Ed25519 by K2 |
| `DeviceAuthenticationRotationId` | `KSecureMessage-DeviceAuthRotationId-v1` | SHA-256, 32 bytes |

The statement binds the device, both keys and the expected epoch, so the
transition `(K1, epoch N) → K2` is explicit in what K1 signs, even though
the server knows K1 and N. K1 = K2 cannot be expressed
(`DeviceAuthenticationRotationStatement` rejects it). The rotation ID is
never an authorization: it identifies the transition for idempotent retries
and as the server's record of which transition installed the current key.

Vectors in `core:protocol` `DeviceAuthenticationRotationTest` are frozen and
were computed independently (Python `struct`, `hashlib`, `cryptography`
Ed25519; the same script first reproduced the frozen M14 recovery vectors):
base statement, authorization and PoP signatures, rotation ID, and variants
for another device, current key, replacement key, epoch (also
`Long.MAX_VALUE`), timestamp, nonce and a UTF-8 address.

No domain is shared with ServerAuth v1, DeviceRecovery v1 or SafetyNumber v1.

## Request authentication and nonces

The rotation endpoint carries **no ServerAuth headers**. The K1 authorization
over the statement is the request's authentication: it is fresh (timestamp
window), single-use (nonce), bound to the device, to the current key and
epoch and to the exact replacement. Adding ServerAuth by K1 would add a
second nonce claimed in another transaction and would make an exact retry
after a lost response fail, because K1 is no longer registered once the
server committed.

There is one nonce: the statement nonce, bound into both signatures. It is
claimed under the device's address in the same `authentication_nonce` table
as ServerAuth nonces (16 random bytes; one namespace per device), inside the
compare-and-set transaction, like M14. A nonce the device already used for
an ordinary request is a replay. Nonces are never cleared by a rotation (or
recovery); they are pruned only by timestamp, as for every request.

The epoch read (`GET …/registration`) is an ordinary ServerAuth v1 request
with its own nonce, claimed by `DeviceAuthenticator` as for every protected
endpoint.

## Freshness

`now - 5 min <= timestamp <= now + 5 min`, bounds included, millisecond
precision, the server's injected `Clock` — the same window as ServerAuth and
recovery (`DeviceAuthenticationRotation.VALIDITY_WINDOW`).

## Server semantics

`DeviceAuthenticationRotationService` checks, in this order; an earlier
failure changes nothing:

1. the statement names the route's device (the route builds the statement
   from the path, so the signatures cover the path's address); sizes, a
   positive epoch and K1 ≠ K2 are enforced when the body is decoded
   (`400 invalid_device_auth_rotation`);
2. the device is registered (`404 device_auth_rotation_not_registered`);
3. the timestamp is within the window (`401 expired_authentication`);
4. **exact retry**: if the registered key was installed by the rotation with
   this statement's ID and equals K2, both proofs are verified (K1's with the
   statement's current key, which the stored ID binds; K2's with the
   registered key) and the result is `ALREADY_APPLIED` (`204`), without any
   write or nonce claim;
5. the registered key is K1 and the epoch is the expected one
   (`409 device_auth_rotation_conflict`);
6. the authorization verifies with the **registered** key
   (`401 invalid_device_auth_rotation_proof`);
7. the proof of possession verifies with K2 (same error);
8. `DeviceRegistrationRepository.replaceForRotation`, one transaction:
   not registered → same rotation ID already installed (`ALREADY_APPLIED`) →
   key/epoch differ from the verified state or K2 is the current key
   (`CONFLICT`) → epoch is `Long.MAX_VALUE` (`EPOCH_EXHAUSTED`,
   `409 device_auth_epoch_exhausted`) → prune + claim the nonce (`REPLAY`,
   `401 authentication_replay`) → K2, epoch + 1, `rotation_id` set,
   `recovery_id` cleared, `auth_key_installed_at` = server time (`REPLACED`,
   `204`).

Unexpected failures are `500 {"error":"internal_error"}`; logs name the
address and the failure category only, never keys, signatures or the body.

### Authentication epoch

Epochs start at 1 on first registration and grow by exactly one per
recovery or rotation. They never wrap: at `Long.MAX_VALUE` both recovery and
rotation fail closed with `EPOCH_EXHAUSTED` and nothing changes (SQLite
would otherwise turn `auth_epoch + 1` into a REAL). A failed rotation leaves
the epoch unchanged; an idempotent retry does not increment it again.

### Transition metadata

`device_registration` keeps the ID of the transition that installed the
current key in one of three columns: `recovery_id` (a `DeviceRecoveryId`),
`rotation_id` (a `DeviceAuthenticationRotationId`) or, since milestone 18,
`last_device_recovery_id` (a `LastDeviceRecoveryId`,
docs/last-device-recovery.md); at most one is set, all are `NULL` after
first registration. Each transition sets its own column and clears the
other two. The ID kinds never match each other, so an older rotation or
recovery is never mistaken for the one that is applied.

### Stale transitions

After K1 → K2 and K2 → K3, a replay of the K1 → K2 statement fails: its
current key and epoch are no longer registered (`CONFLICT`), and with a
statement rewritten against the current state its nonce is still claimed
(`REPLAY`). K3 stays authoritative, also across server restarts
(`SqlDelightServerRotationTest`, `DeviceAuthenticationRotationRoutesTest`).

### After a successful rotation

From the commit on, only K2 authenticates the device: every ServerAuth
request signed with K1 fails with `401 invalid_authentication`, requests
signed with K2 are accepted at once. First registration is unchanged:
registering K2 again is idempotent, registering K1 conflicts.

## Interaction with recovery

- Rotation then recovery: K1 → K2 by rotation, K2 lost, another device
  recovers K2 → K3; epochs 1 → 2 → 3.
- Recovery then rotation: K1 → K2 by recovery, then K2 → K3 by rotation.
- Race: a rotation K1 → K2 and a recovery K1 → K3 verified against the same
  (K1, epoch N) — exactly one compare-and-set wins, the loser gets its
  conflict (`DeviceAuthenticationRotationServerTest`, gated deterministically;
  `DeviceAuthenticationRotationRepositoryContractTest` with 32 parties).

On the client, at most one pending key exists: preparing a rotation while a
recovery is pending throws `DeviceAuthenticationRecoveryInProgress`, and
preparing a recovery while a rotation is pending throws
`DeviceAuthenticationRotationInProgress`; the storage enforces the same
(`storePendingRotationKeyPair` / `storePendingRecoveryKeyPair` refuse).
Milestone 18 adds a third slot, the pending last-device recovery key: while
it is pending, preparing a rotation throws `LastDeviceRecoveryInProgress`,
`rotateDeviceAuthenticationKeyIfNeeded` returns `RecoveryInProgress` and
`DeviceAuthenticationRotationStatus.pendingRecovery` is `true`. A last-device
recovery and a rotation from the same (key, epoch) have exactly one
compare-and-set winner (docs/last-device-recovery.md).

Escape path when K1 is lost during an unfinished rotation: call
`resolveDeviceAuthenticationRotation()` first — if the server already holds
K2 it is promoted and nothing else is needed; otherwise
`cancelDeviceAuthenticationRotation()` and start a recovery (M14, or M18
with the offline recovery key when no other device exists). The client never
promotes K2 just because K1 disappeared.

## Client state

- Active key K1: unchanged and used for every request until the server
  accepted K2.
- Pending rotation key K2: created only by `prepareDeviceAuthenticationRotation`
  (by `ProtocolEngine`, never by storage), persisted before any network
  I/O, sealed at rest (record type 9), reused across restarts and attempts
  until completed or cancelled; never generated twice for one rotation.
- Completion: reads the epoch with K1, builds a fresh statement (current
  time, fresh nonce) and sends it; never inside a storage transaction.
- Promotion: pending → active in one transaction (`promotePendingRotationKeyPair`),
  only after the server accepted, answered `ALREADY_APPLIED`, or the
  registration probe with K2 succeeded; K1 is overwritten only in that
  transaction.
- Server rejection before mutation (invalid proof, not registered, epoch
  exhausted, transport failures): K1 stays active, K2 stays pending for
  another attempt or an explicit cancel; nothing is deleted automatically.
- Cancel: removes only the pending rotation key.
- Nothing rotates implicitly: not in `initialize`, `send`, `receive`,
  `publishPreKeys`, and not by key age. Policy is out of scope.

### Lost responses and crashes

- Response lost after the server committed: the next
  `completeDeviceAuthenticationRotation` reads the epoch with K1, which the
  server now rejects (`AuthenticationFailed(INVALID)`); the client then
  probes with K2 (`resolveDeviceAuthenticationRotation`, a registration
  request signed by K2 — registering the registered key changes nothing) and
  promotes K2. A rotation rejected as `CONFLICT`, `EXPIRED` or `REPLAY` is
  resolved the same way before failing.
- An exact retry of the same request (same statement bytes) within the
  window is answered `ALREADY_APPLIED` by the server.
- Crash or failed promotion after the server committed: K2 is still pending
  after a restart; `resolveDeviceAuthenticationRotation` or another
  `completeDeviceAuthenticationRotation` promotes it. No recovery is needed.
- A competing recovery won (for example started from another installation
  of this device): K1 is rejected and the K2 probe conflicts; the call fails
  with `AuthenticationFailed`, K1 and K2 stay as they are. This installation
  holds neither registered key: cancel the rotation and recover it
  (docs/device-recovery.md).

## Storage

- Client: `device_authentication_rotation_key` (single row, sealed record
  type 9, own associated data so it never opens as the active key (type 7)
  or the recovery key (type 8)); in `SEALED_COLUMNS`, re-encrypted and
  covered by the reference scan of storage key rotation
  (docs/storage-key-rotation.md); a damaged record throws
  `StorageEncryptionException` and is never replaced. Client SQLDelight
  schema v11 via `10.sqm` (a new empty table; no existing row changes),
  frozen fixture `Version10Schema`. `InMemoryClientStorage` has the same
  semantics without encryption.
- Server: `device_registration.rotation_id`, server schema v3 via server
  `2.sqm` (`server_storage.format = 3`), frozen fixture `ServerVersion2Schema`.
  Milestone 17 adds `device_registration.auth_key_installed_at`, server
  schema v4 via server `3.sqm` (`server_storage.format = 4`), frozen fixture
  `ServerVersion3Schema`; `open` refuses formats 1, 2 and 3 (migrate with
  `SqlDelightServerStorage.Schema`). `InMemoryServerStorage` has the same
  semantics.
- The client stores no epoch and no installation time (M17 needs no client
  schema change).

## HTTP API

```text
GET /v1/devices/{user}/{device}/registration            ServerAuth v1 (READ_REGISTRATION)
200 {"authEpoch":7,"authKeyInstalledAt":1767225600000}  (M17: installation time, epoch ms)
401 missing_authentication | device_not_registered | expired_authentication
    | invalid_authentication | authentication_replay

PUT /v1/devices/{user}/{device}/registration/rotation   no auth headers
{"currentPublicKey":"<b64>","replacementPublicKey":"<b64>","authEpoch":7,
 "timestamp":1767225600000,"nonce":"<b64>",
 "authorizationSignature":"<b64>","proofOfPossession":"<b64>"}
204                                         rotated or already applied
400 invalid_device_auth_rotation            malformed, non-canonical Base64, sizes, epoch < 1, K1 = K2
404 device_auth_rotation_not_registered
401 expired_authentication | invalid_device_auth_rotation_proof | authentication_replay
409 device_auth_rotation_conflict | device_auth_epoch_exhausted
500 internal_error
```

Signatures cover the binary statement, never the JSON. The recovery route
additionally maps `EPOCH_EXHAUSTED` to `409 device_auth_epoch_exhausted`.

## Usage

```kotlin
client.rotateDeviceAuthenticationKey()        // prepare + complete

// or step by step
client.prepareDeviceAuthenticationRotation()  // local only; K2 persisted
client.completeDeviceAuthenticationRotation() // network; promotes K2

// after a crash or lost response
client.resolveDeviceAuthenticationRotation()  // true: K2 promoted
client.cancelDeviceAuthenticationRotation()   // only if the rotation will not complete

// M17: policy, when the application decides to check
val policy = DeviceAuthenticationRotationPolicy(maxKeyAge = 30.days)
client.deviceAuthenticationRotationStatus()          // epoch, installedAt, age, pending flags
client.evaluateDeviceAuthenticationRotation(policy)  // NotNeeded / Due / RotationPending / RecoveryPending
client.rotateDeviceAuthenticationKeyIfNeeded(policy) // NotNeeded / Rotated / ResumedPendingRotation / RecoveryInProgress
```

## Tests

- `core:protocol` `DeviceAuthenticationRotationTest`: frozen vectors, tamper,
  wrong signers, malformed signatures, same key, domain separation.
- `storage:testing` `DeviceAuthenticationRotationRepositoryContractTest`
  (in-memory, SQLDelight in-memory, file-backed): CAS, epoch, metadata,
  idempotency, stale replay, exhaustion, 32-party races (identical,
  different, rotation vs recovery), prekeys/mailbox/nonces untouched.
- `storage:server:sqldelight` `SqlDelightServerRotationTest` (restarts,
  rollback before/after nonce claim and CAS), `SqlDelightServerMigrationTest`
  (v1 → v3, v2 → v3, fresh = migrated), `SqlDelightServerStorageOpenTest`.
- `server:core` `DeviceAuthenticationRotationServerTest`,
  `server:ktor` `DeviceAuthenticationRotationRoutesTest` (routes, adapter,
  client over HTTP, lost response, restarts, `internal_error`).
- M17: `storage:testing` contracts (installation time on registration,
  retries, recovery, rotation, conflicts, replays), `storage:server:sqldelight`
  `SqlDelightServerPersistenceTest.keyInstallationTimeSurvivesEveryRestartExactly`,
  `SqlDelightServerMigrationTest` (v3 → v4, legacy stamping once),
  `SqlDelightServerStorageOpenTest`; `server:core`
  `DeviceRegistrationStatusServerTest`; `server:ktor`
  `DeviceAuthenticationRotationRoutesTest` (exact JSON, restarts);
  `client:core` `DeviceAuthenticationRotationPolicyTest` (boundary, clamp,
  infinite, validation) and `DeviceAuthenticationRotationPolicyClientTest`
  (end to end, clocks, recovery, pending, lost responses, no implicit
  calls, concurrency).
- `client:core` `DeviceAuthenticationRotationTest`; `storage:client:sqldelight`
  `DeviceAuthenticationRotationStorageTest` (sealing, AD separation,
  corruption, storage key rotation, restarts, crash before promotion,
  migration from `Version10Schema`); `storage:encryption`
  `StorageCipherTest.deviceAuthenticationRotationKeyVector` and
  `ClientRecordCipherTest`; `ClientStorageContractTest`.

## Key age and rotation policy (milestone 17)

M16 is the mechanism. M17 adds what an application needs to decide when to
use it:

```text
M16          rotateDeviceAuthenticationKey()            the mechanism
M17          status / evaluate / rotate-if-needed       is rotation due?
application  decides when to call M17                   no library scheduler
```

### Authoritative installation time

The server records, with every registration, the server time its current
key was installed at: `DeviceRegistrationState.authKeyInstalledAt`
(`device_registration.auth_key_installed_at`, epoch milliseconds). It moves
together with the key and the epoch, in the same atomic step, and only
there:

| Event | `authEpoch` | `authKeyInstalledAt` |
| --- | --- | --- |
| first registration | 1 | server now |
| registration retry of the same key (lost response, M14/M16 probe) | unchanged | unchanged |
| device recovery (M14) | + 1 | server now |
| routine rotation (M16) | + 1 | server now |
| exact retry (`ALREADY_APPLIED`), `CONFLICT`, `REPLAY`, `EXPIRED`, rejected registration | unchanged | unchanged |

"Server now" is the injected server `Clock` (`SecureMessageServer(storage,
clock)`), truncated to milliseconds like every auth timestamp. It is never
the client-supplied request, recovery or rotation timestamp, never a local
key creation time and never first use. `server:core` passes it into the
repository (`register(registration, installedAt)`,
`RecoveryReplacement.installedAt`, `RotationReplacement.installedAt`);
repositories read no clock (except the one-time legacy stamping below).

The server owns this metadata because it already owns the key, the epoch
and the transitions: the age survives client reinstalls, lost responses,
restarts, recovery on another device and client clock changes. The client
persists none of it.

Legacy registrations (server schema v3 and older) have no installation
time: `3.sqm` adds the column as `NULL` (SQL has no trusted server clock),
and `SqlDelightServerStorage.open(driver, dispatcher, clock)` stamps every
`NULL` row with `clock`'s time in one transaction. That happens once: a
stamped time is never rewritten by a later open, and a row with a time is
never touched (docs/server-storage.md). The legacy key's age therefore
starts at the upgrade, not at its (unknown) historical registration. A
`NULL` read afterwards fails closed (`IllegalStateException`, `500`).

### Registration status

The existing signed `GET /v1/devices/{user}/{device}/registration` (ServerAuth
v1, `READ_REGISTRATION`, signed by the active key) returns the metadata:

```json
{"authEpoch":7,"authKeyInstalledAt":1767225600000}
```

`authKeyInstalledAt` is epoch milliseconds; the Kotlin model is
`DeviceAuthenticationRegistrationStatus(authEpoch: Long, authKeyInstalledAt: Instant)`
(`core:model`), returned by `SecureMessageServer.registrationStatus` and
`SecureMessageTransport.registrationStatus` (which replaced M16's
`authenticationEpoch`). No path changed and there is no new endpoint; the
status is never public. ServerAuth authenticates the request, not the
response: the client trusts the server (over HTTPS) as the authority for its
registration metadata, and M17 adds no signed responses. The server never
answers "rotate now": it exposes metadata, not policy.

### Policy, status, decision

```kotlin
class DeviceAuthenticationRotationPolicy(val maxKeyAge: Duration)   // > 0; INFINITE = never due

data class DeviceAuthenticationRotationStatus(
    val authEpoch: Long,
    val authKeyInstalledAt: Instant,   // server time
    val evaluatedAt: Instant,          // client clock
    val pendingRotation: Boolean,
    val pendingRecovery: Boolean,
) { val age: Duration }                // max(0, evaluatedAt - authKeyInstalledAt)

sealed interface DeviceAuthenticationRotationDecision {
    NotNeeded(status), Due(status), RotationPending, RecoveryPending
}
sealed interface DeviceAuthenticationRotationResult {
    NotNeeded(status), Rotated(previous), ResumedPendingRotation, RecoveryInProgress
}
```

- Due exactly when `age >= maxKeyAge` (the boundary is due).
- `maxKeyAge` must be positive; zero and negative throw
  `IllegalArgumentException`. `Duration.INFINITE` disables age-based
  rotation. There is no default policy and nothing applies one implicitly.
- No key material in any of these types.

Client API (`SecureMessageClient`):

- `deviceAuthenticationRotationStatus()`: reads the status from the server
  (signed by the active key; never cached) and the local pending flags.
  Throws `NotInitialized` without an active key and `AuthenticationFailed`
  if the active key is not registered.
- `evaluateDeviceAuthenticationRotation(policy)`: a pending recovery gives
  `RecoveryPending`, a pending rotation `RotationPending`, both decided
  locally without a request; otherwise `Due` or `NotNeeded` with the status.
  Never rotates, never creates a key.
- `rotateDeviceAuthenticationKeyIfNeeded(policy)`:
  1. pending recovery → `RecoveryInProgress`, nothing started or sent;
  2. pending rotation → completes it with its existing key, including the
     M16 lost-response resolution (K1 rejected for the epoch read → K2
     registration probe) → `ResumedPendingRotation`, whatever the policy
     says; never a second pending key;
  3. otherwise fetches the status; not due → `NotNeeded(status)`; due →
     the M16 rotation (`prepare` + `complete`) → `Rotated(previous)`.
  Errors are the M16 ones; M17 adds no exception type.

None of these is called by `initialize`, `registerDevice`, `send`,
`receive`, `decrypt`, `publishPreKeys`, recovery or anything else in the
library. There is no timer, worker, coroutine loop, WorkManager/BGTask job
or server cron: the application decides when to evaluate.

### Clocks

The age is the client's clock (`SecureMessageClient`'s injected `Clock`)
minus the server's installation time:

- Client clock behind the installation time (skew or rollback): the age is
  clamped to zero; a key never becomes due because a clock moved backwards.
- Client clock jumping forward: the key may become due early. Accepted:
  routine rotation is safe and explicit.
- This is a wall-clock policy, not a secure monotonic timer: whoever
  controls the device clock can make a rotation happen earlier or later.

### Interaction with recovery and retries

- A recovery installs the recovered key at the recovery's server time: a
  key recovered after its predecessor was 100 days old has age 0.
- A rotation resets the age: an immediate re-evaluation is `NotNeeded`.
- Registration probes (M14 `resolveDeviceAuthenticationRecovery`, M16
  `resolveDeviceAuthenticationRotation`) and exact retries never refresh the
  time; a key whose rotation response was lost keeps its commit time.

### Concurrency

- One instance: the rotation steps (`prepare`, `complete`, `resolve`,
  `cancel`, `rotateDeviceAuthenticationKey`, `…IfNeeded`) share a mutex.
  Concurrent `rotateDeviceAuthenticationKeyIfNeeded` calls run one after
  the other; the later ones see the new key's age and return `NotNeeded`.
- Several instances on one storage: the storage keeps at most one pending
  rotation key (and never together with a recovery key), the server's
  compare-and-set applies at most one rotation per epoch. An instance
  that finds its accepted key already promoted by another instance treats
  that as done; otherwise the M16 errors apply.

### Health awareness (milestone 25)

`deviceAuthenticationHealth(policy)` combines the local key slots and, only
when they do not decide, one registration status read into one read-only
result (`Healthy`, `RotationDue`, `RotationPending`, `RecoveryPending`,
`ActiveKeyMissing`, `Unregistered`, `Inconsistent`). It uses this policy's
semantics unchanged (`age >= maxKeyAge`, clamped age, `INFINITE` never due,
no default), reports a pending rotation before any age, and never rotates,
resolves or completes anything. See docs/device-authentication-health.md.

## Limitations

- Rotation is explicit; the M17 policy is evaluated only when the
  application asks, and the server never triggers it. There is no
  scheduler.
- The age policy relies on wall-clock time; there is no secure monotonic
  clock. Only age-based policy: no request-, message- or usage-count
  policy, and no server-side policy.
- The active key K1 is required; a device that lost it uses recovery
  (docs/device-recovery.md) or, as the last device, last-device recovery
  (docs/last-device-recovery.md).
- No account recovery, recovery codes or passwords.
- No messaging identity rotation or recovery; no sealed sender.
