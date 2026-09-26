# Device authentication recovery

Milestone 14. Explains how a device that lost its device authentication key
(docs/server-authentication.md) gets a new one registered on the server:
another registered device of the **same user** authorizes the replacement,
and the device proves it holds the new key.

Code:

- Recovery statement, signatures, recovery ID, transfer encoding:
  `core/protocol/.../protocol/DeviceRecovery.kt` (`DeviceRecovery`,
  `DeviceRecoveryRequest`, `DeviceRecoveryAuthorization`, `DeviceRecoveryId`,
  `DeviceRecoveryCodec`)
- Server contract: `storage/core/.../storage/ServerStorage.kt`
  (`DeviceRegistrationRepository.registrationState` / `replaceForRecovery`,
  `DeviceRegistrationState`, `RecoveryReplacement`, `RecoveryReplacementResult`)
- Server logic: `server/core/.../server/DeviceRecoveryService.kt`
  (`DeviceRecoveryException`, `DeviceRecoveryOutcome`),
  `SecureMessageServer.recoverDevice`
- HTTP: `server/ktor/.../KSecureMessageRoutes.kt`,
  `client/ktor/.../KtorSecureMessageTransport.recoverDevice`
- Client: `SecureMessageClient.prepareDeviceAuthenticationRecovery`,
  `authorizeDeviceRecovery`, `completeDeviceAuthenticationRecovery`,
  `resolveDeviceAuthenticationRecovery`, `cancelDeviceAuthenticationRecovery`;
  pending key in `DeviceAuthenticationKeyStore`

## What is recovered, and what is not

M14 recovers exactly one binding on the server:

```text
DeviceAddress → device authentication public key
```

It never changes, and never implies anything about:

- the messaging identity key (X3DH), signed prekeys, one-time prekeys;
- TOFU pins and their manual verification state, on this device or on
  peers (docs/identity-trust.md, docs/identity-verification.md): safety
  numbers are derived from messaging identity keys only, so a recovery
  changes no safety number and no verification;
- Double Ratchet sessions, retired session initiations;
- pending outbound messages and processed inbound message IDs;
- the device's mailbox on the server.

Server authentication and end-to-end identity continuity are separate. A
recovered device keeps its messaging identity; peers notice nothing. If the
device lost its messaging identity or session state as well, M14 does not
help with that: `prepareDeviceAuthenticationRecovery` requires the local
identity, and nothing creates a new messaging identity as part of recovery.
Queued envelopes stay in the mailbox; they can be undecryptable if the
session state is gone, which is a separate recovery problem.

## Recovery authority

| Who authorizes | May recover |
|---|---|
| a registered device `u/a` | every **other** registered device `u/b` of the same `UserId` |
| a device of another user | nobody (`recovery_cross_user`) |
| the device itself | nobody (`recovery_self_authorization`) |
| an unregistered device | nobody (`recovery_authorizer_not_registered`) |

The user comparison uses the structured `UserId` value, exactly (no case
folding or normalization). The authorizer is verified with its **currently
registered** key, never one from the request.

Self-recovery is forbidden: a device that still has its key does not need
recovery (it rotates its key itself, M16,
docs/device-authentication-rotation.md), and a device that lost its key
cannot authenticate. Recovery signatures never verify as rotation signatures
or the other way round: other domains, other statement, other endpoint.

The target must be registered already (`recovery_target_not_registered`
otherwise): recovery is never a second way to register an address. First
registration stays trust on first registration.

**Single-device limitation.** A user with only one registered device has no
recovery path in M14 if that device loses its key. That is intentional:
without another device there is nothing to authorize the replacement, and
M14 does not weaken authentication to cover this case. Account-level or
offline recovery (recovery keys, codes) can address it in a later milestone.

## Protocol

```text
target (lost key)                   authorizer (same user)              server
─────────────────                   ──────────────────────              ──────
prepareDeviceAuthenticationRecovery(authorizer)
  pending key N (sealed, persisted)
  request = statement + PoP_N
          ── application transfers request ──▶
                                    authorizeDeviceRecovery(request)
                                      checks + signs with its active key
          ◀── application transfers authorization ──
completeDeviceAuthenticationRecovery(authorization)
  PUT …/registration/recovery ──────────────────────────────────────▶ verify both,
                                                                       claim nonce,
                                                                       CAS K → N
  ◀──────────────────────────────────────────────────────────── 204
  promote N to active key
```

Both proofs are required: the authorizer's signature alone cannot install a
key nobody holds (and a malformed key cannot verify a proof of possession),
and the new key's proof alone carries no authority. Someone who knows only
the new public key can do neither. There is no server-side recovery session:
one request carries everything, and the server checks it at one point in
time.

The library does not move data between the devices: applications transfer
the request and the authorization themselves (QR code, local network, their
own server). `DeviceRecoveryCodec` gives both a compact binary form.

## Cryptographic format v1 (frozen)

All constructions share the **recovery statement**:

```text
u32 length | target userId (UTF-8)
u32 length | target deviceId (UTF-8)
u32 length | authorizer userId (UTF-8)
u32 length | authorizer deviceId (UTF-8)
replacement public key (32, Ed25519)
timestamp: i64, epoch milliseconds
nonce (16)
```

Integers are big-endian; strings are length-prefixed UTF-8; keys and nonce
are fixed size. Each construction prefixes the statement with
`u32 length | domain (UTF-8)`:

| Construction | Domain | Operation |
|---|---|---|
| authorization | `KSecureMessage-DeviceRecovery-v1` | Ed25519 signature by the authorizer's registered device authentication key |
| proof of possession | `KSecureMessage-DeviceRecovery-PoP-v1` | Ed25519 signature by the replacement key |
| `DeviceRecoveryId` | `KSecureMessage-DeviceRecoveryId-v1` | SHA-256, 32 bytes |

The domains keep the three apart from each other and from server request
signatures (`KSecureMessage-ServerAuth-v1`, unchanged): a ServerAuth
signature never verifies as a recovery signature and vice versa, and the
authorizer's signature never stands in for the proof of possession. Every
field is bound by both signatures, so none can be swapped after
authorization: target, replacement key, authorizer, timestamp and nonce. The
target in the HTTP path is the statement's target.

The nonce is a `RequestNonce` (16 bytes from the platform's secure random
generator), the same type as for server requests: it has the same meaning,
a single-use value per request.

`DeviceRecoveryId` identifies the statement for idempotent retries and
audit. It is not secret and never an authorization.

Frozen vectors (computed independently with Python `struct`, `hashlib` and
`cryptography`'s Ed25519) are in `core:protocol` `DeviceRecoveryTest`:
authorization and PoP bytes, recovery ID and both signatures for a base case
and for a different target, replacement key, authorizer, timestamp and
nonce, UTF-8 addresses, and the two transfer blobs.

### Transfer encoding v1

```text
version:u8 = 1 | kind:u8 (1 request, 2 authorization) | statement
| proof of possession (64) | [authorizer signature (64), kind 2 only]
```

Decoding is strict (valid UTF-8, exact sizes, non-negative timestamp, no
trailing bytes) and verifies no signature: the receiver does.

## Freshness and replay

- **Timestamp**: `DeviceRecovery.VALIDITY_WINDOW` = ±5 minutes, bounds
  included, the same as for server requests. The target sets it when it
  prepares the request; the authorizer checks it against its own clock
  before signing, the server against its injected `Clock`. The whole
  exchange must complete within the window; `prepare` again for a new
  timestamp and nonce (the pending key stays the same).
- **Nonce**: claimed under the **target's** address in the same nonce table
  as server requests, atomically with the replacement. A replay of a request
  that did not install the current key is `authentication_replay`.
- **Compare-and-set**: the replacement happens only if the target's key and
  epoch, and the authorizer's key and epoch, are still what the signatures
  were verified against.

Replay scenarios:

| Scenario | Result |
|---|---|
| K1 → K2 succeeded, same request again (within the window) | idempotent success, nothing changes (see below) |
| K1 → K2, then K2 → K3, then K1 → K2 replayed | `authentication_replay`: its nonce is still claimed |
| same, after the window | `expired_authentication` |
| two different valid requests verified against K1 at once | one wins, the other `recovery_conflict` |
| the authorizer's own key replaced while a request is verified | `recovery_conflict` |

**Target nonces are not cleared on recovery.** Clearing them would free the
nonce of an earlier recovery, and a replay of K1 → K2 inside the window
would pass the nonce check after K2 → K3 and install K2 again. Keeping them
is harmless: a request signed with the old key fails signature verification
against the new registered key, and nonces are pruned by timestamp after the
window as always. So nonces need no epoch scoping.

## Server semantics

`DeviceRecoveryService` checks, in this order, and changes nothing before
the last step:

1. sizes (replacement key 32 bytes, signatures 64) → `400 invalid_recovery`
2. authorizer = target → `403 recovery_self_authorization`;
   different `UserId` → `403 recovery_cross_user`
3. authorizer registered → else `401 recovery_authorizer_not_registered`;
   target registered → else `404 recovery_target_not_registered`
4. timestamp within the window → else `401 expired_authentication`
5. authorizer signature with its registered key, proof of possession with
   the replacement key → else `401 invalid_recovery_proof`
6. `replaceForRecovery`, one atomic step:
   - target's `recovery_id` equals this statement's ID → **already applied**
     (`204`, no write, no nonce claim);
   - target or authorizer key/epoch changed, or the replacement key is the
     target's current key → `409 recovery_conflict`, no write;
   - target's epoch is `Long.MAX_VALUE` → `409 device_auth_epoch_exhausted`
     (M16; epochs never wrap), no write;
   - prune nonces, claim the nonce under the target → `401 authentication_replay`;
   - store the replacement key, `auth_epoch + 1`, `recovery_id` (and clear a
     `rotation_id`, M16) → `204`.

Success is `204 No Content` for both a replacement and an already applied
retry. Any other failure is `500 {"error":"internal_error"}` without
details. The server logs the target and authorizer addresses and the outcome
category only, never keys, signatures or the body.

### Authentication epoch

Every registration has an `authEpoch`: 1 at first registration, +1 per
recovery or routine rotation (M16), never decremented, reused or wrapped. The compare-and-set is on key **and**
epoch, so a key that comes back later (K1 → K2 → K1) is still a new state.
The epoch is server state only; it is not part of any signature. Existing
(M13) registrations are migrated to epoch 1.

### Idempotency and lost responses

The server records on the registration the `DeviceRecoveryId` of the
recovery that installed the current key (since M16 either this or the
`DeviceAuthenticationRotationId` of a routine rotation; at most one is set). A retry of exactly that statement
succeeds without changes, so a client whose response was lost can resend the
same authorization. This does not weaken the compare-and-set: only the
statement that installed the current key matches; any other statement for
the same key is a conflict, and a stale one is a replay or a conflict.

After the window, the retry is `expired_authentication`. The client then
asks the server directly (see [lost response](#lost-response)).

### After a successful recovery

- The old key is invalid at once: every later request is verified with the
  registered key, which is the new one. There is no grace period and never
  two active keys.
- The new key authenticates at once: prekey publication, mailbox drain,
  further recoveries (as target or authorizer).
- Prekeys, one-time prekey tombstones and the mailbox are unchanged; queued
  envelopes can be drained with the new key.

### Atomicity

`storage:server:inmemory` runs the recovery under the one mutex shared by
registrations and nonces. `storage:server:sqldelight` runs it in one
database transaction: the checks, the nonce claim and a guarded
`UPDATE … WHERE key = expected AND epoch = expected`. Routine rotation (M16)
uses the same compare-and-set, so a recovery and a rotation verified
against the same state never both apply. A crash before the
commit leaves the old registration authoritative; after it, the new one. A
failure inside the transaction rolls back the nonce claim too. (Unlike
ordinary authenticated requests, whose nonce claim is its own transaction,
the recovery's claim is part of the recovery transaction.)

## Client state

`DeviceAuthenticationKeyStore` holds, next to the **active** key, at most one
**pending recovery key**:

| Operation | Storage effect |
|---|---|
| `prepareDeviceAuthenticationRecovery(authorizer)` | creates the pending key once (`ProtocolEngine.createDeviceAuthenticationKey`), reuses it on later calls; active key untouched |
| `completeDeviceAuthenticationRecovery(authorization)` | after the server accepted: pending → active in one transaction (`promotePendingRecoveryKeyPair`) |
| `resolveDeviceAuthenticationRecovery()` | same promotion, if the server confirms the pending key |
| `cancelDeviceAuthenticationRecovery()` | removes the pending key |

A pending recovery key and a pending routine rotation key (M16) never exist
together: `prepareDeviceAuthenticationRecovery` throws
`DeviceAuthenticationRotationInProgress` while a rotation is pending (resolve
it first, then cancel it), and a rotation cannot start while a recovery is
pending.

- The pending key is persisted before anything is sent, sealed at rest in
  `storage:client:sqldelight` (record type 8, table
  `device_authentication_recovery_key`, docs/storage-encryption.md) and kept
  across restarts and storage key rotations. Repeated attempts reuse it;
  there are never several competing replacement keys.
- The active key is not deleted when recovery starts: if it still exists,
  it keeps working until the server replaced it. Promotion replaces or
  installs it and clears the pending key atomically.
- `initialize()` is unchanged: a lost active key still fails closed with
  `InconsistentStorage`, also while a pending key exists. Only the explicit
  recovery operations create a replacement key. After promotion
  `initialize()` works again.
- `completeDeviceAuthenticationRecovery` refuses an authorization for another
  device or another key than the pending one (`InvalidDeviceRecovery`), and
  never sends the network request inside a storage transaction.

### Lost response

If the server committed but the client did not get the response (or crashed
before promotion), the pending key is already registered:

1. `completeDeviceAuthenticationRecovery` with the same authorization within
   the window: the server answers "already applied", the client promotes.
2. If the server answers `recovery_conflict`, `expired_authentication` or
   `authentication_replay`, `complete…` itself calls
   `resolveDeviceAuthenticationRecovery()`.
3. `resolveDeviceAuthenticationRecovery()` sends an ordinary registration
   request (`PUT …/registration`) for the pending key, signed with it.
   Registration semantics are unchanged: exactly the registered key gives
   `204` (then the client promotes and returns `true`), another key gives
   `409` (`false`, the pending key stays for another attempt).

Other failures (network, `invalid_recovery_proof`, …) leave the pending key
for another attempt; cancelling after the server accepted the key means the
device has to be recovered again.

## HTTP API

`PUT /v1/devices/{user}/{device}/registration/recovery` (target in the
path), not ServerAuth-signed; the body carries both signatures:

```json
{
  "authorizer": {"userId": "alice", "deviceId": "phone"},
  "replacementPublicKey": "<b64, 32 bytes>",
  "timestamp": 1767225600000,
  "nonce": "<b64, 16 bytes>",
  "proofOfPossession": "<b64, 64 bytes>",
  "authorizerSignature": "<b64, 64 bytes>"
}
```

Base64 is standard with padding and must be canonical. The signatures cover
the binary statement, never this JSON. Status codes are listed under
[Server semantics](#server-semantics); `KtorSecureMessageTransport` maps the
error codes to `SecureMessageTransportException.DeviceRecoveryRejected(reason)`
(`INVALID_REQUEST`, `SELF_AUTHORIZATION`, `CROSS_USER`,
`AUTHORIZER_NOT_REGISTERED`, `TARGET_NOT_REGISTERED`, `EXPIRED`,
`INVALID_PROOF`, `REPLAY`, `CONFLICT`).

## Usage

```kotlin
// On the device that lost its key (alice/laptop):
val request = laptop.prepareDeviceAuthenticationRecovery(authorizer = alicePhone)
send(DeviceRecoveryCodec.encodeRequest(request))           // application's channel

// On alice/phone, after showing the user which device is being recovered:
val request = DeviceRecoveryCodec.decodeRequest(received)
val authorization = phone.authorizeDeviceRecovery(request)
send(DeviceRecoveryCodec.encodeAuthorization(authorization))

// Back on the laptop:
laptop.completeDeviceAuthenticationRecovery(DeviceRecoveryCodec.decodeAuthorization(received))
laptop.initialize()
laptop.receive()
```

## Tests

- `core:protocol` `DeviceRecoveryTest`: frozen vectors, tampering of every
  field, wrong keys, malformed signatures, cross-domain signatures, transfer
  encoding.
- `storage:testing` `DeviceRecoveryRepositoryContractTest` (in-memory,
  SQLDelight in-memory and file-backed): CAS, epochs, idempotency, conflicts,
  replay, stale recovery, concurrent races, untouched prekeys/mailbox/nonces.
- `storage:server:sqldelight` `SqlDelightServerRecoveryTest` (restarts,
  rollback) and `SqlDelightServerMigrationTest` (schema 1 → 2).
- `server:core` `DeviceRecoveryServerTest`: every rejection, window, old key
  rejected and new key accepted at once, gated concurrent recoveries, replay
  race, authorizer changed meanwhile.
- `server:ktor` `DeviceRecoveryRoutesTest`: status mapping, malformed bodies,
  the Ktor client against the routes, restarts, `internal_error`.
- `client:core` `DeviceAuthenticationRecoveryTest`: full flow, pending key
  reuse and cancel, validation on both devices, failures before submission,
  lost responses, restart before promotion, messaging state unchanged.
- `storage:client:sqldelight` `DeviceRecoveryStorageTest`: sealed pending
  key, restarts, rotation, corruption, promotion failure, schema 8 → 9.

## Limitations

- Recovery needs another registered device of the same user; losing the only
  (or last) device's key is not recoverable.
- Whoever controls another registered device of the user (a compromised or
  stolen device) can recover, and so take over, the user's other devices'
  server authentication. There is no human or account ownership proof.
- No messaging identity or session recovery, no backup, no TOFU reset. A
  peer can accept a new messaging identity only explicitly
  (docs/identity-verification.md); device recovery never does that.
- No admin override, no password/OAuth/e-mail/SMS/recovery-phrase recovery.
- No device deletion. Routine rotation of a key that is still available is
  its own protocol (M16, docs/device-authentication-rotation.md).
- No sealed sender; the server still sees routing metadata.
