# Last-device recovery

Milestone 18. This document explains how a device that lost its device
authentication key (docs/server-authentication.md) gets a new one registered
when nothing else can authorize the replacement:

- no other registered device of the user exists, or none is usable, so device
  recovery (M14, docs/device-recovery.md) is not possible;
- the device's own key is gone, so routine rotation (M16,
  docs/device-authentication-rotation.md) is not possible either.

An **offline recovery key** of the user authorizes the replacement. The
server issues a **challenge**, and the new key proves possession.

Code:

- Recovery key, statement, signatures, recovery ID:
  `core/protocol/.../protocol/LastDeviceRecovery.kt` (`LastDeviceRecoveryKey`,
  `LastDeviceRecoveryKeyRegistration`, `LastDeviceRecoveryChallenge`,
  `LastDeviceRecoveryChallengeId`, `LastDeviceRecoveryStatement`,
  `LastDeviceRecoveryAuthorization`, `LastDeviceRecoveryId`,
  `LastDeviceRecovery`); `ProtocolEngine.createLastDeviceRecoveryKey`.
- Server contract: `storage/core/.../storage/ServerStorage.kt`
  (`LastDeviceRecoveryRepository`, `LastDeviceRecoveryChallengeRequest`,
  `LastDeviceRecoveryChallengeIssue`, `StoredLastDeviceRecoveryChallenge`,
  `LastDeviceRecoveryKeyException`,
  `DeviceRegistrationRepository.replaceForLastDeviceRecovery`,
  `LastDeviceRecoveryReplacement`, `LastDeviceRecoveryReplacementResult`,
  `DeviceRegistrationState.lastDeviceRecoveryId`).
- Server logic: `server/core/.../server/LastDeviceRecoveryService.kt`
  (`LastDeviceRecoveryException`, `LastDeviceRecoveryOutcome`),
  `SecureMessageServer.registerLastDeviceRecoveryKey` /
  `lastDeviceRecoveryChallenge` / `recoverLastDevice`,
  `ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY`.
- HTTP: `server/ktor/.../KSecureMessageRoutes.kt`;
  `client/ktor/.../KtorSecureMessageTransport.registerLastDeviceRecoveryKey` /
  `lastDeviceRecoveryChallenge` / `recoverLastDevice`.
- Client: `SecureMessageClient.createLastDeviceRecoveryKey`,
  `registerLastDeviceRecoveryKey`, `prepareLastDeviceRecovery`,
  `completeLastDeviceRecovery`, `recoverLastDevice`,
  `resolveLastDeviceRecovery`, `cancelLastDeviceRecovery`. The pending key
  lives in `DeviceAuthenticationKeyStore` (`pendingLastDeviceRecoveryKeyPair`
  and related functions).

## What is recovered, and what is not

Like M14 and M16, M18 changes exactly one binding on the server:

```text
DeviceAddress → device authentication public key
```

It never changes, and never implies anything about:

- the messaging identity key (X3DH), signed prekeys, one-time prekeys,
  one-time prekey tombstones;
- TOFU pins, manual verification state or safety numbers, on this device or
  on peers;
- Double Ratchet sessions or retired session initiations;
- pending outbound messages and processed inbound message IDs;
- storage encryption keys;
- the device's mailbox on the server. Queued envelopes stay, and the
  recovered key drains them.

`prepareLastDeviceRecovery` requires the local messaging identity
(`NotInitialized` otherwise). An installation that lost its messaging
identity or session state is not helped by M18. It can drain its mailbox
again, but old envelopes may be undecryptable. Messaging identity recovery
is a separate problem and out of scope.

## Recovery model: an offline Ed25519 key per user

```text
healthy device                             server
──────────────                             ──────
createLastDeviceRecoveryKey()  ─ R (seed, stays on the client; application backs it up offline)
registerLastDeviceRecoveryKey(R)
  PUT …/last-device-recovery/key  ───────▶ store public(R) for the user (ServerAuth by the device)

… later, every usable device-auth key is lost …

recovering installation (has the messaging identity)
prepareLastDeviceRecovery()        ─ pending K2 (sealed, persisted)
completeLastDeviceRecovery(R)
  POST …/last-device-recovery/challenge ─▶ challenge (id, nonce, epoch, expiry)
  statement = challenge + public(R) + K2
  sign with R (authorization) and K2 (proof of possession)
  PUT …/last-device-recovery ────────────▶ verify both, consume challenge,
                                           CAS (key, epoch) → K2, epoch + 1,
                                           installedAt = server now
  ◀──────────────────────────────── 204
  promote K2 to the active key
```

The design is asymmetric: the recovery key is an Ed25519 key pair.

- The **private** part is a 32-byte seed. The library returns it once to the
  application (`LastDeviceRecoveryKey`). The library never stores it, never
  sends it and never logs it.
- The **public** part (32 bytes) is the only part the server gets.

Consequences:

- A leak of the server database (or its backups) reveals only public keys.
  It gives no power to forge a recovery. A symmetric verifier (for example
  `HMAC(V, statement)` with a server-held `V`) was rejected for exactly this
  reason.
- The seed has 256 bits of entropy, so there is no password hardening and no
  guessing attack. Human passwords, PINs and mnemonics are out of scope.
- Whoever holds the seed can replace the server authentication key of every
  registered device of the user it is registered for. That is the intended
  power; applications must protect the seed like a master credential.

**Scope: per `UserId`.** One recovery key per user recovers any registered
device of that user. It never crosses users: the server looks up the key by
the target's `UserId` (exact comparison) and verifies the recovery signature
with that registered key only, never with a key the request supplies.

### Text form (frozen)

`LastDeviceRecoveryKey.encode()` gives the seed in Base64url without
padding: exactly 43 characters from `[A-Za-z0-9_-]`, for example
`wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t8`.

`decode` is strict. It rejects:

- other lengths;
- padding (`=`), whitespace and line breaks;
- the standard alphabet's `+` and `/`;
- any text that is not the canonical encoding of its bytes (non-zero unused
  bits in the last character).

The public key is derived from the seed (Ed25519), so the text form is the
whole key. `toString()` is redacted, and equality compares the public key.
There is no mnemonic word list in M18.

## Provisioning: registering the recovery key

```text
PUT /v1/devices/{user}/{device}/last-device-recovery/key    (ServerAuth v1, signed by {device})
{"publicKey":"<b64, 32>","proofOfPossession":"<b64, 64>"}
```

- **Authentication:** only a registered device can register the key, with
  an ordinary ServerAuth v1 request signed by its registered key. The key is
  registered for the route's user, which is the authenticated device's user
  (`ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY`).
- **Proof of possession:** the body carries the recovery key's own signature
  over `u32 len | KSecureMessage-LastDeviceRecoveryKey-PoP-v1 | u32 len |
  userId | public key`. An active key can be replaced only by a rotation
  that needs this key's signature (M19), so a key nobody holds (a typo, a
  wrong key) must never get registered. The PoP is
  bound to the user, so a registration for another user does not verify.
- **Results:**

  | Situation | Response |
  |---|---|
  | no key registered | stored: `201` |
  | the same key again | idempotent: `204`, nothing changes |
  | a different key | `409 last_device_recovery_key_conflict`, nothing changes (only a rotation replaces an active key, docs/recovery-key-lifecycle.md) |
  | the user's key was revoked (M19) | stored: `201`, at recovery key epoch + 1 |
  | revoked at the maximum epoch (M19) | `409 recovery_key_epoch_exhausted` |
  | malformed body, bad PoP, or PoP for another user | `400 invalid_last_device_recovery_key` |
  | authentication failure | the usual `401` codes |

- **Explicit only:** `initialize()`, `registerDevice()` and every other call
  never create or register a recovery key. The application decides when
  recovery is enabled: `createLastDeviceRecoveryKey()`, show or export the
  key, then `registerLastDeviceRecoveryKey(key)`.

## Challenge protocol

```text
POST /v1/devices/{user}/{device}/last-device-recovery/challenge   (public, no body)
200 {"challengeId":"<b64, 16>","challengeNonce":"<b64, 32>","authEpoch":N,"expiresAt":<epoch ms>}
404 last_device_recovery_target_not_registered | last_device_recovery_not_configured
```

The client learns the epoch from the challenge. It could not read it any
other way, because the signed `GET …/registration` needs the lost key.

- **Fields:** a 16-byte random ID and a 32-byte random nonce, both from the
  server's `SecureRandom`. The challenge also carries the target's current
  epoch and `expiresAt = issuedAt + 5 minutes`
  (`LastDeviceRecovery.CHALLENGE_LIFETIME`), both on the server's injected
  `Clock`. Nothing in it is secret. The server stores the registered key the
  challenge was issued for, but never returns it.
- **One active challenge per device:** while a challenge is valid
  (`now <= expiresAt`) and the registration still has the key and epoch it
  was issued for, every request gets the **same** challenge. A new challenge
  replaces it only when it expired or the registration changed. This bounds
  storage to one row per registered device. Nobody can knock out someone
  else's challenge by requesting new ones: both get the same challenge, and
  only the holder of the recovery key can use it.
- **Single use:** the successful recovery deletes the challenge in the same
  transaction as the key replacement. A consumed, replaced or unknown
  challenge is `last_device_recovery_challenge_invalid`.
- **Pruning:** challenges that expired before `now` are deleted when a
  challenge is issued and in every storage recovery attempt, inside those
  transactions. There is no background job.
- **Recovery key epoch (M19):** each challenge also records the recovery key
  epoch it was issued under. A recovery key rotation or revocation deletes
  every challenge of the user in the same transaction, and issue, reuse and
  consumption compare the challenge's epoch with the current one. A
  challenge from before a rotation or revocation never authorizes anything
  (docs/recovery-key-lifecycle.md). The frozen statement format is
  unchanged: the binding is server-side state.
- **Persistence:** challenges live in server storage
  (`last_device_recovery_challenge`) and survive restarts until they expire.
- **Privacy:** the public endpoint reveals whether a device is registered
  (as the public prekey bundle fetch already does), whether its user
  configured a recovery key, and the device's current auth epoch. It never
  reveals keys. This is documented metadata leakage; M18 has no rate limit
  beyond the one-challenge-per-device rule.

## Cryptographic format v1 (frozen)

Recovery statement (integers big-endian, strings `u32 length | UTF-8`):

```text
u32 length | target userId
u32 length | target deviceId
recovery public key (32, Ed25519)
challenge ID (16)
challenge nonce (32)
expected authentication epoch: i64 (>= 1)
challenge expiry: i64, epoch milliseconds (>= 0)
replacement public key K2 (32, Ed25519)     // K2 ≠ recovery public key
```

Each construction prefixes `u32 length | domain (UTF-8)`:

| Construction | Domain | Operation |
|---|---|---|
| recovery authorization | `KSecureMessage-LastDeviceRecovery-v1` | Ed25519, offline recovery key |
| proof of possession | `KSecureMessage-LastDeviceRecovery-PoP-v1` | Ed25519, K2 |
| `LastDeviceRecoveryId` | `KSecureMessage-LastDeviceRecoveryId-v1` | SHA-256, 32 bytes |
| key registration PoP | `KSecureMessage-LastDeviceRecoveryKey-PoP-v1` | Ed25519, recovery key, over `u32 len userId | recovery public key` |

What the statement binds, and why:

- **User and device:** the target, and so the user whose recovery key must
  verify.
- **Recovery key:** it plays the role of the key version. M18 has one key per
  user.
- **Challenge ID and nonce:** freshness and single use.
- **Epoch:** the state being replaced.
- **Expiry:** the challenge's lifetime.
- **K2:** the exact replacement.

The current key K1 is **not** in the statement, because the recovering
device does not know it. The server compare-and-set checks the key and epoch
stored with the challenge instead.

No domain is shared with ServerAuth v1, DeviceRecovery v1, DeviceAuthRotation
v1, SafetyNumber v1 or the storage domain. A signature from any of them
never verifies as a last-device recovery signature, and the other way round
(tested).

Frozen vectors are in `core:protocol` `LastDeviceRecoveryTest`. They were
computed independently with Python `struct`, `hashlib`, `base64` and
`cryptography`'s Ed25519; the same script first reproduced the frozen M16
rotation vectors. They cover:

- key derivation and text form;
- statement, both signatures and the ID for the base case;
- a different target, epoch, challenge ID, challenge nonce and K2;
- UTF-8 identifiers;
- key registration PoP for an ASCII and a UTF-8 user.

## Recovery request and server semantics

```text
PUT /v1/devices/{user}/{device}/last-device-recovery     (public, no auth headers)
{"recoveryPublicKey","challengeId","challengeNonce","authEpoch","expiresAt",
 "replacementPublicKey","recoverySignature","proofOfPossession"}
```

The target is the route's device, and binary fields are canonical standard
Base64 with padding. The signatures cover the binary statement, never the
JSON.

`LastDeviceRecoveryService` checks, in this order, and changes nothing
before the last step:

1. The statement names the route's device; sizes and K2 ≠ recovery key are
   enforced by the types. Failure: `400 invalid_last_device_recovery`.
2. The user has a registered recovery key (else
   `404 last_device_recovery_not_configured`), and it is the statement's
   recovery key (else `401 last_device_recovery_proof_invalid`).
3. The target is registered. Else
   `404 last_device_recovery_target_not_registered`: recovery is never a way
   to register an address.
4. **Exact retry:** if the target's stored `last_device_recovery_id` is this
   statement's ID and its registered key is K2, and both signatures verify,
   the result is `204` with no write. This check comes before the challenge
   check, because the challenge is already consumed.
5. The target's stored challenge has the statement's ID, nonce, epoch and
   expiry, and was issued under the current recovery key epoch (M19) (else
   `401 last_device_recovery_challenge_invalid`), and
   `now <= expiresAt` (else `401 last_device_recovery_expired`).
6. The registration still has the key and epoch the challenge was issued
   for. Else `409 last_device_recovery_conflict`: another transition won.
   If step 5 or 6 fails, the exact-retry check of step 4 is repeated on the
   current registration first: an identical submission may have committed
   (and consumed the challenge) between the two reads, and that is still an
   exact retry (`204`), not a failure.
7. The recovery signature verifies with the **registered** recovery key, and
   the proof of possession with K2. Else `401 last_device_recovery_proof_invalid`.
8. `replaceForLastDeviceRecovery`, one atomic step, as described in the next
   section.

Success is `204` for both a replacement and an already-applied retry. The
epoch never wraps: `409 device_auth_epoch_exhausted`. Any other failure is
`500 {"error":"internal_error"}` without details. Logs contain the target
address and the outcome category only: never keys, signatures, challenges or
the body.

### Atomic replacement (storage)

`DeviceRegistrationRepository.replaceForLastDeviceRecovery` runs in one
transaction (SQLDelight) or under the one authentication mutex (in-memory):

1. Not registered: `NOT_REGISTERED`.
2. The stored `last_device_recovery_id` equals this ID: `ALREADY_APPLIED`,
   no write.
3. The user's recovery key is missing, revoked or different: `NOT_CONFIGURED`.
4. No matching challenge, or one of another recovery key epoch: `CHALLENGE_INVALID`. A matching one that expired:
   `EXPIRED`. Expired challenges are pruned either way.
5. Key or epoch differ from the expected state or from the challenge's, or
   K2 is the current key: `CONFLICT`.
6. Epoch is `Long.MAX_VALUE`: `EPOCH_EXHAUSTED`.
7. Deletes the challenge; then the guarded
   `UPDATE … WHERE key = expected AND epoch = expected` sets K2,
   `auth_epoch + 1`, `auth_key_installed_at = now` (the server's time, never
   the client's) and `last_device_recovery_id`, and clears `recovery_id` and
   `rotation_id`. Result: `REPLACED`.

Last-device recovery shares the compare-and-set helper with M14 recovery and
M16 rotation (one private function per adapter). The "claim" step is the
challenge consumption instead of a nonce claim. The server-issued challenge
is the single-use value, so no `authentication_nonce` row is written, and
nonces are never cleared. At most one of `recovery_id`, `rotation_id` and
`last_device_recovery_id` is set, and each transition sets its own and
clears the other two.

### Concurrency

| Race | Result |
|---|---|
| 32 identical submissions | one `REPLACED`, 31 `ALREADY_APPLIED`, epoch + 1 once |
| same challenge, different K2 values | exactly one wins; the rest get `CHALLENGE_INVALID` (consumed) or `CONFLICT` |
| last-device recovery vs M14 recovery from the same state | exactly one CAS winner; the loser gets `recovery_conflict` or `last_device_recovery_conflict`; a losing last-device recovery consumes nothing |
| last-device recovery vs M16 rotation from the same state | exactly one winner; the loser gets `device_auth_rotation_conflict` or `last_device_recovery_conflict` |

These are tested in the storage contract (in-memory, SQLDelight in-memory and
file-backed SQLite) and in `server:core` with gated storage that holds both
verified transitions before either commits.

### Stale recovery

The sequence K1 → K2 (last-device recovery), then K2 → K3 (rotation or
recovery), then a replay of the first recovery is rejected:

- the rotation cleared `last_device_recovery_id`, so the replay is no exact
  retry;
- its challenge is consumed, so it is `challenge_invalid`, even after a new
  challenge was issued, because the old statement does not match it.

K3 stays authoritative. The same holds across server restarts.

## Client state

`DeviceAuthenticationKeyStore` has a third pending slot next to the M14
recovery key and the M16 rotation key:

| Operation | Effect |
|---|---|
| `prepareLastDeviceRecovery()` | creates the pending key K2 once (`ProtocolEngine.createDeviceAuthenticationKey`), reuses it later; the active key (if any) untouched; no network |
| `completeLastDeviceRecovery(recoveryKey)` | challenge → authorize → submit → promote K2 in one transaction after the server accepted |
| `recoverLastDevice(recoveryKey)` | prepare + complete |
| `resolveLastDeviceRecovery()` | K2 registration probe; promotes if the server holds K2 |
| `cancelLastDeviceRecovery()` | removes the pending key |

- The three pending slots are mutually exclusive, in storage and in the
  client. `prepareLastDeviceRecovery` throws
  `DeviceAuthenticationRecoveryInProgress` or
  `DeviceAuthenticationRotationInProgress` while another transition is
  pending. M14 and M16 preparation throw `LastDeviceRecoveryInProgress` while
  a last-device recovery is pending.
- `rotateDeviceAuthenticationKeyIfNeeded` returns `RecoveryInProgress`, and
  `DeviceAuthenticationRotationStatus.pendingRecovery` is also `true` for a
  pending last-device recovery.
- All last-device recovery steps of one client instance run under
  `deviceAuthenticationMutex`. Network requests never run inside a storage
  transaction.
- `storage:client:sqldelight` keeps K2 in
  `device_authentication_last_device_recovery_key`, sealed as **record type
  10** (docs/storage-encryption.md). It is listed in `SEALED_COLUMNS` and
  re-encrypted by storage key rotation. A damaged record fails closed and is
  never replaced by a new key. Promotion reseals it as record type 7. The
  table was added by schema version 12 (`11.sqm`).
- The offline recovery key is **never** stored by the client. The application
  passes it to `completeLastDeviceRecovery` and keeps it wherever it keeps
  offline secrets.
- `initialize()` is unchanged: a lost active key still fails closed with
  `InconsistentStorage` until promotion.

### Lost response and restarts

If the server committed but the client did not get the response, or crashed
before promotion, K2 is already registered. The next
`completeLastDeviceRecovery` proceeds as follows:

1. It gets a challenge for the new state (epoch + 1, key K2).
2. It submits a statement with K2 as replacement, which the server rejects
   as `last_device_recovery_conflict` (K2 is the current key).
3. The client then runs the registration probe (`PUT …/registration` signed
   by K2). Exactly-registered gives `204`, so the client promotes K2. There is
   no second transition, and the epoch grew once.

The client also probes after `last_device_recovery_expired` and
`last_device_recovery_challenge_invalid`. `resolveLastDeviceRecovery()` runs
only the probe. Other failures (network, `proof_invalid`, `not_configured`)
keep the pending key for another attempt.

**Probe caveat (same as M14 and M16):** the probe is an ordinary
registration. If the server had no registration at all for the address, the
probe would register K2 as a first registration. That cannot happen through
recovery, because the target must be registered, and there is no device
deletion. If deletion is ever added, the probe needs revisiting.

## HTTP summary

| Route | Auth | Success | Errors |
|---|---|---|---|
| `PUT …/last-device-recovery/key` | ServerAuth v1 (registered device of the user) | `201` created, `204` same key | `400 invalid_last_device_recovery_key`, `401` auth codes, `409 last_device_recovery_key_conflict` |
| `POST …/last-device-recovery/challenge` | public | `200` challenge | `404 last_device_recovery_target_not_registered`, `404 last_device_recovery_not_configured` |
| `PUT …/last-device-recovery` | public (both signatures in the body) | `204` replaced or already applied | `400 invalid_last_device_recovery`, `401 last_device_recovery_challenge_invalid`, `401 last_device_recovery_expired`, `401 last_device_recovery_proof_invalid`, `404 …_not_configured`, `404 …_target_not_registered`, `409 last_device_recovery_conflict`, `409 device_auth_epoch_exhausted` |

Unexpected failures return `500 {"error":"internal_error"}`.
`KtorSecureMessageTransport` maps these responses as follows:

- to `SecureMessageTransportException.LastDeviceRecoveryKeyRejected`
  (`INVALID`, `CONFLICT`);
- to `SecureMessageTransportException.LastDeviceRecoveryRejected`
  (`INVALID_REQUEST`, `NOT_CONFIGURED`, `TARGET_NOT_REGISTERED`,
  `CHALLENGE_INVALID`, `EXPIRED`, `INVALID_PROOF`, `CONFLICT`,
  `EPOCH_EXHAUSTED`).

## Server storage

Server schema version 5 (`4.sqm`, docs/server-storage.md); M19's version 6
(`5.sqm`) replaces `last_device_recovery_key` by
`last_device_recovery_key_state` and adds the challenges' recovery key
epoch (docs/recovery-key-lifecycle.md). As shipped by M18:

- `device_registration.last_device_recovery_id BLOB` (NULL for existing
  rows);
- `last_device_recovery_key(user_id PK, public_key, registered_at)`;
- `last_device_recovery_challenge(user_id, device_id PK, challenge_id UNIQUE,
  challenge_nonce, auth_epoch, auth_public_key, issued_at, expires_at)`,
  indexed by `expires_at`.

The frozen fixture is `ServerVersion4Schema`. `open` refuses format 4 until
the host migrates it. Registrations, epochs, installation times,
recovery/rotation IDs, nonces, prekeys, tombstones, the mailbox and its
sequence are kept.

## Usage

```kotlin
// While the device is healthy, once:
val recoveryKey = client.createLastDeviceRecoveryKey()
showToUserForOfflineBackup(recoveryKey.encode())   // application's responsibility
client.registerLastDeviceRecoveryKey(recoveryKey)

// After every device-auth key is lost (messaging identity still present):
val key = LastDeviceRecoveryKey.decode(userTypedText)
client.recoverLastDevice(key)                      // prepare + challenge + submit + promote
client.initialize()
client.receive()
```

## Tests

- `core:protocol` `LastDeviceRecoveryTest`: frozen vectors, strict text
  decoding, redaction, field binding, wrong keys, cross-domain rejection.
- `storage:testing` `LastDeviceRecoveryRepositoryContractTest` (in-memory,
  SQLDelight in-memory, file-backed):
  - registration once and never replaced;
  - challenge reuse, replacement and pruning;
  - single use, exact retry, expiry, conflict and stale replay;
  - epoch exhaustion;
  - races with itself, M14 and M16;
  - other state untouched.

  `ClientStorageContractTest` covers the new pending slot.
- `storage:server:sqldelight`:
  - `SqlDelightServerLastDeviceRecoveryTest`: restarts, stale replay,
    rollback;
  - `SqlDelightServerMigrationTest`: 1/2/3/4 → 5 and fixture shape;
  - `SqlDelightServerStorageOpenTest`: refuses formats 1–4 (1–5 since M19).
- `server:core` `LastDeviceRecoveryServerTest`:
  - provisioning rules;
  - every rejection and the check order;
  - old key rejected, new key at once;
  - mailbox and prekeys kept;
  - gated races with M14 and M16.
- `server:ktor` `LastDeviceRecoveryRoutesTest`:
  - status mapping and malformed bodies;
  - the Ktor client against the routes;
  - lost response;
  - SQLDelight restarts;
  - `internal_error`.
- `client:core` `LastDeviceRecoveryTest`:
  - full flow with messaging, verification and safety numbers unchanged;
  - provisioning and pending-key reuse;
  - mutual exclusion;
  - lost response, explicit probe and promotion failure;
  - competing transition and expired challenge.
- `storage:client:sqldelight` `LastDeviceRecoveryStorageTest`:
  - sealed record type 10 and restarts;
  - storage key rotation;
  - corruption and cross-type records;
  - crash before promotion;
  - schema 11 → 12 against `Version11Schema`.
- `storage:encryption` `StorageCipherTest` (type 10 vector, computed
  independently) and `ClientRecordCipherTest`.

## Limitations

- The offline recovery key must be protected by the application and the user.
  The library only hands it out once and never stores it.
- Losing the recovery key and every device authentication key means there is
  no recovery path. There is no admin override.
- Stealing the recovery key grants server-authentication recovery authority
  over every device of the user.
- M18 had no recovery key rotation or revocation. Milestone 19 adds both,
  with two authorities (a registered device of the user and the current
  offline key; docs/recovery-key-lifecycle.md). A **lost** recovery key can
  be replaced only by the delayed, cancellable reset of milestone 23
  (docs/recovery-key-reset.md): a registered device requests it, every device
  and the current key can see and cancel it during the server's policy
  delay, and it completes with the new key's proof of possession. The
  current key stays authoritative for last-device recovery until the
  completion, which removes every outstanding challenge.
- There is no human or account identity proof. The recovery key is the
  authority.
- There is no messaging identity or session recovery, no backup and no TOFU
  reset.
- The public challenge endpoint reveals registration, configuration and the
  auth epoch. There is no general rate limiting.
- There is no sealed sender; the server still sees routing metadata.
