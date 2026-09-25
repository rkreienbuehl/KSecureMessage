# Storage key rotation

Milestone 11. Replaces the storage key that seals the client storage records
(docs/storage-encryption.md) with a new key, re-encrypts every record, and
then retires the old key, without a window in which a record needs a key
that no longer exists.

This is **storage key rotation**. It is unrelated to **signed prekey
rotation** (docs/signed-prekey-lifecycle.md), which replaces a protocol key.
Storage key rotation never touches protocol keys, prekey lifecycle
timestamps, sessions, pins or messages; it only changes which key encrypts
them at rest.

Rotation is explicit. There is no scheduler, background worker or remote
trigger: the application decides when to call it.

```kotlin
val storage = SqlDelightClientStorage.open(driver, keyProvider)

storage.rotateStorageKey()                       // new key current; returns its ID
while (storage.resumeStorageKeyRotation(256).phase != StorageKeyRotationPhase.STABLE) {
    // one bounded, transactional step per call; safe to stop at any point
}
storage.storageKeyRotationStatus()               // phase, key IDs, remaining records
```

The API lives on `SqlDelightClientStorage`, not on `SecureMessageClient`:
messaging code needs no knowledge of it. Calling a rotation function inside a
`transaction { }` of the same storage throws `IllegalStateException`.
`StorageKeyRotationPhase`, `StorageKeyRotationStatus` and
`StorageKeyRotationInProgressException` are in
`dev.kreienbuehl.ksecuremessage.storage.rotation` (module `storage:rotation:core`).

## Architecture

The state machine is independent of SQLDelight, so another persistent storage
adapter can reuse it instead of copying it:

| module | owns |
|---|---|
| `storage:rotation:core` | `StorageKeyRotationManager` (the state machine: step order, key ID allocation rule, provider calls, read-back check, zero-reference rule, which provider results are acceptable in which phase), `StorageKeyRotationState` (validated state per phase), `StorageKeyRotationBackend` (the contract), phase, status, in-progress exception |
| `storage:client:sqldelight` | `SqlDelightStorageKeyRotationBackend`: the `storage_encryption` row and its phase encoding, SQL transactions and compare-and-set updates, key checks, re-encryption batches, `SEALED_COLUMNS` and the key reference scan; `SqlDelightClientStorage` delegates its three rotation functions to the manager |
| `storage:keyprovider:*` | key material only (`createKey`, `key`, `removeKey`) |
| `storage:encryption` | `StorageKeyId`, `StorageEncryptionKey`, `StorageKeyProvider`, record format v1, AES-GCM, associated data |

Dependencies: `storage:encryption` ← `storage:rotation:core` ←
`storage:client:sqldelight`. The rotation core has no SQL, no platform code
and no AEAD. Each backend method is one atomic storage step; transitions are
compare-and-set on the state the manager read, and the manager calls the
provider only between them, inside `exclusive { }`, which serializes the step
with every storage transaction. The zero-reference proof stays atomic with the
RETIRING commit: `markRetiring` runs the backend's scan and the manager's check
in the same transaction. Generic state consistency (which key IDs each phase
has, high-water mark) is validated by `StorageKeyRotationState.of`; the backend
validates only its own columns (key checks) and maps the persisted phase codes.

A new backend implements `StorageKeyRotationBackend`: persist the state and a
key ID high-water mark, make each transition a single atomic compare-and-set,
re-encrypt a bounded batch per `migrateBatch`, and scan every location that can
hold a sealed record in `keyReferences`. It then wraps
`StorageKeyRotationManager(backend, keyProvider)`.

## Invariant

A storage key is never removed from the provider while any record in the
database may still need it. Every step below keeps that true across crashes,
restarts, cancellation, provider failures and damaged records.

## Who owns what

- **The database is the authority** for rotation state: which key is
  current, which key is being retired, the phase, and the key ID high-water
  mark. The state is persisted in the `storage_encryption` row, never kept
  only in memory, and never inferred from the number of keys a provider
  holds.
- **The provider holds key material** only: create a key under a given ID,
  return a key by ID, remove a key by ID. It does not know which key is
  current (the Android file's `currentKeyId` field is not used for that; see
  below).

The two are not one transactional system, so the order of steps is chosen
such that the database never records a state that needs a key whose
durability is not already proven.

## State machine

Schema version 7 (`6.sqm`) adds to `storage_encryption`:

| column | meaning |
|---|---|
| `highest_key_id` | key ID high-water mark; never lowered |
| `rotation_phase` | 0 STABLE, 1 PREPARING, 2 MIGRATING, 3 RETIRING |
| `next_key_id` | allocated key, while PREPARING |
| `retiring_key_id` | previous key, while MIGRATING and RETIRING |
| `retiring_key_check` | key check sealed with the previous key, while MIGRATING |

`key_id` / `key_check` (milestone 9) remain the **current** key and its check.

| phase | current | keys needed to open | new records sealed with | leaves when |
|---|---|---|---|---|
| STABLE | K | K | K | `rotateStorageKey()` allocates N |
| PREPARING | K (N allocated) | K | K | N created in the provider, read back, activated |
| MIGRATING | N (K retiring) | N and K, each proven by its key check | N | no record uses K (full scan) |
| RETIRING | N (K retiring) | N | N | K removed from the provider (or already gone) |

Transitions (each one database transaction; provider calls happen between
them, outside any transaction):

1. **STABLE → PREPARING.** `next_key_id = highest_key_id + 1`,
   `highest_key_id = next_key_id`. Committed before the provider is asked, so
   the ID is never allocated twice.
2. **Provider:** `createKey(N)` (returns the existing key if N already
   exists), then `key(N)`; both must return the same 32 bytes under ID N.
3. **PREPARING → MIGRATING.** A key check sealed with N becomes `key_check`,
   the old check moves to `retiring_key_check`, `retiring_key_id = K`,
   `key_id = N`. The storage instance switches to a cipher that seals with N
   and opens records of N and K.
4. **MIGRATING, batches.** Each `resumeStorageKeyRotation(maxRecords)` call
   re-encrypts up to `maxRecords` records in one transaction (below).
5. **MIGRATING → RETIRING.** When no record is left, one transaction clears
   `retiring_key_check`, scans every sealed value, and commits only if every
   record names N. The instance drops K from memory.
6. **Provider:** the scan runs again; then `removeKey(K)`. `false` (K is
   already gone) is accepted here, and only here.
7. **RETIRING → STABLE.** `retiring_key_id = NULL`.

Each transition statement checks the phase and key IDs it leaves, so a stale
or concurrent caller changes nothing. Steps 1–7 are driven by
`StorageKeyRotationManager`; the database parts are the SQLDelight backend.

### Crash windows

| crash after | state on restart | open needs | what resume does |
|---|---|---|---|
| 1 (ID allocated) | PREPARING, N may not exist | K | creates N, activates it |
| 2 (N persisted) | PREPARING, N exists but unused | K | `createKey(N)` returns the existing N, activates it |
| 3 (activated) | MIGRATING, all records on K | N and K | re-encrypts |
| 4 (some batches) | MIGRATING, mixed | N and K | continues with the remaining records |
| 5 (proven) | RETIRING, K still in the provider | N | removes K, finishes |
| 6 (K removed) | RETIRING, K gone | N | `removeKey(K)` returns `false`, finishes |
| 7 | STABLE on N | N | nothing |

`rotateStorageKey()` in PREPARING finishes the interrupted start with the
already allocated ID; it never allocates another one. In MIGRATING or
RETIRING it throws `StorageKeyRotationInProgressException` (with the
current status); finish the running rotation first.

A key created in step 2 by a rotation the application never resumes stays in
the provider unused. That is an **orphan key**: harmless (no record uses it,
the database does not name it as current). Milestone 11 never deletes
provider keys the database does not name as retiring, because it cannot
prove that such a key is unused by anything else in the namespace. Leaking a
key is preferred to deleting one that is still needed. If the provider
already holds a key under the allocated ID (for example an item left from an
earlier installation that used the same namespace), `createKey` returns that
key unchanged and the rotation uses it; it was never used by this database.

## Key ID allocation

Key IDs come from the database's `highest_key_id`, never from the number of
provider keys. The first key is 1 (milestones 9 and 10); rotations produce 2,
3, … IDs are never reused, not even after a key is retired, and do not wrap
around: when `highest_key_id` is `Int.MAX_VALUE`, `rotateStorageKey()` throws
`StorageEncryptionException.KeyIdsExhausted` and changes nothing. Providers
accept the ID they are given; Android and Apple never pick IDs themselves.

## New writes and mixed-key reads

From the activation commit on, every new or rewritten record (sessions,
prekeys, pending frames, …) is sealed with the new key. Nothing continues to
write the old key, which makes the migration converge.

Every record names its key in its header (`keyId` of record format v1). While
MIGRATING, the storage opens a record with the key the header names, which
must be the current or the retiring key; a record naming any other key fails
with `KeyUnavailable`. The current key is never assumed for an existing
record. Outside MIGRATING only the current key is loaded.

Every top-level storage transaction first compares the database's key state
with the instance's keys and fails with `KeyUnavailable` if they differ, for
example when another instance (or process) rotated the key. A stale instance
therefore can never seal a record with a key that is being retired; it has to
be opened again. As before, use one `SqlDelightClientStorage` per database.

## Re-encryption

Order (fixed, for reproducible progress, not for security): local identity,
signed prekeys by ID (current and grace period), one-time prekeys by ID,
sessions by remote address, pending outbound frames by sequence. The key
checks are not re-encrypted: activation writes a new one and retirement drops
the old one.

A batch selects rows whose record does **not** start with the current key's
header (so malformed or foreign records are selected too and fail the batch
instead of being skipped), and for each:

1. opens it with the typed opener and the same row key as always (so the
   same associated data: header, domain, record type, row key fields);
2. seals the identical plaintext with the current key, with the same row key,
   and a fresh random nonce (every seal draws a new nonce; an old nonce is
   never reused);
3. `UPDATE`s only the sealed column of that row, by primary key.

Nothing else changes: IDs, `created_at` / `replaced_at`, `sequence`, logical
message IDs, session state bytes, pins, retired initiations, processed IDs,
row IDs and the AUTOINCREMENT high-water mark stay as they were.

Transactions: one per batch. If any record in a batch fails (authentication,
malformed record, unknown key, cancellation), the whole batch rolls back and
the error propagates (`CancellationException` is rethrown, never
swallowed). Batches committed before stay migrated; the rotation stays
MIGRATING, the retiring key is kept, and a later call continues. Mixed-key
state is valid by design here, unlike the milestone 8 → 9 migration, which
had to be all or nothing.

A record that never opens blocks completion forever: the rotation stays
MIGRATING and the old key is retained. Repairing or deleting such a record is
an application decision and not part of milestone 11.

`maxRecords` bounds the work per call (default 256). Correctness never
depends on finishing in one call.

## Key reference proof

The authoritative check before a key is retired is a scan, not a counter.
`SEALED_COLUMNS` lists every column that holds sealed records:

- `local_identity.sealed_identity`
- `device_authentication_key.sealed_key_pair` (milestone 12)
- `signed_pre_key.sealed_key_pair`
- `one_time_pre_key.sealed_key_pair`
- `session.sealed_state`
- `pending_outbound_message.sealed_frame`
- `storage_encryption.key_check`
- `storage_encryption.retiring_key_check`

The scan reads every non-NULL value of these columns and parses its header
(`SealedRecords.keyId`; nothing is decrypted). A value that is not a
well-formed record throws. Retirement commits only if every value names the
current key. The same scan runs again before the provider key is removed.

`sealedColumnsCoverEverySealedValueInTheSchema` checks the list against the
real schema: every BLOB column must be either in `SEALED_COLUMNS` or on an
explicit plaintext list (`remote_identity.identity_key`,
`retired_session_initiation.initiation_id`, the two `message_id` columns). A
new sealed column that is not added to the scan fails that test.

## Opening

`SqlDelightClientStorage.open` reads the phase and loads exactly the keys the
phase needs (table above), each with `StorageKeyProvider.key(id)` (never
`loadOrCreateKey`, never `createKey`), and verifies each with its own key
check using a single-key cipher. It fails closed:

- MIGRATING and the retiring key is missing: `KeyUnavailable`. Records still
  use it; they are never treated as absent, deleted, or declared migrated.
- The current key is missing (MIGRATING or RETIRING, or STABLE): `KeyUnavailable`.
  Opening never rolls the current key back to the previous one; that would be
  an unaudited rollback.
- A key with wrong bytes: `AuthenticationFailed` (key check).
- RETIRING and the retiring key is missing: expected, opens.
- Inconsistent rotation columns (e.g. MIGRATING without a retiring key, a
  `highest_key_id` below a used ID): `MalformedRecord`; an unknown phase:
  `UnsupportedFormat`.

Opening never advances, finishes or reverts a rotation, and a failed open
changes nothing.

## Existing databases

`6.sqm` only adds the columns and sets `highest_key_id = key_id`. A milestone
9/10 database becomes STABLE on its bound key (normally 1). Nothing is read,
decrypted or re-encrypted on upgrade. Milestone 8 databases still get
encrypted by the first `open` (now also setting `highest_key_id`).
`Version6Schema` is the frozen pre-M11 fixture;
`milestone10DatabaseIsStableOnItsKeyWithoutReEncryption` checks that every row
survives byte for byte.

## Provider operations

`StorageKeyProvider` (docs/storage-key-providers.md) gained:

- `createKey(id)`: returns key `id`, creating and persisting it (read back
  before returning) only if the provider does not have it; never overwrites or
  replaces a key; other keys untouched; concurrent calls for one ID yield one
  key. Requires an already provisioned provider, otherwise `KeyUnavailable`.
- `removeKey(id)`: removes exactly that key; `true` if removed, `false` if
  absent; never removes the provider's last key (`IllegalStateException`,
  nothing changed). There is no "delete all".
- `loadOrCreateKey()`: now fails with `KeyUnavailable` if the provider holds
  several keys (a namespace mid-rotation); with one key it returns it,
  whatever its ID.

The storage never asks a provider to remove the current key (checked before
the call), and providers refuse to remove their last key.

## Platform support

| provider | multiple keys | removal | tested |
|---|---|---|---|
| Android Keystore (`AndroidStorageKeyProvider`) | one wrapped entry per key ID in the same file | rewrites the file without that entry | emulator/device (`connectedAndroidDeviceTest`) |
| Apple data protection keychain | one item per key ID (`v1/<id>`) | `SecItemDelete` of that one account | signed keychain host (iOS simulator; macOS when signing is configured) |
| Apple legacy macOS keychain | same | same | `macos*Test` |
| `StaticStorageKeyProvider` | keys passed in | forgets it in memory | JVM/native |

Both the provider contract (`StorageKeyProviderContractTest`) and the storage
rotation test (`PlatformKeyProviderStorageTest.storageKeyRotationRetiresThePlatformKey`)
run against each real platform store.

## Limitations

- Manual, explicit rotation only; no schedule, no automatic trigger.
- Orphan provider keys may remain after an abandoned rotation start.
- No key recovery or reset: a lost current key, or a lost retiring key while
  MIGRATING, leaves the database unopenable.
- A record that cannot be opened blocks the rotation; there is no repair.
- Record-level encryption limits (docs/storage-encryption.md) still apply:
  metadata is plaintext, whole-database rollback is not detected, and old
  ciphertext under a retired key may remain in free SQLite pages, the WAL or
  backups until overwritten. Retiring a key does not securely erase anything.
- A compromised process has access to the active keys.
