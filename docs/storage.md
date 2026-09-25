# KSecureMessage client storage and local key lifecycle

This document describes how a KSecureMessage client keeps its local protocol
state: the identity key, prekeys and sessions, and since milestone 8 its
message reliability state. It also defines what a
`ClientStorage` implementation must guarantee.

Contracts: `storage/core/.../storage/ClientStorage.kt`.
Lifecycle: `client/core/.../client/SecureMessageClient.kt` and `PreKeyManager.kt`.

## Sensitive data at rest

Client storage holds secret key material (the identity private key, signed
and one-time prekey private keys), session state (`SecureSession.state`,
which contains the ratchet chain keys) and, since milestone 8, application
message content: the plaintext of every sent message stays in
`PendingOutboundStore` until the recipient acknowledges it
([message-reliability.md](message-reliability.md)). `ProcessedInboundStore`
holds sender addresses and logical message IDs (metadata, no content).

**Since milestone 9 `SqlDelightClientStorage` encrypts these records** with
AES-256-GCM under a storage key from an application-supplied
`StorageKeyProvider`, bound to record type and row key
([storage-encryption.md](storage-encryption.md)). This is record-level
encryption, not database encryption: IDs, addresses, timestamps, pins,
retired initiations and processed message IDs stay plaintext metadata, and
row deletion or rollback of the whole database is not detected. The
protection is only as good as the key storage. `InMemoryClientStorage` does
not encrypt (it persists nothing).

Key bytes, session state and message plaintext never appear in logs,
exception messages or `toString()`.

## Client lifecycle

```kotlin
val client = SecureMessageClient(
    localAddress = address,
    storage = storage,              // InMemoryClientStorage, SqlDelightClientStorage, ...
    protocol = KodiumProtocolEngine(),
    transport = transport,
)
client.initialize()                 // on every start
val bundle = client.currentPreKeyBundle()
val oneTimePreKeys = client.publicOneTimePreKeys()
```

`initialize()` runs one storage transaction:

1. Load the local identity.
   - If it exists, keep it.
   - If it is missing and no prekey state exists, create it (`ProtocolEngine.createIdentity`) and store it.
   - If it is missing but prekeys exist, fail with `SecureMessageClientException.InconsistentStorage`. A new identity would not match the stored prekeys, so the client never creates one silently.
2. Signed prekey maintenance (milestone 7, see
   [signed-prekey-lifecycle.md](signed-prekey-lifecycle.md)): stamp keys stored
   before milestone 7 with the current time, create a current signed prekey if
   there is none or rotate it once it reached
   `PreKeyConfiguration.signedPreKeyRotationAge` (default 7 days), delete
   replaced keys whose `signedPreKeyGracePeriod` (default 30 days) is over,
   and prune retired session initiations that only those keys could accept.
   New signed prekeys are signed by the identity.
3. If fewer than `PreKeyConfiguration.oneTimePreKeyTarget` one-time prekeys
   (default 100) are stored, create only the missing number.

`initialize()` is idempotent. A second call, or a call after an app restart
on the same storage, changes nothing unless one-time prekeys were consumed
or time moved past a rotation or expiry deadline. Sessions are never touched.
Time comes from the client's `clock` parameter (`Clock.System` by default).

Initialization is explicit. Other operations do not create state. Without
a stored identity they throw `SecureMessageClientException.NotInitialized`.
The client caches nothing, and every operation reads storage.

Key material is always created by the `ProtocolEngine`. Storage only persists
it.

## Prekeys

### Signed prekeys

The current signed prekey is the one to publish. `rotateSignedPreKey()`, or
`initialize()` once the current key reached the rotation age, creates a new
current signed prekey. The replaced one stays stored and available by ID for
the grace period. A `PreKeyMessage` created from an older bundle names the
old ID, and its private key is needed to accept it. After the grace period,
new initiations naming it fail with `ExpiredSignedPreKey`, and `initialize()`
deletes it. Established sessions are not affected. Each key stores
`createdAt` and, once replaced, `replacedAt`. See
[signed-prekey-lifecycle.md](signed-prekey-lifecycle.md).

### One-time prekeys

A one-time prekey is deleted when a session is accepted with it. That
happens in the same transaction that stores the new session.
The next `initialize()` replaces it with a new key under a new ID.

### ID allocation

`SignedPreKeyId` and `OneTimePreKeyId` are in `0..Int.MAX_VALUE`. Each store
keeps a persisted high-water mark, the highest ID ever stored
(`highestSignedPreKeyId`, `highestOneTimePreKeyId`). Deleting keys does not
lower it. New IDs are allocated upward from `highest + 1`, starting at 0.

- IDs of consumed one-time prekeys and deleted signed prekeys are never reused.
- Stores reject a key whose ID is not above the high-water mark.
- There is no wraparound. When the next IDs would pass `Int.MAX_VALUE`,
  `initialize()` or `rotateSignedPreKey()` fails with
  `SecureMessageClientException.PreKeyIdsExhausted` and writes nothing.

### Publication boundary

`publishPreKeys()` uploads this public material (see
[prekey-publication.md](prekey-publication.md)). It reads it in one
transaction and does the network call afterwards:

- `currentPreKeyBundle()`: the identity public key and the current signed prekey
  (ID, public key, signature). `oneTimePreKey` is always `null`.
- `publicOneTimePreKeys()`: the public halves of all unused local one-time
  prekeys.

The client does not select, reserve or mark one-time prekeys as handed out.
Which one a fetcher receives is a server concern. Locally a key is only
removed when a session is accepted with it.

## `ClientStorage` contract

```kotlin
interface ClientStorage {
    val identity: IdentityStore
    val remoteIdentities: RemoteIdentityStore
    val sessions: SessionStore
    val sessionInitiations: SessionInitiationStore
    val preKeys: PreKeyStore
    val pendingOutbound: PendingOutboundStore
    val processedInbound: ProcessedInboundStore
    suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T
}
```

Every implementation must provide:

- **Atomic transactions.** If `transaction`'s block throws, none of its writes
  become visible. Otherwise all of them do. This is what keeps the ratchet
  state consistent with sent and received messages. It also makes first
  contact safe: storing the session and removing the one-time prekey commit
  together or not at all. A failure never leaves a stored session with its
  one-time prekey still available, or a removed one-time prekey with no
  session. The first remote identity pin commits with the same transaction
  (see [identity-trust.md](identity-trust.md)). A replaced session, its
  retired initiation and the consumed one-time prekey commit together too
  (see [session-lifecycle.md](session-lifecycle.md)).
- **Nesting.** A `transaction` call inside a running transaction of the same
  storage joins it, through the receiver or the storage object.
- **Single-call writes.** Store calls outside `transaction` behave as
  single-call transactions.
- **No identity replacement.** `IdentityStore.store` fails if an identity
  exists.
- **No pin replacement.** `RemoteIdentityStore.store` is a no-op for the key
  already pinned for an address and fails with `IllegalStateException` for a
  different key. Pins are per `DeviceAddress` and are never removed.
- **Retired initiations are kept until pruned.** `SessionInitiationStore.retire`
  is idempotent (the first entry wins), and entries are per `DeviceAddress`.
  Each entry may name a local signed prekey. Entries are removed only by
  `removeRetiredFor(signedPreKeyId)`, which the client calls after that key
  was deleted.
- **Signed prekey lifecycle.** `storeCurrentSignedPreKey(key, createdAt)` sets
  the previous current key's `replacedAt` to `createdAt` in the same call.
  `signedPreKeyInfos()` returns metadata without key material.
  `removeSignedPreKey` refuses the current key and keeps the high-water mark.
  `stampLegacySignedPreKeys` only fills missing timestamps.
- **Pending outbound messages** (milestone 8). `store(recipient, id, frame)`
  fails with `IllegalArgumentException` if (recipient, id) is pending and
  returns a sequence number that is higher than every earlier one, also after
  removals and restarts. `list(recipient)` is ordered by sequence.
  `remove` returns whether it removed something. The client stores a message
  in the transaction that first encrypts it and removes it in the transaction
  that decrypts its acknowledgement.
- **Processed inbound messages** (milestone 8). `markProcessed` is idempotent
  and scoped by sender. Entries are never removed. The client writes the
  marker in the transaction that decrypts the message.
- **Monotonic prekey IDs**, as described above.
- **No aliasing.** Mutating an array after storing it, or an array returned
  by a load, must not change stored state.

Rules for transaction blocks:

- No network I/O or other long suspension. A transaction holds a lock, and
  `SecureMessageClient` fetches prekey bundles before its transaction starts.
- Do not switch threads or dispatchers. The SQLite drivers bind a transaction
  to the thread that started it.

`storage:testing` contains `ClientStorageContractTest`. Every adapter's tests
extend it.

## Adapters

Client storage adapters live under `storage:client:*`, server repository
adapters under `storage:server:*`; the contracts they implement stay in
`storage:core`. `storage:encryption`, `storage:keyprovider:*` and
`storage:rotation:core` are storage security infrastructure; today they serve
only the persistent client adapter.

### `storage:client:inmemory`

`InMemoryClientStorage` is not persistent. It is meant for tests and examples.
Its committed state is one immutable snapshot. A transaction works on a copy
and replaces the snapshot only when the block returns normally. A failed
block drops the copy. A `Mutex` serializes transactions. Byte arrays are
copied on store and on load.

### `storage:client:sqldelight`

`SqlDelightClientStorage` persists to SQLite through SQLDelight 2.4.0 with
async code generation. It supports all client targets: JVM, Android, iOS,
macOS, linuxX64, mingwX64, JS and Wasm. The application creates the
platform driver and closes it:

| Platform | Driver artifact | Example |
|---|---|---|
| JVM | `app.cash.sqldelight:sqlite-driver` | `JdbcSqliteDriver("jdbc:sqlite:client.db", Properties(), SqlDelightClientStorage.Schema.synchronous())` |
| Android | `app.cash.sqldelight:android-driver` | `AndroidSqliteDriver(SqlDelightClientStorage.Schema.synchronous(), context, "client.db")` |
| Apple, Linux, Windows | `app.cash.sqldelight:native-driver` | `NativeSqliteDriver(SqlDelightClientStorage.Schema.synchronous(), "client.db")` |
| JS, Wasm | `app.cash.sqldelight:web-worker-driver` | web worker driver, async schema |

Use one `SqlDelightClientStorage` instance per database.

Each `transaction` is a SQLite transaction (`SuspendingTransacter.transactionWithResult`).
If the block throws, SQLite rolls back. A `Mutex` serializes transactions of
the instance.

Tables:

- `storage_encryption`: one row with the storage format and the bound storage key ID
- `local_identity`: one row, the sealed key pair
- `device_authentication_key`: one row, the sealed device authentication key pair (schema version 8, milestone 12, [server-authentication.md](server-authentication.md))
- `device_authentication_state`: one row, `awaits_upgrade_key` (plaintext flag: set by the version 8 migration when an identity existed without a key)
- `signed_pre_key`: sealed key pair, with `created_at` and `replaced_at` (epoch milliseconds, nullable)
- `one_time_pre_key`: sealed key pair
- `pre_key_state`: one row holding the current signed prekey ID and both high-water marks
- `session`: sealed state, keyed by remote user and device ID
- `remote_identity`: pinned remote identity public keys, keyed by remote user and device ID
- `retired_session_initiation`: retired 32-byte session initiation IDs, keyed by remote user, device ID and initiation ID, with the nullable local `signed_pre_key_id` used for pruning
- `pending_outbound_message`: `sequence INTEGER PRIMARY KEY AUTOINCREMENT` (never reused), recipient user and device ID, 16-byte `message_id`, and the sealed frame (encrypted; the frame holds the application plaintext); unique per recipient and message ID
- `processed_inbound_message`: sender user and device ID and 16-byte `message_id`

Since schema version 6 the key pairs, session state and pending frames are
in `sealed_*` columns holding encrypted storage records, and
`storage_encryption` (one row) records the storage format and the bound
storage key ID ([storage-encryption.md](storage-encryption.md)). The schema
does not depend on Kodium internals. All IDs have a
`CHECK (id BETWEEN 0 AND 2147483647)` constraint.

Open the storage with `SqlDelightClientStorage.open(driver, keyProvider)`.
There is no unencrypted mode.

The schema version is 8. Version 1 (milestones 3 and 4) had no
`remote_identity` table; `1.sqm` adds it and changes nothing else. Version 2
(milestone 5) had no `retired_session_initiation` table; `2.sqm` adds it and
changes nothing else. Version 3 (milestone 6) had no lifecycle columns;
`3.sqm` adds `signed_pre_key.created_at`, `signed_pre_key.replaced_at` and
`retired_session_initiation.signed_pre_key_id`, all nullable, and changes
nothing else. Upgraded signed prekeys get their timestamps on the next
`initialize()`: the current key counts as created then, older keys start a
full grace period then, and nothing is deleted on that first start
([signed-prekey-lifecycle.md](signed-prekey-lifecycle.md#migration)).
Version 4 (milestone 7) had no reliability tables; `4.sqm` creates
`pending_outbound_message` and `processed_inbound_message`, empty, and
changes nothing else. Messages from before the upgrade are neither pending
nor processed. Version 5 (milestone 8) stored key pairs, session state and
pending frames in plaintext; `5.sqm` only adds `storage_encryption` with
format 0, and the next `SqlDelightClientStorage.open` encrypts every
sensitive record in one transaction, rebuilding the five sensitive tables
([storage-encryption.md](storage-encryption.md#migration-from-milestone-8)).
Plaintext that the old version wrote may survive in free pages, the journal
and backups. Version 6 (milestones 9 and 10) had no storage key rotation
state; `6.sqm` adds it to `storage_encryption` ([storage-key-rotation.md](storage-key-rotation.md)).
Version 7 (milestone 11) had no device authentication key; `7.sqm` creates
`device_authentication_key` (empty) and `device_authentication_state`, whose
flag is 1 if the database held an identity. The migration creates no key
material; the next `initialize()` creates the key once, and a key that goes
missing later fails closed ([server-authentication.md](server-authentication.md#telling-before-m12-apart-from-lost)).
Frozen copies of versions 1–7 (`Version1Schema` … `Version7Schema`) back the
migration tests.
A driver created with `SqlDelightClientStorage.Schema`,
as in the table above, reads SQLite's `user_version` on open and runs the
migrations itself. An application that manages schema versions on its own
calls `SqlDelightClientStorage.Schema.migrate(driver, oldVersion, SqlDelightClientStorage.Schema.version)`.
Existing identities, prekeys, sessions, pins and retired initiations are kept. Sessions from
version 1 have no pin, see
[identity-trust.md](identity-trust.md#sessions-from-before-pinning). Session
BLOBs written before milestone 6 use the older local state format and stay
readable (see [session-lifecycle.md](session-lifecycle.md#persistence-and-compatibility)).

The tests run on JVM (file database) and Apple/native targets. They cover the
contract, closing and reopening the database, on-disk rollback, a client
restart that continues an existing session, remote trust across restarts,
replay protection and simultaneous-initiation resolution across restarts, the
signed prekey lifecycle (grace, expiry, pruning, clock set back) across
restarts, pending messages, duplicate suppression and collision recovery
across restarts, and migrating version 1, 2, 3 and 4 databases. Since
milestone 9 they also check the persisted bytes: sensitive columns hold only
encrypted records, corrupted and swapped records fail closed, wrong and
missing keys fail at open, encryption failures roll back, and a milestone 8
database migrates completely or not at all.
JS/Wasm have no SQLDelight tests: the web worker driver needs a browser worker.
The linuxX64 and mingwX64 test binaries link against the target's `libsqlite3`,
so they are only linked and run on a Linux or Windows host.

## Not covered yet

- Safety numbers, manual verification, and accepting a changed remote
  identity (TOFU itself is described in [identity-trust.md](identity-trust.md)).
- Tracking locally what the server handed out (the server tombstones consumed
  one-time prekey IDs instead, see [prekey-publication.md](prekey-publication.md)).
- Pruning of retired session initiations that name no local signed prekey
  (initiations this device started, entries from before milestone 7).
- A secure or monotonic clock for the signed prekey lifecycle.
- Pruning of processed message IDs (kept forever, see
  [message-reliability.md](message-reliability.md#storage)).
- Platform storage key providers, storage key rotation, rollback protection
  and integrity of plaintext metadata
  ([storage-encryption.md](storage-encryption.md#not-covered)).
