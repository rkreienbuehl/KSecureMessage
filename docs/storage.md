# KSecureMessage client storage and local key lifecycle

This document describes how a KSecureMessage client keeps its local protocol
state: the identity key, prekeys and sessions. It also defines what a
`ClientStorage` implementation must guarantee.

Contracts: `storage/core/.../storage/ClientStorage.kt`.
Lifecycle: `client/core/.../client/SecureMessageClient.kt` and `PreKeyManager.kt`.

## Sensitive data at rest

**Storage adapters persist raw secret key material.** This covers the
identity private key, signed and one-time prekey private keys, and session
state (`SecureSession.state`, which contains the ratchet chain keys). Neither
adapter encrypts these bytes. A persistent database is not a secure database.

Until encryption at rest exists (a later milestone), the application must
protect the storage with platform means. Examples are an app-private data
directory, full-disk or file protection classes, or an encrypted SQLite build.
Key bytes and session state never appear in logs, exception messages or
`toString()`.

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
2. If there is no current signed prekey, create and store one. It is signed by the identity.
3. If fewer than `PreKeyConfiguration.oneTimePreKeyTarget` one-time prekeys
   (default 100) are stored, create only the missing number.

`initialize()` is idempotent. A second call, or a call after an app restart
on the same storage, changes nothing unless one-time prekeys were consumed
since the last call. Sessions are never touched.

Initialization is explicit. Other operations do not create state. Without
a stored identity they throw `SecureMessageClientException.NotInitialized`.
The client caches nothing, and every operation reads storage.

Key material is always created by the `ProtocolEngine`. Storage only persists
it.

## Prekeys

### Signed prekeys

The current signed prekey is the one to publish. `rotateSignedPreKey()`
creates a new current signed prekey. The replaced one stays stored and
available by ID. A `PreKeyMessage` created from an older bundle names the old
ID, and its private key is needed to accept it. No signed prekey is deleted
yet: there is no retention policy and no time-based rotation.

### One-time prekeys

A one-time prekey is deleted when a session is accepted with it. That
happens in the same transaction that stores the new session.
The next `initialize()` replaces it with a new key under a new ID.

### ID allocation

`SignedPreKeyId` and `OneTimePreKeyId` are in `0..Int.MAX_VALUE`. Each store
keeps a persisted high-water mark, the highest ID ever stored
(`highestSignedPreKeyId`, `highestOneTimePreKeyId`). Deleting keys does not
lower it. New IDs are allocated upward from `highest + 1`, starting at 0.

- IDs of consumed one-time prekeys are never reused.
- Stores reject a key whose ID is not above the high-water mark.
- There is no wraparound. When the next IDs would pass `Int.MAX_VALUE`,
  `initialize()` or `rotateSignedPreKey()` fails with
  `SecureMessageClientException.PreKeyIdsExhausted` and writes nothing.

### Publication boundary

Publishing is not implemented yet. The client exposes the public material a
publication layer needs:

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
    val sessions: SessionStore
    val preKeys: PreKeyStore
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
  session.
- **Nesting.** A `transaction` call inside a running transaction of the same
  storage joins it, through the receiver or the storage object.
- **Single-call writes.** Store calls outside `transaction` behave as
  single-call transactions.
- **No identity replacement.** `IdentityStore.store` fails if an identity
  exists.
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

### `storage:inmemory`

`InMemoryClientStorage` is not persistent. It is meant for tests and examples.
Its committed state is one immutable snapshot. A transaction works on a copy
and replaces the snapshot only when the block returns normally. A failed
block drops the copy. A `Mutex` serializes transactions. Byte arrays are
copied on store and on load.

### `storage:sqldelight`

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

- `local_identity`: one row
- `signed_pre_key`
- `one_time_pre_key`
- `pre_key_state`: one row holding the current signed prekey ID and both high-water marks
- `session`: keyed by remote user and device ID

Keys and session state are opaque BLOBs, and the schema does not depend on
Kodium internals. All IDs have a `CHECK (id BETWEEN 0 AND 2147483647)`
constraint. The schema version is 1. Migrations will be added as `.sqm` files
when it changes.

The tests run on JVM (file database) and Apple/native targets. They cover the
contract, closing and reopening the database, on-disk rollback, and a
client restart that continues an existing session.
JS/Wasm have no SQLDelight tests: the web worker driver needs a browser worker.
The linuxX64 and mingwX64 test binaries link against the target's `libsqlite3`,
so they are only linked and run on a Linux or Windows host.

## Not covered yet

- Remote identity trust (TOFU, safety numbers, identity change handling).
  The identity key in a first-contact message is accepted without checks.
- Publishing prekeys to a server and tracking what the server handed out.
- Simultaneous session initiation by both sides.
- Signed prekey retention and scheduled rotation.
- Encryption at rest.
