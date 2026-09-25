# Persistent server storage (milestone 13)

`storage:server:sqldelight` (package
`dev.kreienbuehl.ksecuremessage.storage.server.sqldelight`) persists the four
server repositories of `storage:core` on SQLite through SQLDelight:

| `ServerStorage` property | Contract | Tables |
|---|---|---|
| `devices` | `DeviceRegistrationRepository` | `device_registration` |
| `authenticationNonces` | `AuthenticationNonceRepository` | `authentication_nonce` |
| `preKeys` | `PreKeyRepository` | `device_prekey_state`, `available_one_time_prekey`, `consumed_one_time_prekey` |
| `mailboxes` | `MailboxRepository` | `mailbox_message` |

It has the same semantics as `InMemoryServerStorage`; both run the same
contract tests from `storage:testing`. `SecureMessageServer` and the Ktor
routes depend only on `ServerStorage`, never on SQLDelight.

The module is JVM only, like `server:core` and `server:ktor`. Its main
dependencies are `storage:core` (and through it `core:model`,
`core:protocol`), the SQLDelight runtime and kotlinx-coroutines. It does not
depend on any `storage:client:*` module, `storage:encryption`,
`storage:keyprovider:*`, `storage:rotation:core` or `client:core`. (Its tests
use `storage:testing`, which brings `storage:encryption` onto the test
classpath only.)

## Driver injection and ownership

The host application creates, configures and owns the `SqlDriver`:

```text
host creates the driver (location, driver type, connection settings)
host creates the schema (SqlDelightServerStorage.Schema)
host opens the storage:   SqlDelightServerStorage.open(driver)
host closes the driver on shutdown
```

`SqlDelightServerStorage` never creates, configures or closes a driver and
has no `close()`. It contains no file paths, JDBC URLs, pools or lifecycle
policy. Its public API only names the SQLDelight `SqlDriver` abstraction,
never a concrete driver class.

JVM example (host configuration, not library policy; the path is the host's
choice):

```kotlin
val driver = JdbcSqliteDriver("jdbc:sqlite:/var/lib/myserver/server.db", Properties(), SqlDelightServerStorage.Schema)
val storage = SqlDelightServerStorage.open(driver)
embeddedServer(Netty) {
    install(ContentNegotiation) { json() }
    routing { kSecureMessageRoutes(SecureMessageServer(storage)) }
}.start(wait = true)
// on shutdown: driver.close()
```

`JdbcSqliteDriver(url, properties, Schema)` creates the schema in a new
database and tracks its version in `PRAGMA user_version`. A host that manages
the schema itself calls `SqlDelightServerStorage.Schema.create(driver)` once
for a new database. `open` creates nothing: it reads the single-row
`server_storage` marker and throws `IllegalStateException` (without SQL
details) if the database has no server schema or an unknown format.

`open(driver, dispatcher)` takes an optional `CoroutineDispatcher`
(default `Dispatchers.IO`) for the blocking driver calls.

There is no pooling abstraction. The JDBC SQLite driver opens one connection
per thread on a file database; a production host may choose another driver or
connection strategy later, as long as it is SQLite compatible and
synchronous.

## Supported databases: SQLite only

A configurable `SqlDriver` is not the same as support for arbitrary SQL
databases. The schema and queries use the SQLite dialect (`INSERT OR IGNORE`,
`INTEGER PRIMARY KEY AUTOINCREMENT`, BLOB columns). Supported are
SQLite-compatible, synchronous SQLDelight drivers, for example the JVM JDBC
SQLite driver. Asynchronous drivers (R2DBC, web worker) are not supported.
PostgreSQL, MySQL and other databases are not supported. They would get their
own dialect-specific module, for example

```text
storage/server/
├── inmemory
├── sqldelight        (SQLite)
└── postgresql
```

or `sqldelight-sqlite` / `sqldelight-postgresql` if SQLDelight dialect
separation proves useful. None of this exists yet.

## Schema (server schema version 1)

Defined in `ServerState.sq`, independent of the client schema (client version
8+ does not apply here); there are no `.sqm` migrations yet. Later versions
add `.sqm` files with server-own numbering. Timestamps are epoch
milliseconds. Uniqueness is enforced by the database, not only by Kotlin:

| Table | Key / constraint | Columns |
|---|---|---|
| `server_storage` | `id = 0` (single row) | `format` = 1 |
| `device_registration` | PK `(user_id, device_id)` | `auth_public_key` |
| `authentication_nonce` | PK `(user_id, device_id, nonce)`, index on `request_timestamp` | `request_timestamp` |
| `device_prekey_state` | PK `(user_id, device_id)` | `identity_key`, `signed_pre_key_id`, `signed_pre_key`, `signed_pre_key_signature` |
| `available_one_time_prekey` | PK `(user_id, device_id, pre_key_id)` | `public_key` |
| `consumed_one_time_prekey` | PK `(user_id, device_id, pre_key_id)` | (tombstone) |
| `mailbox_message` | `sequence INTEGER PRIMARY KEY AUTOINCREMENT`, index `(recipient_user_id, recipient_device_id, sequence)` | sender/recipient address, `envelope_id`, `protocol_version`, `payload` BLOB |

No statement uses `INSERT OR REPLACE`: a conflict never overwrites stored
data.

## Transaction semantics

Every repository call is exactly one SQLite transaction. If it throws, all of
its writes roll back. Calls of one storage instance are serialized by a
mutex.

- **Registration**: `INSERT OR IGNORE`; one inserted row = first
  registration (`true`). Otherwise the stored key is compared in the same
  transaction: equal = idempotent `false`, different =
  `DeviceRegistrationException.Conflict`, nothing written.
- **Nonce claim**: `DELETE ... WHERE request_timestamp < pruneBefore`, then
  `INSERT OR IGNORE` of the nonce, in one transaction. `true` only if the row
  was inserted. The prune commits also when the claim returns `false`, like
  the in-memory repository. The ±5 minute window and `pruneBefore` stay
  `DeviceAuthenticator` policy (server clock outside the repository).
- **Nonce claim vs. protected operation**: separate transactions, on purpose.
  The claim commits first; the publication or drain runs afterwards in its own
  transaction. A failed operation never un-claims its nonce (M12, at most one
  execution per signed request; docs/server-authentication.md).
- **Prekey publication**: repeated IDs are rejected before the database is
  touched. Then one transaction checks the identity key, the signed prekey
  (higher ID replaces, same ID with same bytes is a no-op, same ID with other
  bytes or a lower ID conflicts), writes the signed prekey, and for each
  one-time prekey skips consumed IDs, accepts identical ones, inserts new ones
  and throws `OneTimePreKeyConflict` for other bytes. Any conflict rolls back
  the signed prekey update and every inserted one-time prekey.
- **Bundle consumption**: one transaction loads the device state, selects the
  lowest available one-time prekey, deletes it and inserts its tombstone. No
  two callers get the same one-time prekey; a consumed ID is never available
  again, also after re-upload and restart.
- **Enqueue**: one insert transaction; `enqueue` returns only after the
  commit, so `POST /v1/messages` answers `202` only for a stored envelope.
- **Drain**: one transaction selects the recipient's rows `ORDER BY sequence`
  and deletes exactly those (all rows up to the highest selected sequence;
  sequences only grow). Returned only after the commit; if the transaction
  fails, the mailbox is unchanged.

Byte arrays are copied on the way in and out. Nothing is logged by the
adapter.

## Ordering and concurrency

`mailbox_message.sequence` is `AUTOINCREMENT`: SQLite never reuses a
sequence, also after a drain or a restart. `ORDER BY sequence ASC` is the
global enqueue order, which preserves every (sender, recipient) stream
(docs/transport-ordering.md); nothing stronger is promised across senders.

Concurrent calls on one instance are serialized, so registration races have
exactly one winner, concurrent identical nonce claims exactly one success,
concurrent bundle fetches distinct one-time prekeys, and concurrent drains of
one recipient return each envelope once (the first drain takes the queue, the
others get nothing). The contract suites run these races on in-memory SQLite
and on file-backed SQLite (one JDBC connection per thread, real SQLite
transactions).

Use one storage instance per database, in one process. Several instances or
processes on one file are not supported: SQLite would serialize writers with
`SQLITE_BUSY` errors instead of waiting.

## Persistence and restart

After the host closes the driver and opens the same database with a new
driver and a new storage instance:

- registrations are kept and still never replaced;
- claimed nonces are kept until pruned, so a replay inside the window is
  rejected after a restart;
- prekey state, available one-time prekeys and tombstones are kept; a
  consumed one-time prekey stays consumed after re-upload;
- queued envelopes are kept in order, drained ones stay gone.

These are tested with real temporary database files, closing the old driver
(`SqlDelightServerPersistenceTest`, `server:ktor` `SqlDelightHttpEndToEndTest`).

## Errors

Domain exceptions are unchanged (`DeviceRegistrationException`,
`PreKeyPublicationException`); `null` for an unknown device's bundle stays
`404 device_not_found`. Other failures (SQL errors, I/O) propagate from the
repository; the Ktor routes answer them with `500 {"error":"internal_error"}`
and log them on the server, never putting the exception text (which can name
tables or statements) into the response.

## What the database contains

It contains public device authentication keys, public identity keys and
prekeys with signatures, opaque encrypted envelopes with routing metadata
(sender and recipient addresses, envelope ID, protocol version) and nonce
replay metadata (nonce, request timestamp). It does not contain client
private keys, session secrets or application plaintext. The server database
is not encrypted; that is out of scope, like backups.

## Tests

```bash
./gradlew :storage:server:sqldelight:test
./gradlew :server:ktor:test --tests "*SqlDelightHttpEndToEndTest"
```

- `SqlDelight*RepositoryTest` / `FileBacked*RepositoryTest`: the four shared
  contracts on in-memory and on file-backed SQLite.
- `SqlDelightServerPersistenceTest`: restart persistence.
- `SqlDelightServerRollbackTest`: failure injection through a delegating
  driver (`TestDriver`), one test per operation.
- `SqlDelightServerStorageOpenTest`: driver injection, schema marker, driver
  ownership, database-level uniqueness.

## Limitations

- SQLite only, single node, one storage instance per database; no PostgreSQL,
  clustering, HA or distributed locking.
- No server database encryption, backup, mailbox expiry, quotas or background
  cleanup jobs (nonces are pruned only by claims).
- No device reset or auth-key recovery; no sealed sender.
