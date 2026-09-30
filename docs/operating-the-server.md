# Operating KSecureMessage

For people who run the reference server (`server:core` + `server:ktor` +
`storage:server:sqldelight`) or ship the client with persistent storage. It
summarizes and links the detailed specifications; where they differ, the
specification wins.

## Reference server

### What it is

`SecureMessageServer` is a blind relay: it stores public prekeys, device
authentication public keys, recovery key state and opaque encrypted
envelopes, authenticates device requests and hands out one-time prekeys once.
It never sees message plaintext or client private keys. `kSecureMessageRoutes`
exposes it as HTTP API v1 on Ktor.

It is **a single-node server on one SQLite database**. There is no
clustering, replication, PostgreSQL adapter, load balancing across processes,
rate limiting, quota, mailbox expiry or background job. Treat it as a
reference implementation to run behind your own TLS termination, access
control and abuse protection, not as a horizontally scalable service.

### Requirements

- JDK 17 or newer (the server modules are compiled for Java 17).
- A SQLite JDBC driver (`app.cash.sqldelight:sqlite-driver`) and a Ktor
  server engine chosen by the host (the sample uses CIO).
- Ktor `ContentNegotiation` with kotlinx JSON installed by the host.

### Startup

```kotlin
val driver = JdbcSqliteDriver("jdbc:sqlite:/var/lib/ksm/server.db", Properties(), SqlDelightServerStorage.Schema)
val storage = SqlDelightServerStorage.open(driver)
// The host decides, with its own authenticated principal, who may add a device to which user (S1, S1.1).
val registrationAuthorizer = DeviceRegistrationAuthorizer<AccountPrincipal> { principal, request ->
    if (request.address.userId == principal.userId && myAccounts.mayAddDevice(principal, request.address)) {
        DeviceRegistrationAuthorizationResult.Authorized
    } else {
        DeviceRegistrationAuthorizationResult.Denied
    }
}
val server = SecureMessageServer(storage, Clock.System, registrationAuthorizer, recoveryKeyResetPolicy = null)
embeddedServer(CIO, port = 8080) {
    install(ContentNegotiation) { json() }
    install(Authentication) { /* the host's own login: session, bearer, OAuth, … */ }
    routing {
        authenticate(optional = true) {
            // null (not logged in) = registration refused; never a shared anonymous principal.
            kSecureMessageRoutes(server) { call -> call.principal<AccountPrincipal>() }
        }
    }
}.start(wait = true)
```

The complete, compiled version is
[`samples/jvm-e2e`](https://github.com/rkreienbuehl/KSecureMessage/blob/main/samples/jvm-e2e/app/src/main/kotlin/dev/kreienbuehl/ksecuremessage/sample/Main.kt).

- The **host owns the driver**: it chooses the file location, creates the
  driver, and closes it. `SqlDelightServerStorage` never creates, configures
  or closes a driver.
- **Schema**: `JdbcSqliteDriver(url, properties, Schema)` creates the schema
  in a new database and migrates an older one (tracked in
  `PRAGMA user_version`). A host that manages schemas itself calls
  `Schema.create` / `Schema.migrate`. `open` never migrates: it refuses a
  database that is not at the current server schema (version 8) with an
  `IllegalStateException`, and stamps key installation times of rows
  migrated from schema 3 or older exactly once. Details:
  [server-storage.md](server-storage.md).
- **One storage instance per database, one process.** SQLite serializes
  writers; several processes or instances on one file are not supported.
- Unexpected failures are answered with `500 internal_error`; the exception
  text is logged, never returned.
- Identifiers from requests (user and device IDs) can contain any UTF-8,
  including line breaks. The routes log them only escaped and quoted
  (`user="a\nb" device="c"`; CR, LF, TAB, other controls, U+2028/U+2029
  escaped), so a request cannot forge log lines (S1, findings F5/F6). A
  log pipeline that unescapes these fields reopens that.

### Shutdown

Stop the HTTP engine (so no request is in flight), then close the driver.
Every repository call is one committed transaction; there is no write-behind
state to flush.

### Upgrades

Library upgrades that change the server schema ship a numbered migration
(`.sqm` files next to `ServerState.sq`). The migration
runs when the host opens the database with `JdbcSqliteDriver(..., Schema)` or
calls `Schema.migrate`. Back up the database before upgrading. There is no
downgrade path.

## Wall clock dependencies

Several server mechanisms compare the server's wall clock (the `Clock` passed
to `SecureMessageServer` and `SqlDelightServerStorage.open`) with timestamps:

| Mechanism | Uses the clock for |
|---|---|
| ServerAuth ([server-authentication.md](server-authentication.md)) | request freshness: ±5 minutes around the client's signed timestamp; nonce pruning |
| Device recovery / rotation ([device-recovery.md](device-recovery.md), [device-authentication-rotation.md](device-authentication-rotation.md)) | statement freshness window; key installation time (`authKeyInstalledAt`) that the client rotation policy compares with its own clock |
| Last-device recovery challenges ([last-device-recovery.md](last-device-recovery.md)) | challenge expiry (issue time + 5 minutes) |
| Recovery key reset ([recovery-key-reset.md](recovery-key-reset.md)) | `requestedAt`, `eligibleAt = requestedAt + delay`, eligibility at completion |

Run the server with reliable time synchronization (NTP or the platform
equivalent) and keep clients synchronized too: a skew above 5 minutes makes
signed requests fail. These are wall-clock comparisons, not monotonic
timers. A server clock set far forward makes pending resets eligible early;
a clock set backward delays them; since S1 it can no longer reopen replay
windows (the nonce prune watermark never moves back), but requests are
refused as replays until the clock has caught up again. Protect the clock
like any other security input.

## DeviceRegistrationAuthorizer

Required since S1 (docs/security-review-remediation.md, findings F1/F2);
since S1.1 (finding N1) it decides with the host's authenticated request
context. Every first registration of a device address, including a user's
first device, is passed to the host's `DeviceRegistrationAuthorizer<C>`
after the request proved possession of the device key and before anything
is stored. KSecureMessage has no account system: the host authenticates the
HTTP call itself (its login, session, bearer token, OAuth subject,
enrollment grant) and hands the resulting principal to the registration
route through the required `DeviceRegistrationContextExtractor<C>` of
`kSecureMessageRoutes(server, registrationContext)`. The authorizer then
answers "may *this principal* add *this device* to *this user*?", typically
`request.address.userId == principal.userId` plus the host's own device
policy.

- No context (the extractor returns `null`) or `Denied` answers `403
  registration_not_authorized`; the reason is not sent. An exception in the
  extractor or authorizer answers `500 internal_error` and is logged by
  exception class only, never its message or the context.
- The authorizer gets no view of KSecureMessage's registrations (S1.1,
  finding N2): being the first device of a user is not an authority, and a
  count read outside the registration's write would be stale.
- A retry with the already registered key never asks the authorizer and
  needs no context; a different key for a registered address is a conflict
  and never asks it.
- Everything that treats "a registered device of the same user" as an
  authority (device recovery, the offline recovery key, its rotation,
  revocation and reset) trusts exactly the membership the authorizer
  approved. An authorizer that says yes to everyone, or an extractor that
  returns one shared principal for unauthenticated calls, brings back
  findings F1/F2.
- The sample's bearer-token table is DEMO ONLY: it stands in for the
  application's login and is not secure authentication.
- There is no allow-all default; tests pass an explicit test authorizer.

### Registrations from before S1

Registrations stored by a server older than S1 were **never host-authorized**:
before S1 whoever registered a free address first owned it (findings F1/F2).
An upgraded server keeps them as trusted historical state; they are not
re-verified. A device an attacker registered before the upgrade therefore
still can, until it is removed:

- authenticate as its registered address (signed prekey publication,
  mailbox drain, registration status);
- submit signed envelopes as that address;
- act as a "registered device of the same user": authorize a device
  recovery (M14) of the user's other devices, register, rotate or revoke
  the user's offline recovery key (M18/M19) and request, read, complete or
  cancel its reset (M23).

KSecureMessage cannot tell a legitimate pre-S1 registration from a
malicious one, so it never deletes or blesses them automatically. Before
exposing an upgraded server, audit them against the application's own
account and device records (read-only, on the server database):

```sql
SELECT user_id, device_id, auth_epoch, auth_key_installed_at FROM device_registration ORDER BY user_id, device_id;
-- Recovery key state per user and who requested a pending reset:
SELECT user_id, state, epoch, installed_at FROM last_device_recovery_key_state;
SELECT user_id, requested_by_device, requested_at, eligible_at FROM last_device_recovery_key_reset;
```

For a registration the application does not recognize: stop the server,
back up the database, and delete that device's rows in one transaction
(`device_registration`, `authentication_nonce`,
`last_device_recovery_challenge`, `device_prekey_state`,
`available_one_time_prekey`, `consumed_one_time_prekey`, and the
`mailbox_message` rows it sent or would receive). Then review the affected
user's recovery key state: a recovery key that device registered, rotated
or revoked, or a reset it requested, may be the attacker's; cancel the
reset and have the user rotate or re-register the recovery key from a
legitimate device. There is no remote admin API for this by design.

### Upgrade checklist (S1 / S1.1)

1. Upgrade servers and clients together: new sessions need session
   initiation v2 (wire type `0x03`), which pre-S1 peers cannot read.
2. Migrate the server database to schema 8 before `open`.
3. Audit registrations created before S1 (above).
4. Remove or revoke registrations the application's account and device
   system does not recognize, and review the affected users' recovery keys.
5. Wire `DeviceRegistrationAuthorizer<C>` to the application's
   authenticated principal and pass a `DeviceRegistrationContextExtractor`
   that returns `null` for unauthenticated calls.
6. Confirm the registration route cannot run without principal extraction:
   an unauthenticated `PUT …/registration` for a new address must answer
   `403 registration_not_authorized`.
7. On Android, review the storage key provider limitation of
   [storage-key-providers.md](storage-key-providers.md#haskeys-s1) (F7).

## RecoveryKeyResetPolicy

`SecureMessageServer(storage, clock, deviceRegistrationAuthorizer, recoveryKeyResetPolicy)` controls the
delayed reset of a **lost** offline recovery key
([recovery-key-reset.md](recovery-key-reset.md)):

- `null` (the default): new reset requests are refused
  (`recovery_key_reset_not_available`). A reset that is already pending stays
  readable, cancellable and completable.
- `RecoveryKeyResetPolicy(delay)`: a positive, finite delay chosen by the
  host. There is **no library default**, and no delay is "cryptographically
  correct": the delay is the time the legitimate user has to notice and
  cancel a reset started by a compromised device. It is a product and threat
  model decision (how often users check, how they are notified).
- Changing the policy never shortens or restarts a pending reset: its
  `eligibleAt` was fixed when it was requested.

## Backups of the server database

The database holds registrations (device authentication public keys,
epochs, installation times), recovery key states, pending resets and
challenges, published prekeys and one-time prekey tombstones, the mailbox
(opaque envelopes with routing metadata) and claimed request nonces. It holds
no private keys and no plaintext, but it is not encrypted and reveals who
talks to whom.

Back up the whole SQLite file consistently (SQLite online backup, or a copy
while the server is stopped). **Restoring an older backup restores older
server-side security state**, and nothing in the library detects it:

- a device authentication key that was rotated or recovered since becomes
  valid again, and the newer one is rejected;
- a revoked or rotated offline recovery key becomes active again, and a
  cancelled or completed reset can reappear;
- one-time prekeys handed out since the backup can be handed out again;
- claimed nonces newer than the backup are forgotten, so requests signed in
  the last few minutes before the restore could be replayed;
- envelopes delivered since the backup are delivered again (clients
  deduplicate by logical message ID while they keep processed IDs), and
  envelopes received since are lost.

Treat a restore as a security event: prefer restoring only after data loss,
inform users, and have affected users rotate device authentication and
offline recovery keys afterwards. Rollback-safe restore is not implemented.

## Client storage

Production clients use `SqlDelightClientStorage.open(driver, keyProvider)`
([storage-encryption.md](storage-encryption.md)):

- **Record-level encryption**: private keys, ratchet state, pending message
  frames and processed digests are sealed with AES-256-GCM under a 32-byte
  storage key. Metadata (addresses, IDs, sequences, timestamps) stays
  plaintext. It protects a copied database file without the storage key; it
  does not protect against an attacker who has the database **and** the key,
  or who controls the running process.
- **Storage key providers** ([storage-key-providers.md](storage-key-providers.md)):
  `AndroidStorageKeyProvider` (key wrapped by an Android Keystore key, file in
  `noBackupFilesDir`) and `AppleStorageKeyProvider` (Keychain item,
  `AfterFirstUnlockThisDeviceOnly`, not synchronizable, data protection
  keychain). There is no JVM, desktop, JS or Wasm provider in this release;
  implement `StorageKeyProvider` with the platform's secret store if needed.
- **Backups**: keep the database and the key on the same device. Neither the
  Keystore key nor a `ThisDeviceOnly` Keychain item is backed up, so exclude
  the database from backup and device transfer too
  (`android:dataExtractionRules`, iOS backup exclusion).
- **Losing the storage key** makes the encrypted client state permanently
  unreadable: `open` fails with `KeyUnavailable`. It never creates a new key
  for an existing database. Recovering means a new installation with a new
  messaging identity (peers see an identity change).
- **Storage key rotation** is explicit: `rotateStorageKey()`,
  `resumeStorageKeyRotation(maxRecords)`, `storageKeyRotationStatus()`
  ([storage-key-rotation.md](storage-key-rotation.md)). Nothing rotates
  automatically.
- **Migrations**: client schema changes (currently version 15) are numbered,
  one-way SQLDelight migrations tested against frozen schema fixtures. The
  driver the application creates with `SqlDelightClientStorage.Schema` runs
  them; `open` then finishes data migrations that SQL cannot do (for example
  encrypting pre-M9 plaintext records). There is no downgrade.
- `InMemoryClientStorage` is for tests and examples: nothing is persisted or
  encrypted.
