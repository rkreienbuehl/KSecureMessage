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
  registration_not_authorized`; the reason is not sent. Anything the
  extractor or authorizer throws (exceptions and errors such as
  `AssertionError` or `NotImplementedError` alike; S1.2, finding N4) answers
  `500 internal_error`, also in Ktor's development mode, and is logged by
  class name only, never its message, stack, cause or the context.
  <!-- ksm-security-claim:host-boundary-throwables -->
  The throwable's class alone is never trusted (S1.3, finding N7): genuine
  coroutine cancellation (the request's coroutine is no longer active)
  propagates unchanged; a `CancellationException` thrown by host code while
  the coroutine is still active is sanitized like any other failure, and so
  are `InternalError`, `UnknownError` and other errors host code can throw
  with its own message. Only the process-health failures `OutOfMemoryError`
  and `StackOverflowError` propagate unchanged: KSecureMessage does not
  turn them into an ordinary HTTP answer, and what happens to them after
  they leave its boundary (engine, logging) is outside its control.
  Consequences for host code (S1.3 final re-review, informational):
  KSecureMessage does not sanitize what it deliberately propagates. Once a
  request is genuinely cancelled, a message or cause that host code attached
  to the cancellation can reach the runtime's or server's own logging, so
  host code must not place secrets in cancellation exception messages or
  causes. Likewise, host code must not use `OutOfMemoryError` or
  `StackOverflowError` as control flow or attach secrets to their messages:
  such an error constructed by host code can reach the engine's HTTP and log
  handling unchanged.
  <!-- /ksm-security-claim:host-boundary-throwables -->
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

<!-- ksm-security-claim:pre-s1-audit -->
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

Such a device may also have **left authority behind** that outlives its
registration: an offline recovery key it registered, rotated in or
installed by a completed reset is held by the attacker, and before S1 a
device recovery could replace the key of a legitimate address with an
attacker's key. KSecureMessage cannot tell a legitimate pre-S1 registration
from a malicious one, so it never deletes or blesses them automatically.

**Addresses alone are not enough.** A known, legitimate address may carry an
attacker's device authentication key (installed by a pre-S1 recovery or
last-device recovery). Before exposing an upgraded server, audit every
registration and every user's recovery key state against the application's
own account and device records: compare the address **and** the current
device authentication public key **and** the transition that installed it
(`recovery_id`, `rotation_id`, `last_device_recovery_id`, epoch,
installation time) wherever the application has records of them. These
queries are read-only; the server database holds public keys only, never
private key material:

<!-- ksm-sql:pre-s1-audit:begin -->
```sql
-- Every registration: address, current device authentication public key, epoch
-- and the transition that installed it (all NULL = first registration).
SELECT user_id, device_id, hex(auth_public_key) AS auth_public_key, auth_epoch,
       auth_key_installed_at, hex(recovery_id) AS recovery_id, hex(rotation_id) AS rotation_id,
       hex(last_device_recovery_id) AS last_device_recovery_id
FROM device_registration ORDER BY user_id, device_id;
-- Offline recovery key state per user: 1 = ACTIVE (public_key set), 2 = REVOKED.
SELECT user_id, state, epoch, hex(public_key) AS public_key, installed_at, transitioned_at,
       hex(rotation_id) AS rotation_id, hex(revocation_id) AS revocation_id,
       hex(reset_completion_id) AS reset_completion_id
FROM last_device_recovery_key_state ORDER BY user_id;
-- Pending recovery key resets: who requested them and the key and epoch they replace.
SELECT user_id, hex(reset_id) AS reset_id, requested_by_device, expected_epoch,
       hex(expected_public_key) AS expected_public_key, requested_at, eligible_at
FROM last_device_recovery_key_reset ORDER BY user_id;
-- Outstanding last-device recovery challenges.
SELECT user_id, device_id, hex(auth_public_key) AS auth_public_key, auth_epoch, recovery_key_epoch,
       issued_at, expires_at
FROM last_device_recovery_challenge ORDER BY user_id, device_id;
```
<!-- ksm-sql:pre-s1-audit:end -->

A registration is **suspicious** if the application does not recognize its
address, or recognizes the address but not its key or the transition that
installed it. A matching address is never enough on its own: if an operator
cannot establish that a pre-S1 registration's current authentication key is
legitimate (for example because the application kept no record of device
keys), treat that registration/user as suspect.
<!-- /ksm-security-claim:pre-s1-audit -->

### Pre-S1 cleanup

<!-- ksm-security-claim:pre-s1-recovery-key-cleanup -->
**If you discover any unrecognized device that existed before S1, assume
that user's recovery-key authority may also have been compromised. Removing
only the device registration is insufficient**: the attacker may still hold
the user's current offline recovery key and use it alone to cancel a reset,
to take over any of the user's devices through last-device recovery, and so
to regain same-user authority.

Treat that user's current offline recovery key as compromised. Never rotate
it and never rely on it: a rotation needs the suspect key's own signature,
and the attacker can rotate first. Instead the cleanup forces the user's
recovery key state to REVOKED (`state = 2`), deletes the user's pending
recovery key reset and outstanding last-device recovery challenges, and a
legitimate device then provisions a fresh recovery key. Skipping the
revocation for a user requires independent evidence (for example the
application's own records) that the user's current recovery key was
provisioned after S1 by a legitimate device; the procedure has no switch
for this and nothing is assumed implicitly.

Perform the cleanup with the **server stopped**, after a backup, as **one
database transaction** run by the cleanup script, then have a legitimate
device provision a fresh recovery key. There is no remote admin API for this
by design.

The script is the file
[`operator/ksecuremessage-pre-s1-cleanup.sql`](operator/ksecuremessage-pre-s1-cleanup.sql)
([on GitHub](https://github.com/rkreienbuehl/KSecureMessage/blob/main/docs/operator/ksecuremessage-pre-s1-cleanup.sql)),
shown in full below. It is the only copy: the test suite runs exactly this
file with the `sqlite3` shell against server schema 8.

**Preconditions**, all required:

- the server is stopped (no request in flight) and the database file is
  backed up;
- the database is at server schema version 8 (the script checks
  `server_storage.format` and refuses anything else);
- the audit queries above were run and every suspicious
  `(user_id, device_id)` tuple was checked against their output.

**Run it as a script, exactly like this** (on an edited copy of the file):

```sh
sqlite3 -bail /path/to/server.db < ksecuremessage-pre-s1-cleanup.sql
```

**Do not paste the cleanup statements interactively into the sqlite3
prompt**, and do not run them with another tool statement by statement.
Interactively, the shell continues after a failed statement (`.bail on`
has no effect there), so a guard or constraint failure is followed by the
remaining `DELETE`s, the `UPDATE` and `COMMIT`: a partial cleanup is
committed. Run as a script, the first error stops the shell with a non-zero
exit status and SQLite rolls the open transaction back: nothing changes.
This fail-closed behavior is tested for this documented, non-interactive
invocation and the SQL errors the test suite provokes; it is not a claim
about every other way of feeding the file to `sqlite3` or another tool.

Steps:

1. Stop the server and back up the database file.
2. Run the audit queries above and list the suspicious registrations.
3. Copy the script and edit **only** the section between
   `-- ksm-cleanup-input:begin` and `-- ksm-cleanup-input:end`: one
   `INSERT INTO ksm_cleanup_device (user_id, device_id) VALUES (…);` row per
   suspicious registration, and `ksm_exhausted_user` only as described under
   "Exhausted recovery key epoch" below.
4. Run it with the command above. It needs SQLite 3.15 or newer (row-value
   `IN`).
5. **Post-cleanup verification** (mandatory, never rely on the exit status
   alone). The run is successful only if all of these hold:
    - the exit status is 0;
    - the script printed one `name|violations` line per check, each with
      violation count `0`, and its last line is
      `ksm-pre-s1-cleanup: verification passed`;
    - the audit queries, run again in a fresh `sqlite3` session, no longer
      show any listed registration, show every affected user's recovery key
      state as `2` (REVOKED) or absent, and show no reset and no challenge
      for an affected user.

    If any check fails, do not start the server; restore the backup and
    investigate. A non-zero exit status with an error that names
    `post_cleanup_verification_found_no_violations` means the transaction
    was committed but its result is wrong. The post-cleanup verification
    runs after `COMMIT`: a failed verification reports the problem, but it
    does not undo the committed cleanup. Recovering from it means restoring
    the backup taken in step 1.
6. Only then restart the server.
7. On a legitimate device of each affected user:
   `val r2 = client.createLastDeviceRecoveryKey()`, back `r2` up offline,
   `client.registerLastDeviceRecoveryKey(r2)`, and check that
   `client.lastDeviceRecoveryKeyStatus()` is `Active` with `r2`'s public key.
   Registration after a revocation is the normal M18/M19 path; it needs
   ServerAuth by a registered device of the user and `r2`'s proof of
   possession, never the old key.

**Guards.** The script checks everything before its first change, inside
the transaction, after the input is listed, and aborts (non-zero exit,
nothing changed) with the name of the failed guard:

- `server_schema_is_version_8`: the database is at server schema 8;
- `at_least_one_device_listed`: an empty list is refused, so running the
  unedited file never looks successful;
- `every_listed_device_is_registered`: every listed tuple is a current
  registration; a typo such as `alice/evl` for `alice/evil` aborts instead
  of revoking the recovery key while the attacker's device stays registered;
- a duplicate row fails on `ksm_cleanup_device`'s primary key
  (`UNIQUE constraint failed`);
- `no_unlisted_exhausted_epoch` and
  `every_exhausted_user_is_listed_active_and_exhausted`: see below.

<!-- ksm-sql:pre-s1-cleanup-script:begin -->
```sql
--8<-- "docs/operator/ksecuremessage-pre-s1-cleanup.sql"
```
<!-- ksm-sql:pre-s1-cleanup-script:end -->

What it changes and why. The cleanup removes **authority and
reachability**, not history:

| Table | Rows of the listed registrations / affected users |
|---|---|
| `device_registration` | deleted: the key can no longer sign anything |
| `authentication_nonce` | deleted (the device's claimed nonces); the prune watermark is kept |
| `device_prekey_state`, `available_one_time_prekey` | deleted: the bundle fetch is public, a remaining bundle would still start sessions with the suspect key holder |
| `consumed_one_time_prekey` | **kept**: a consumed one-time prekey ID is never handed out again, also after a legitimate device returns to the address and publishes its prekeys again (publication skips consumed IDs) |
| `mailbox_message` | deleted if **addressed to** a listed registration (the invalidated device instance); **kept** if sent as it (see below) |
| `last_device_recovery_key_state` | an ACTIVE key is forced to REVOKED (`state = 2`, no public key, no installation time, no transition IDs) at epoch + 1; an already REVOKED user is left unchanged; a user without a row stays unconfigured |
| `last_device_recovery_key_reset`, `last_device_recovery_challenge` | deleted for every affected user: issued under suspect authority |

The epoch step keeps the recovery key epoch monotonic, so every statement,
challenge and reset bound to the old epoch is dead. Several listed devices
of one user cause a single transition. `transitioned_at` is the wall-clock
time of the cleanup. Afterwards the old recovery key can no longer cancel
or read a reset, obtain a challenge, recover a device, rotate or revoke:
every one of those needs an ACTIVE key. Unchanged: other devices of the
user (registrations, keys, epochs, prekeys, nonces, their mailboxes), other
users and the nonce prune watermark.

**Envelopes sent as a listed address are kept**, for a wholly malicious
address as for a known one. They are opaque ciphertext and confer no
authority: whether a message is authentic is decided end to end by the
recipient's session and identity trust, never by the relay's sender field,
and deleting them cannot undo what the suspect key holder already
delivered. A known address may also have legitimate envelopes in flight
from its legitimate device, which the relay cannot tell apart.
The consequence (finding N8, accepted LOW residual): an envelope a suspect
device submitted **before** the cleanup and that is still queued may be
delivered **after** it. The cleanup does not recall queued messages; it
stops the removed key from submitting new ones. Recipients still validate
such an envelope cryptographically (session, identity pin, v2 transcript);
for an address they never talked to, it can create a new `UNVERIFIED`
identity pin. Tell users that an unexpected first contact from a cleaned
address after the remediation is unverified and suspicious until they
compare safety numbers
([security-review-remediation.md](security-review-remediation.md#n8-queued-envelopes-from-cleaned-sender-addresses)).

**A known address with an attacker's key** (a legitimate device whose key a
pre-S1 recovery or last-device recovery replaced) is cleaned up the same
way, with its address in the list. The legitimate device then calls
`registerDevice()` again (a first registration of its own key, authorized
by the host) and `publishPreKeys()`; its already consumed one-time prekey
IDs stay tombstoned. Envelopes that were addressed to it are gone; their
senders still hold them as pending and resend them with
`retryPendingMessages()` until acknowledged.

**Tombstoned one-time prekey IDs of a returning device** (finding N9,
accepted LOW residual): if an attacker published one-time prekeys under
the address before S1 and had them handed out, their IDs stay tombstoned.
When the legitimate device publishes one-time prekeys with the same IDs,
the server skips them silently, so the device may believe its one-time
prekeys are available while the server holds none. New sessions with it
are then set up without a one-time prekey. See
[security-review-remediation.md](security-review-remediation.md#n9-consumed-one-time-prekey-tombstone-poisoning);
v0.1.0 has no automatic replenishment with fresh IDs.

**Exhausted recovery key epoch.** If an affected user's ACTIVE recovery key
epoch is already `9223372036854775807`, the epoch cannot grow and never
wraps, so the script aborts (`no_unlisted_exhausted_epoch`) and changes
nothing. Decide manually. Revoking without an epoch change is fail-closed:
add that user, and only that user, to the input section with
`INSERT INTO ksm_exhausted_user (user_id) VALUES (…);` and run the script
again. For that user the old key is then as dead as above (REVOKED, every
use needs an ACTIVE key, challenges and the reset are deleted) and the
epoch stays `9223372036854775807`, so that user can **never** register a
recovery key again on this database (`EPOCH_EXHAUSTED`). Every other
affected user gets the normal revocation at epoch + 1. Listing a user
whose epoch is not exhausted, who is not ACTIVE, or who has no listed
device aborts (`every_exhausted_user_is_listed_active_and_exhausted`).

The script runs against server schema version 8 in the test suite
(`PreS1CleanupTest` in `server:ktor`: the real `sqlite3` shell with the
command above, on a file-backed database with the real constraints; the
audit queries run verbatim from this page).
<!-- /ksm-security-claim:pre-s1-recovery-key-cleanup -->

### Upgrade checklist (S1 / S1.1)

1. Upgrade servers and clients together: new sessions need session
   initiation v2 (wire type `0x03`), which pre-S1 peers cannot read.
2. Migrate the server database to schema 8 before `open`.
3. Audit registrations created before S1, with their keys and transition
   metadata, not only their addresses (above).
4. For every suspicious registration run the offline [pre-S1
   cleanup](#pre-s1-cleanup) script, as a script (never pasted), and pass
   its post-cleanup verification: it also revokes the affected users'
   recovery keys and deletes their pending resets and challenges; then
   provision a fresh recovery key from a legitimate device.
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
- **Migrations**: client schema changes (currently version 16) are numbered,
  one-way SQLDelight migrations tested against frozen schema fixtures. The
  driver the application creates with `SqlDelightClientStorage.Schema` runs
  them; `open` then finishes data migrations that SQL cannot do (for example
  encrypting pre-M9 plaintext records). There is no downgrade.
- `InMemoryClientStorage` is for tests and examples: nothing is persisted or
  encrypted.
