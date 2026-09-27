# KSecureMessage

KSecureMessage is a Kotlin Multiplatform scaffold for a Signal-style secure messaging library built on top of [Kodium](https://github.com/LivotovLabs/kodium).

The project intentionally separates:

- shared protocol/domain models
- Kodium-backed protocol orchestration
- client-side messaging behavior
- server-side prekey/message relay behavior
- transport adapters such as Ktor
- storage contracts and implementations

> This project does not claim wire-level compatibility with Signal/libsignal. Kodium provides X3DH and Double Ratchet primitives; KSecureMessage is intended to add the surrounding messaging lifecycle and infrastructure.

## Modules

```text
KSecureMessage/
├── core/
│   ├── model/
│   └── protocol/
├── client/
│   ├── core/
│   └── ktor/
├── server/
│   ├── core/
│   └── ktor/
└── storage/
    ├── core/
    ├── encryption/
    ├── testing/
    ├── client/
    │   ├── inmemory/
    │   └── sqldelight/
    ├── server/
    │   ├── inmemory/
    │   └── sqldelight/
    ├── keyprovider/
    │   ├── android/
    │   └── apple/
    └── rotation/
        └── core/
```

Storage modules are split by side: `storage:client:*` holds local client persistence (`ClientStorage` adapters), `storage:server:*` server repository persistence (`ServerStorage` adapters), and `storage:core` the shared contracts both implement. `storage:encryption`, `storage:keyprovider:*` and `storage:rotation:core` are storage security infrastructure; today they serve only the persistent client storage (`storage:client:sqldelight`).

### `core:model`
Shared serializable value types such as user/device addresses, prekey metadata, and encrypted envelopes.

### `core:protocol`
Protocol-facing orchestration and Kodium dependency. Keep Kodium-specific types internal where possible so the public API remains stable.

### `client:core`
Client lifecycle contracts such as transport, session access, sending, receiving, the application commit of received messages, acknowledgements and resend.

### `client:ktor`
Kotlin Multiplatform Ktor client transport adapter.

### `server:core`
Server-side repositories/services for public device information, prekey bundles, and encrypted envelopes. It should not decrypt client messages or own client session secrets. `PreKeyService` validates publications and hands out each one-time prekey at most once. `DeviceAuthenticator` verifies device-signed requests against registered device authentication keys, with a time window and single-use nonces (see [docs/server-authentication.md](docs/server-authentication.md)) `DeviceRecoveryService` replaces a lost device's key when another registered device of the same user authorizes it (see [docs/device-recovery.md](docs/device-recovery.md)).

### `server:ktor`
JVM Ktor server routes/adapters for HTTP API v1, see [docs/prekey-publication.md](docs/prekey-publication.md) and [docs/server-authentication.md](docs/server-authentication.md).

### `storage:core`
Shared storage contracts.

### `storage:client:inmemory`
Non-persistent `InMemoryClientStorage` for tests and examples. Transactions are atomic.

### `storage:server:inmemory`
Non-persistent `InMemoryServerStorage` (prekey, mailbox, device registration and authentication nonce repositories) for tests and examples. Each repository operation is atomic.

### `storage:server:sqldelight`
Persistent `SqlDelightServerStorage` on SQLite via SQLDelight, JVM only. The host application creates, configures and closes the `SqlDriver`; the adapter only runs the repository logic, each operation in one SQLite transaction. SQLite dialect only: a configurable driver does not mean support for arbitrary SQL databases. See [docs/server-storage.md](docs/server-storage.md).

### `storage:client:sqldelight`
Persistent `ClientStorage` on SQLite via SQLDelight, for all client targets. The application supplies the platform driver and a `StorageKeyProvider`; key pairs, session state, pending message plaintext (sent and received) and committed message digests are stored as encrypted records, see [docs/storage.md](docs/storage.md) and [docs/storage-encryption.md](docs/storage-encryption.md). The storage key can be rotated explicitly, see [docs/storage-key-rotation.md](docs/storage-key-rotation.md).

### `storage:encryption`
Record-level encryption of sensitive client storage records: AES-256-GCM (cryptography-kotlin) with associated data bound to record type and row key, the versioned record format, `StorageKeyProvider` and `StorageEncryptionKey`. Used by `storage:client:sqldelight`.

### `storage:rotation:core`
The storage key rotation state machine (`StorageKeyRotationManager`), its validated state, status and the `StorageKeyRotationBackend` contract a persistent storage adapter implements. No SQL or platform code; `storage:client:sqldelight` provides the SQLite backend. See [docs/storage-key-rotation.md](docs/storage-key-rotation.md#architecture).

### `storage:keyprovider:android`, `storage:keyprovider:apple`
Platform `StorageKeyProvider`s: the storage key wrapped by an Android Keystore key, or stored in the Apple Keychain. See [docs/storage-key-providers.md](docs/storage-key-providers.md).

### `storage:testing`
Shared `ClientStorage`, server `PreKeyRepository`, `MailboxRepository`, `DeviceRegistrationRepository`, `AuthenticationNonceRepository` and `StorageKeyProvider` contract tests that every adapter runs. Not published.

## Coordinates

Base package:

```text
dev.kreienbuehl.ksecuremessage
```

Current dependency baseline:

- Kotlin 2.4.20
- Kodium 1.0.0
- cryptography-kotlin 0.6.0 (storage encryption)
- Ktor 3.6.0
- SQLDelight 2.4.0

## Status

Milestone 1 done: `KodiumProtocolEngine` creates identities and prekeys, sets up sessions with Kodium X3DH (the signed prekey signature is verified), and encrypts and decrypts with the Kodium Double Ratchet. Sessions persist as opaque `SecureSession.state` bytes. The initiator sends `PreKeyMessage`s until it has decrypted the first reply. After that it sends `RatchetMessage`s. See `core/protocol/src/commonTest`.

Milestone 2 done: `CiphertextMessageCodec` encodes `RatchetMessage` and `PreKeyMessage` into a versioned binary wire format for `EncryptedEnvelope.payload` (see [docs/wire-format.md](docs/wire-format.md)). `SecureMessageClient` encrypts and sends through it and decrypts incoming envelopes, accepting a first-contact `PreKeyMessage` without an existing session. Local prekeys come from `ClientStorage.preKeys`; a consumed one-time prekey is removed in the same transaction that stores the new session.

Milestone 3 done: the client owns its local protocol state. `initialize()` creates the identity, a current signed prekey and missing one-time prekeys in storage, and keeps whatever already exists. `currentPreKeyBundle()` and `publicOneTimePreKeys()` expose the public material for publication. `ClientStorage.transaction` is atomic in both adapters, and `storage:client:sqldelight` adds persistent storage. See [docs/storage.md](docs/storage.md).

```kotlin
val client = SecureMessageClient(
    localAddress = address,
    storage = SqlDelightClientStorage(driver),
    protocol = KodiumProtocolEngine(),
    transport = transport,
)
client.initialize()
client.publishPreKeys()
```

> Until milestone 9, storage adapters persisted private keys and session state unencrypted. See milestone 9 below.

Milestone 4 done: `client.publishPreKeys()` uploads the identity key, the current signed prekey and the public one-time prekeys. The server's `PreKeyRepository` applies a publication atomically, treats retries as no-ops and rejects identity and prekey ID conflicts. Each bundle fetch atomically hands out and consumes at most one one-time prekey (lowest ID first); a bundle without one is served when none are left. `server:ktor` and `client:ktor` implement the HTTP API v1. See [docs/prekey-publication.md](docs/prekey-publication.md).

Milestone 5 done: remote identity trust on first use. The first identity key that sets up a session with a remote device, as initiator or responder, is pinned per `DeviceAddress` in the same transaction that stores the session; a failed first contact pins nothing. A different key for a pinned device fails with `SecureMessageClientException.IdentityChanged` and changes nothing. `ClientStorage.remoteIdentities` stores the pins; `storage:client:sqldelight` migrates its schema from version 1 to 2. TOFU detects identity changes after first contact but does not authenticate the remote party on first contact; safety numbers are not implemented. See [docs/identity-trust.md](docs/identity-trust.md).

Milestone 6 done: session replacement and simultaneous initiation, on wire v1. Every session records the `SessionInitiationId` (SHA-256 over the authenticated X3DH inputs) that created it. A new initiation from the pinned identity atomically replaces the existing session. When both sides initiate at once, both keep the smaller ID, independent of arrival order and restarts. Replaced and losing initiations are retired persistently (`ClientStorage.sessionInitiations`, SQLDelight schema version 3) and rejected with `StaleSessionInitiation`, so a replayed old `PreKeyMessage` cannot roll a session back. A losing initiation's messages fail with `SessionCollision` and are not delivered. An initiation that never reached the device before cannot be recognized as old with wire v1. See [docs/session-lifecycle.md](docs/session-lifecycle.md).

Transport ordering (milestone 6 follow-up): sessions converge only if, per (sender, recipient) device pair, a `PreKeyMessage` is processed before every envelope the sender sent after it. `SecureMessageClient.send` hands envelopes to the transport in encryption order, `MailboxRepository` guarantees per (sender, recipient) FIFO (the in-memory mailbox is now synchronized, checked by `MailboxRepositoryContractTest`), and applications decrypt one sender's envelopes in delivery order. No wire or HTTP API change. See [docs/transport-ordering.md](docs/transport-ordering.md).

Milestone 7 done: signed prekey lifecycle. Each signed prekey stores `createdAt` and, once replaced, `replacedAt`. `initialize()` rotates the current key after `PreKeyConfiguration.signedPreKeyRotationAge` (default 7 days). A replaced key keeps accepting delayed first contacts for `signedPreKeyGracePeriod` (default 30 days). After that, new initiations naming it fail with `SecureMessageClientException.ExpiredSignedPreKey`, and `initialize()` deletes its private key. Established sessions keep working. Retired session initiations record the local signed prekey they need and are pruned once it is deleted. Time comes from an injectable `kotlin.time.Clock`. Publication after rotation stays explicit (`publishPreKeys()`). SQLDelight schema version 4 adds nullable lifecycle columns; keys from before the upgrade start a full grace period on the next `initialize()`. This bounds, but does not close, the window in which a withheld initiation is accepted: wire v1 has no authenticated freshness. See [docs/signed-prekey-lifecycle.md](docs/signed-prekey-lifecycle.md).

Milestone 8 done: logical message IDs, encrypted acknowledgements, duplicate suppression and resend. Every application message gets a random 128-bit `LogicalMessageId`, carried inside a versioned, encrypted reliability frame (`SecurePayloadCodec`; ciphertext wire v1 is unchanged). `send` returns `SentMessage` and keeps the message **with its plaintext** in `ClientStorage.pendingOutbound` until the recipient's encrypted acknowledgement arrives; an accepted HTTP request is not an acknowledgement. `decrypt` returns a `ReceiveResult` (`Message`, `Duplicate`, `Acknowledgement`): each (sender, logical ID) is delivered at most once, recorded in `ClientStorage.processedInbound`, and acknowledged automatically; acknowledgements are never acknowledged. `retryPendingMessages(remote)` encrypts pending messages again under the current session with the same logical ID, which recovers messages lost to a session collision, a lost envelope or a lost acknowledgement. SQLDelight schema version 5 adds the two tables. Breaking: `send`/`decrypt` changed, `encrypt` is no longer public, and both peers must run milestone 8 (raw plaintext from older peers is rejected). No exactly-once application side effects, no background retry, processed IDs are kept forever. See [docs/message-reliability.md](docs/message-reliability.md).

```kotlin
val sent = client.send(bob, "hello".encodeToByteArray())   // pending until acknowledged
for (envelope in client.receive()) {                        // transport.receive before milestone 12
    when (val result = client.decrypt(envelope)) {
        is ReceiveResult.Message -> show(result.plaintext)    // once per logical message
        is ReceiveResult.Duplicate, is ReceiveResult.Acknowledgement -> Unit
    }
}
client.retryPendingMessages(bob)                            // e.g. after a SessionCollision
```

> Client storage now also holds the plaintext of sent messages until they are acknowledged. Milestone 9 encrypts it at rest in `SqlDelightClientStorage`.

Milestone 9 done: record-level client storage encryption. `SqlDelightClientStorage.open(driver, keyProvider)` stores the identity and prekey key pairs, session state and pending message frames as AES-256-GCM records (cryptography-kotlin, random 96-bit nonces, 128-bit tags) in a versioned local format that names the storage key ID. The associated data binds each record to its record type and row key (prekey ID, remote address, recipient and logical message ID), so modified, swapped or cross-type records fail with `StorageEncryptionException` instead of reading as absent. The storage key is a dedicated 256-bit key from an application-supplied `StorageKeyProvider`, never stored in the database; there is no plaintext mode. A wrong key fails at open (key check record); a missing key fails with `KeyUnavailable`; no state is ever regenerated. SQLDelight schema version 6 adds a `storage_encryption` marker; the next `open` encrypts a milestone 8 database in one transaction, all or nothing. IDs, addresses, timestamps, pins, retired initiations and processed IDs remain plaintext metadata; row deletion, whole-database rollback and pre-upgrade plaintext left in SQLite pages or backups are not addressed. Platform key providers (Android Keystore, Apple Keychain) are not included. No wire, protocol or messaging API change. See [docs/storage-encryption.md](docs/storage-encryption.md).

```kotlin
val storage = SqlDelightClientStorage.open(driver, keyProvider) // keyProvider: platform key storage
val client = SecureMessageClient(address, storage, KodiumProtocolEngine(), transport)
```

Milestone 10 done: platform storage key providers. `AndroidStorageKeyProvider(context, namespace)` wraps the 32-byte storage key with AES-GCM under a non-exportable Android Keystore key and keeps only the wrapped form in a versioned file in `noBackupFilesDir`. `AppleStorageKeyProvider(namespace)` stores the key as a Keychain generic password item (data protection keychain, after first unlock, this device only, not synchronized); macOS applications without keychain entitlements can choose `AppleStorageKeyProvider.legacyFileKeychain(namespace)` explicitly. A key is created only when the provider has no state; a missing Keystore key, a damaged file or item, or any platform error fails with `KeyUnavailable` and nothing is regenerated. Creation is durable before it returns and concurrent first calls get one key. Namespaces separate databases. No storage format, wire, protocol or messaging API change. See [docs/storage-key-providers.md](docs/storage-key-providers.md).

```kotlin
val storage = SqlDelightClientStorage.open(driver, AndroidStorageKeyProvider(context, namespace = "account-42"))
val storage = SqlDelightClientStorage.open(driver, AppleStorageKeyProvider(namespace = "account-42"))
```

Milestone 10.1 done: the Apple data protection keychain path is tested in a real entitled process. `apple-keychain-host/` wraps the Kotlin/Native test executables in a signed `.app` (ad-hoc with simulated entitlements in the iOS simulator; Apple Development signature and provisioning profile on macOS, configured locally, never in the repository) and runs the provider contract, the SQLDelight integration and a three-process relaunch test against the default `AppleStorageKeyProvider` (`./gradlew appleKeychainHostTest`). Results are PASSED, FAILED or NOT EXECUTED; tests no longer print `SKIPPED` and pass. No provider, storage format, wire, protocol or messaging API change. See [docs/storage-key-providers.md](docs/storage-key-providers.md#signed-keychain-host-apple-data-protection-keychain-tests).

Milestone 11 done: storage key rotation and safe retirement. `SqlDelightClientStorage.rotateStorageKey()` allocates the next key ID from a persisted high-water mark (never reused, no wraparound), has the provider create and persist that key, and only then makes it current: from that commit on every new record is sealed with it, while records of the previous key stay readable by the key ID in their header. `resumeStorageKeyRotation(maxRecords)` re-encrypts old records in bounded, transactional, resumable batches (same associated data, fresh nonces, only the sealed column changes), then proves by scanning every sealed value that no record uses the old key, and only then removes it from the provider. The rotation state (STABLE, PREPARING, MIGRATING, RETIRING) lives in the database; every crash window between database and Keystore/Keychain is recoverable, a missing required key fails closed, and a record that does not open stops the rotation with the old key kept. `StorageKeyProvider` gained `createKey(id)` and `removeKey(id)`; the Android wrapped key file and Apple Keychain items hold one entry per key ID. SQLDelight schema version 7 adds the rotation columns; existing databases become STABLE on their key without re-encryption. Rotation is explicit: no scheduler. The record format, wire, protocol and messaging API are unchanged. See [docs/storage-key-rotation.md](docs/storage-key-rotation.md).

```kotlin
storage.rotateStorageKey()
while (storage.resumeStorageKeyRotation(maxRecords = 256).phase != StorageKeyRotationPhase.STABLE) Unit
```

The rotation state machine is now a separate module, `storage:rotation:core` (`StorageKeyRotationManager` over a `StorageKeyRotationBackend`); `SqlDelightClientStorage` implements the backend and keeps the same three functions. Phase, status and `StorageKeyRotationInProgressException` moved to the package `dev.kreienbuehl.ksecuremessage.storage.rotation`. No behavior, schema or format change.

Milestone 12 done: authenticated server API and device ownership. Every device has a dedicated Ed25519 device authentication key, separate from its messaging identity key: created by `initialize()` (still local only), sealed at rest as record type 7, re-encrypted by storage key rotation, and never recreated after a loss (a pre-M12 installation, marked by SQLDelight schema version 8's migration, gets its first key exactly once; a lost or damaged key fails closed). `registerDevice()` explicitly registers the public key with the server, in a request signed with that key; the server keeps the first key for an address, treats the same key again as success and rejects any other (`409`), with no reset. Prekey publication and mailbox drain now require a signature over an explicit binary request description (domain `KSecureMessage-ServerAuth-v1`, address, method, canonical path, SHA-256 of the exact body bytes, epoch-millisecond timestamp, 16-byte random nonce), verified with the registered key, accepted within ±5 minutes and once per nonce and device; the client signs automatically. Bundle fetch and message submission stay public. This is trust on first registration, not account authentication, and independent of TOFU between peers. Breaking HTTP API v1 behavior change (same paths); wire, protocol, storage formats and messaging semantics are unchanged. See [docs/server-authentication.md](docs/server-authentication.md).

```kotlin
client.initialize()      // local: identity, device authentication key, prekeys
client.registerDevice()  // once per device
client.publishPreKeys()  // signed
for (envelope in client.receive()) client.decrypt(envelope) // signed drain
```

Milestone 13 done: persistent server storage. `storage:server:sqldelight` implements the four server repositories on SQLite through a caller-supplied SQLDelight `SqlDriver` (server schema version 1, independent of the client schema). Registrations, claimed nonces, prekeys with consumed one-time prekey tombstones and queued envelopes survive a restart; every operation keeps the in-memory semantics and is one SQLite transaction (the nonce claim stays separate from the protected operation). Both server adapters run the same contract tests. The HTTP routes now answer unexpected server or storage failures with a generic `500` `internal_error`, never the exception text. Wire, protocol, authentication and client storage are unchanged. SQLite, single node, unencrypted. See [docs/server-storage.md](docs/server-storage.md).

Milestone 14 done: device authentication recovery. A device that lost its device authentication key can have a replacement registered, authorized by another registered device of the same user: the lost device keeps a pending replacement key (sealed at rest as record type 8, kept across restarts and storage key rotation) and signs a proof of possession; the other device signs an authorization with its registered key; the server verifies both over a frozen binary statement (domains `KSecureMessage-DeviceRecovery-v1` and `KSecureMessage-DeviceRecovery-PoP-v1`: target, authorizer, replacement key, timestamp, nonce), checks freshness (±5 minutes) and the nonce, and replaces the key by compare-and-set on key and a new authentication epoch, in one transaction. The old key stops working at once; a retry of an applied recovery is recognized (`DeviceRecoveryId`), and a client whose response was lost confirms its pending key with an ordinary registration request. Cross-user and self authorization, unregistered targets and stale or replayed recoveries are rejected. Only server authentication changes: messaging identity, TOFU pins, sessions, prekeys and mailbox stay. A user with a single device cannot recover it. Server schema version 2 (`1.sqm`), client schema version 9 (`8.sqm`). See [docs/device-recovery.md](docs/device-recovery.md).

```kotlin
val request = lostDevice.prepareDeviceAuthenticationRecovery(authorizer = otherDeviceAddress)
val authorization = otherDevice.authorizeDeviceRecovery(request) // transferred by the application
lostDevice.completeDeviceAuthenticationRecovery(authorization)
```

Milestone 15 done: safety numbers, manual verification and explicit identity-change acceptance. Two devices derive the same safety number from both device addresses and messaging identity keys (SHA-256, domain `KSecureMessage-SafetyNumber-v1`, canonical order by address encoding), shown as 60 digits in 12 groups or as a versioned binary payload for a QR code; vectors are frozen. Each pin has a local verification state (`UNVERIFIED` on first use, `VERIFIED` only after the user confirmed the safety number of exactly that key). Changed identities still fail with `IdentityChanged`, which now names the pinned and the presented key; only `acceptRemoteIdentityChange` replaces a pin, by compare-and-set on the old key, installing exactly the confirmed key as unverified and removing and retiring the old session in one transaction. Pending messages survive and are retried on the new session. Client-local only: no server or wire change. Client schema version 10 (`9.sqm`). See [docs/identity-verification.md](docs/identity-verification.md).

```kotlin
val number = client.safetyNumber(bob)           // number.displayString / number.encode() for a QR code
client.compareSafetyNumber(bob, scannedPayload) // MATCH, MISMATCH or DIFFERENT_DEVICES; changes nothing
client.markRemoteIdentityVerified(number)       // only after the user confirmed

try { client.decrypt(envelope) } catch (e: SecureMessageClientException.IdentityChanged) {
    // show client.safetyNumber(e.change) to the user; only if they approve:
    client.acceptRemoteIdentityChange(e.change)
}
```

Milestone 16 done: routine device authentication key rotation. A device that still holds its registered key K1 replaces it with K2 without another device: `prepareDeviceAuthenticationRotation()` creates K2 once and keeps it as pending rotation key (sealed at rest as record type 9, kept across restarts and storage key rotation, never pending together with a recovery key); `completeDeviceAuthenticationRotation()` reads the current authentication epoch (`GET …/registration`, signed by K1) and sends a frozen binary statement (domains `KSecureMessage-DeviceAuthRotation-v1` / `-PoP-v1`: address, K1, K2, expected epoch, timestamp, nonce) signed by K1 and by K2 to `PUT …/registration/rotation`. The server checks freshness (±5 minutes), the registered key and epoch, both signatures and the nonce, and replaces the key by the same compare-and-set as recovery: `(K1, epoch N) → (K2, N+1)`; K1 stops working at once. An exact retry is recognized by its `DeviceAuthenticationRotationId`; a lost response or a crash before the local promotion is resolved by a registration probe with K2. Stale, replayed, same-key and competing rotations are rejected, a rotation and a recovery racing from the same state have one winner, and epochs never wrap. Only server authentication changes. Nothing rotates automatically. Server schema version 3 (`2.sqm`), client schema version 11 (`10.sqm`). See [docs/device-authentication-rotation.md](docs/device-authentication-rotation.md).

```kotlin
client.rotateDeviceAuthenticationKey()       // prepare + complete; safe to call again after a failure
client.resolveDeviceAuthenticationRotation() // after a crash or lost response: promotes K2 if the server has it
```

Milestone 17 done: device authentication rotation policy and key-age metadata. The server records, with every registration, the server time its current device authentication key was installed at (`authKeyInstalledAt`, injected server clock, epoch milliseconds): set by first registration, device recovery and routine rotation, together with the key and the epoch in the same atomic step, and never changed by a retry, a registration probe or a rejected transition. The signed `GET …/registration` now returns `{"authEpoch":N,"authKeyInstalledAt":T}`. The client stores none of it: `deviceAuthenticationRotationStatus()` reads it on demand and computes the key's age with its own clock (clamped at zero); `evaluateDeviceAuthenticationRotation(policy)` returns `Due` once the age reaches `DeviceAuthenticationRotationPolicy.maxKeyAge` (inclusive) and never rotates; `rotateDeviceAuthenticationKeyIfNeeded(policy)` runs the M16 rotation when due, resumes a pending rotation instead of starting another, and starts nothing while a recovery is pending. Nothing calls these implicitly and there is no default policy, scheduler or server-side policy. Server schema version 4 (`3.sqm`); legacy registrations are stamped once with the server clock on the first `open` after the upgrade. No client schema change; wire, protocol and cryptographic formats are unchanged. See [docs/device-authentication-rotation.md](docs/device-authentication-rotation.md#key-age-and-rotation-policy-milestone-17).

```kotlin
val policy = DeviceAuthenticationRotationPolicy(maxKeyAge = 30.days)
when (client.rotateDeviceAuthenticationKeyIfNeeded(policy)) { // only when the application calls it
    is DeviceAuthenticationRotationResult.NotNeeded -> Unit
    is DeviceAuthenticationRotationResult.Rotated -> Unit
    DeviceAuthenticationRotationResult.ResumedPendingRotation -> Unit
    DeviceAuthenticationRotationResult.RecoveryInProgress -> Unit
}
```

Milestone 18 done: last-device recovery with an offline recovery key. A user whose last usable device authentication key is gone (no other registered device for M14 recovery, no current key for M16 rotation) can still get a new key registered, with an offline Ed25519 recovery key registered in advance. `createLastDeviceRecoveryKey()` returns the key to the application only (43-character canonical Base64url text form, never stored by the library); `registerLastDeviceRecoveryKey(key)` sends only its public key, with a proof of possession, in a ServerAuth-signed request of a registered device of the user; the server keeps one recovery key per user and never replaces it (`409` for another key). To recover, `prepareLastDeviceRecovery()` creates a pending replacement key K2 (sealed at rest as record type 10, kept across restarts and storage key rotation, never pending together with a recovery or rotation key) and `completeLastDeviceRecovery(key)` fetches a public, server-issued, single-use challenge (16-byte ID, 32-byte nonce, current epoch, 5-minute expiry, one per device, persisted), signs a frozen binary statement (domains `KSecureMessage-LastDeviceRecovery-v1` / `-PoP-v1`: target, recovery public key, challenge ID and nonce, epoch, expiry, K2) with the recovery key and with K2, and submits it. The server verifies both with the **registered** recovery key, consumes the challenge and replaces the key by the shared compare-and-set in one transaction (epoch + 1, installation time = server now). An exact retry is recognized by its `LastDeviceRecoveryId`; a lost response is resolved by the K2 registration probe; stale, cross-user and competing recoveries are rejected, and races with M14 recovery and M16 rotation have one winner. Only server authentication changes: messaging identity, pins, verification, sessions, prekeys, tombstones, mailbox and pending/processed messages stay. The server stores only public keys, so its database cannot forge a recovery; whoever holds the offline key can recover the user's devices, and there is no recovery key rotation or revocation yet. Server schema version 5 (`4.sqm`), client schema version 12 (`11.sqm`). See [docs/last-device-recovery.md](docs/last-device-recovery.md).

```kotlin
val recoveryKey = client.createLastDeviceRecoveryKey()        // while healthy; back up recoveryKey.encode() offline
client.registerLastDeviceRecoveryKey(recoveryKey)

client.recoverLastDevice(LastDeviceRecoveryKey.decode(text)) // after every device-auth key is lost
```

Milestone 19 done: offline recovery key rotation and revocation. The recovery key of M18 can now be replaced or removed, but only with two authorities at once: a ServerAuth-signed request of a registered device of the user **and** a signature of the current offline key over a frozen statement (domains `KSecureMessage-RecoveryKeyRotation-v1` / `-NewKeyPoP-v1` / `KSecureMessage-RecoveryKeyRotationId-v1`, `KSecureMessage-RecoveryKeyRevocation-v1` / `KSecureMessage-RecoveryKeyRevocationId-v1`: user, authorizing device, current key, new key, recovery key epoch, timestamp, nonce); a rotation's new key also proves possession. Neither a device nor the recovery key alone can change it, and a lost offline key cannot be replaced by a device (deliberately). The server keeps a per-user recovery key state (`UNCONFIGURED` / `ACTIVE(epoch, key, installedAt)` / `REVOKED(epoch, revokedAt)`) with a monotonic recovery key epoch that never wraps and never resets: registration, rotation, revocation and registration after a revocation each advance it. Rotation and revocation are one atomic compare-and-set on key, epoch and the authorizing device's registration, with the statement nonce claim and the deletion of every outstanding last-device recovery challenge of the user; challenges are also bound to the recovery key epoch. Exact retries return `204` (recognized by the stored transition ID, even after the window and restarts), stale statements conflict, and races have one winner. Client: `rotateLastDeviceRecoveryKey(current, new)` (create and back up the new key first; calling again after a lost response returns `ALREADY_ACTIVE`), `revokeLastDeviceRecoveryKey(current)`, `lastDeviceRecoveryKeyStatus()` (signed `GET …/last-device-recovery/key`); nothing is stored on the client. Only the recovery key state changes: messaging identity, pins, verification, sessions, device authentication, prekeys, mailbox and messages stay. Server schema version 6 (`5.sqm`: existing keys become ACTIVE at epoch 1 with their registration time); no client schema change. See [docs/recovery-key-lifecycle.md](docs/recovery-key-lifecycle.md).

```kotlin
val newKey = client.createLastDeviceRecoveryKey()             // back up newKey.encode() offline first
client.rotateLastDeviceRecoveryKey(currentKey, newKey)        // device + current key; new key proves possession
client.revokeLastDeviceRecoveryKey(currentKey)                // or: turn last-device recovery off
client.registerLastDeviceRecoveryKey(client.createLastDeviceRecoveryKey()) // after a revocation; the epoch continues
```

Milestone 20 done: application commit boundary and bounded inbound deduplication. A received message is no longer acknowledged when it is decrypted: `decrypt` stores it as pending (sealed at rest, record type 11) in the same transaction as its ratchet step and returns `ReceiveResult.Delivery`; retries before the commit return the same delivery again and are not acknowledged; `pendingReceivedMessages()` returns every uncommitted message after a restart, in local acceptance order. Once the application has applied a message durably, `commitReceivedMessage` moves it from pending to processed in one transaction (commit time plus a sealed SHA-256 body digest, record type 12, domain `KSecureMessage-ProcessedMessage-v1`) and only then sends the ACK; an ACK failure never undoes the commit, and a later retry is answered with `AlreadyCommitted` and a new ACK. So an ACK now means the receiving application committed the message. A reused logical ID with another body fails with `LogicalMessageConflict`. Processed IDs are pruned only by an explicit `pruneProcessedMessages(ProcessedInboundRetentionPolicy(maxAge))` (no default, wall clock, age ≥ maxAge pruned); pending messages never expire. Delivery is at least once, not exactly once: apply messages idempotently keyed by sender and logical ID. `ReceiveResult.Message`/`Duplicate` are replaced by `Delivery`/`AlreadyCommitted` (breaking). Client SQLDelight schema version 13 (`12.sqm`; processed IDs from before are kept and stamped once by `initialize()`); no server or wire change. See [docs/application-delivery.md](docs/application-delivery.md).

```kotlin
when (val result = client.decrypt(envelope)) {
    is ReceiveResult.Delivery -> {
        app.applyIdempotently(result.sender, result.id, result.message.plaintext) // the app's own transaction
        client.commitReceivedMessage(result.message)                              // then the ACK is sent
    }
    is ReceiveResult.AlreadyCommitted, is ReceiveResult.Acknowledgement -> Unit
}
client.pendingReceivedMessages().forEach { /* after a restart: apply, then commit */ }
client.pruneProcessedMessages(ProcessedInboundRetentionPolicy(90.days))
```

## Next implementation steps

1. Bounded handling of uncommitted received messages: paged enumeration and an explicit, application-driven discard (dead-letter) of pending inbound messages with a reason, so a poison message cannot grow storage forever.
2. A deliberate, policy-controlled recovery key reset for a lost offline key (delay plus notification of every device), if applications need one; a PostgreSQL server adapter if multi-node deployment is needed.
3. Sealed sender.

## Gradle wrapper

The scaffold does not bundle the Gradle wrapper binary. After opening it with a local Gradle installation, generate one with:

```bash
gradle wrapper --gradle-version 9.0.0
```
