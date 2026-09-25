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
    ├── inmemory/
    ├── sqldelight/
    └── testing/
```

### `core:model`
Shared serializable value types such as user/device addresses, prekey metadata, and encrypted envelopes.

### `core:protocol`
Protocol-facing orchestration and Kodium dependency. Keep Kodium-specific types internal where possible so the public API remains stable.

### `client:core`
Client lifecycle contracts such as transport, session access, sending, receiving, acknowledgements and resend.

### `client:ktor`
Kotlin Multiplatform Ktor client transport adapter.

### `server:core`
Server-side repositories/services for public device information, prekey bundles, and encrypted envelopes. It should not decrypt client messages or own client session secrets. `PreKeyService` validates publications and hands out each one-time prekey at most once.

### `server:ktor`
JVM Ktor server routes/adapters for HTTP API v1, see [docs/prekey-publication.md](docs/prekey-publication.md).

### `storage:core`
Shared storage contracts.

### `storage:inmemory`
Simple in-memory implementations useful for tests and examples. Transactions are atomic.

### `storage:sqldelight`
Persistent `ClientStorage` on SQLite via SQLDelight, for all client targets. The application supplies the platform driver. Stores secret keys unencrypted, see [docs/storage.md](docs/storage.md).

### `storage:testing`
Shared `ClientStorage` and server `PreKeyRepository` contract tests that every storage adapter runs. Not published.

## Coordinates

Base package:

```text
dev.kreienbuehl.ksecuremessage
```

Current dependency baseline:

- Kotlin 2.4.20
- Kodium 1.0.0
- Ktor 3.6.0
- SQLDelight 2.4.0

## Status

Milestone 1 done: `KodiumProtocolEngine` creates identities and prekeys, sets up sessions with Kodium X3DH (the signed prekey signature is verified), and encrypts and decrypts with the Kodium Double Ratchet. Sessions persist as opaque `SecureSession.state` bytes. The initiator sends `PreKeyMessage`s until it has decrypted the first reply. After that it sends `RatchetMessage`s. See `core/protocol/src/commonTest`.

Milestone 2 done: `CiphertextMessageCodec` encodes `RatchetMessage` and `PreKeyMessage` into a versioned binary wire format for `EncryptedEnvelope.payload` (see [docs/wire-format.md](docs/wire-format.md)). `SecureMessageClient` encrypts and sends through it and decrypts incoming envelopes, accepting a first-contact `PreKeyMessage` without an existing session. Local prekeys come from `ClientStorage.preKeys`; a consumed one-time prekey is removed in the same transaction that stores the new session.

Milestone 3 done: the client owns its local protocol state. `initialize()` creates the identity, a current signed prekey and missing one-time prekeys in storage, and keeps whatever already exists. `currentPreKeyBundle()` and `publicOneTimePreKeys()` expose the public material for publication. `ClientStorage.transaction` is atomic in both adapters, and `storage:sqldelight` adds persistent storage. See [docs/storage.md](docs/storage.md).

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

> Storage adapters persist private keys and session state unencrypted. Protect the database with platform means until encryption at rest is added.

Milestone 4 done: `client.publishPreKeys()` uploads the identity key, the current signed prekey and the public one-time prekeys. The server's `PreKeyRepository` applies a publication atomically, treats retries as no-ops and rejects identity and prekey ID conflicts. Each bundle fetch atomically hands out and consumes at most one one-time prekey (lowest ID first); a bundle without one is served when none are left. `server:ktor` and `client:ktor` implement the HTTP API v1. See [docs/prekey-publication.md](docs/prekey-publication.md).

Milestone 5 done: remote identity trust on first use. The first identity key that sets up a session with a remote device, as initiator or responder, is pinned per `DeviceAddress` in the same transaction that stores the session; a failed first contact pins nothing. A different key for a pinned device fails with `SecureMessageClientException.IdentityChanged` and changes nothing. `ClientStorage.remoteIdentities` stores the pins; `storage:sqldelight` migrates its schema from version 1 to 2. TOFU detects identity changes after first contact but does not authenticate the remote party on first contact; safety numbers are not implemented. See [docs/identity-trust.md](docs/identity-trust.md).

Milestone 6 done: session replacement and simultaneous initiation, on wire v1. Every session records the `SessionInitiationId` (SHA-256 over the authenticated X3DH inputs) that created it. A new initiation from the pinned identity atomically replaces the existing session. When both sides initiate at once, both keep the smaller ID, independent of arrival order and restarts. Replaced and losing initiations are retired persistently (`ClientStorage.sessionInitiations`, SQLDelight schema version 3) and rejected with `StaleSessionInitiation`, so a replayed old `PreKeyMessage` cannot roll a session back. A losing initiation's messages fail with `SessionCollision` and are not delivered. An initiation that never reached the device before cannot be recognized as old with wire v1. See [docs/session-lifecycle.md](docs/session-lifecycle.md).

Transport ordering (milestone 6 follow-up): sessions converge only if, per (sender, recipient) device pair, a `PreKeyMessage` is processed before every envelope the sender sent after it. `SecureMessageClient.send` hands envelopes to the transport in encryption order, `MailboxRepository` guarantees per (sender, recipient) FIFO (the in-memory mailbox is now synchronized, checked by `MailboxRepositoryContractTest`), and applications decrypt one sender's envelopes in delivery order. No wire or HTTP API change. See [docs/transport-ordering.md](docs/transport-ordering.md).

Milestone 7 done: signed prekey lifecycle. Each signed prekey stores `createdAt` and, once replaced, `replacedAt`. `initialize()` rotates the current key after `PreKeyConfiguration.signedPreKeyRotationAge` (default 7 days). A replaced key keeps accepting delayed first contacts for `signedPreKeyGracePeriod` (default 30 days). After that, new initiations naming it fail with `SecureMessageClientException.ExpiredSignedPreKey`, and `initialize()` deletes its private key. Established sessions keep working. Retired session initiations record the local signed prekey they need and are pruned once it is deleted. Time comes from an injectable `kotlin.time.Clock`. Publication after rotation stays explicit (`publishPreKeys()`). SQLDelight schema version 4 adds nullable lifecycle columns; keys from before the upgrade start a full grace period on the next `initialize()`. This bounds, but does not close, the window in which a withheld initiation is accepted: wire v1 has no authenticated freshness. See [docs/signed-prekey-lifecycle.md](docs/signed-prekey-lifecycle.md).

Milestone 8 done: logical message IDs, encrypted acknowledgements, duplicate suppression and resend. Every application message gets a random 128-bit `LogicalMessageId`, carried inside a versioned, encrypted reliability frame (`SecurePayloadCodec`; ciphertext wire v1 is unchanged). `send` returns `SentMessage` and keeps the message **with its plaintext** in `ClientStorage.pendingOutbound` until the recipient's encrypted acknowledgement arrives; an accepted HTTP request is not an acknowledgement. `decrypt` returns a `ReceiveResult` (`Message`, `Duplicate`, `Acknowledgement`): each (sender, logical ID) is delivered at most once, recorded in `ClientStorage.processedInbound`, and acknowledged automatically; acknowledgements are never acknowledged. `retryPendingMessages(remote)` encrypts pending messages again under the current session with the same logical ID, which recovers messages lost to a session collision, a lost envelope or a lost acknowledgement. SQLDelight schema version 5 adds the two tables. Breaking: `send`/`decrypt` changed, `encrypt` is no longer public, and both peers must run milestone 8 (raw plaintext from older peers is rejected). No exactly-once application side effects, no background retry, processed IDs are kept forever. See [docs/message-reliability.md](docs/message-reliability.md).

```kotlin
val sent = client.send(bob, "hello".encodeToByteArray())   // pending until acknowledged
for (envelope in transport.receive(client.localAddress)) {
    when (val result = client.decrypt(envelope)) {
        is ReceiveResult.Message -> show(result.plaintext)    // once per logical message
        is ReceiveResult.Duplicate, is ReceiveResult.Acknowledgement -> Unit
    }
}
client.retryPendingMessages(bob)                            // e.g. after a SessionCollision
```

> Client storage now also holds the plaintext of sent messages until they are acknowledged. It is not encrypted.

## Next implementation steps

1. Authenticated server API, device re-registration, persistent server storage.
2. Safety numbers / manual identity verification, and a deliberate way to accept identity changes.
3. Encryption at rest for client storage (keys, sessions and pending message plaintext).
4. An application commit boundary for received messages and bounded dedup retention.
5. Sealed sender.

## Gradle wrapper

The scaffold does not bundle the Gradle wrapper binary. After opening it with a local Gradle installation, generate one with:

```bash
gradle wrapper --gradle-version 9.0.0
```
