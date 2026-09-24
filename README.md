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
Client lifecycle contracts such as transport, session access, sending, and receiving.

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

## Next implementation steps

1. Remote identity trust (TOFU, identity change handling).
2. Handle session reset and simultaneous initiation.
3. Authenticated server API, device re-registration, persistent server storage.
4. Encryption at rest for client storage.
5. Sealed sender.

## Gradle wrapper

The scaffold does not bundle the Gradle wrapper binary. After opening it with a local Gradle installation, generate one with:

```bash
gradle wrapper --gradle-version 9.0.0
```
