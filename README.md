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
    └── inmemory/
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
Server-side repositories/services for public device information, prekey bundles, and encrypted envelopes. It should not decrypt client messages or own client session secrets.

### `server:ktor`
JVM Ktor server routes/adapters.

### `storage:core`
Shared storage contracts.

### `storage:inmemory`
Simple in-memory implementations useful for tests and examples.

## Coordinates

Base package:

```text
dev.kreienbuehl.ksecuremessage
```

Current dependency baseline:

- Kotlin 2.3.10
- Kodium 1.0.0
- Ktor 3.6.0

## Status

Milestone 1 done: `KodiumProtocolEngine` creates identities and prekeys, sets up sessions with Kodium X3DH (the signed prekey signature is verified), and encrypts and decrypts with the Kodium Double Ratchet. Sessions persist as opaque `SecureSession.state` bytes. The initiator sends `PreKeyMessage`s until it has decrypted the first reply. After that it sends `RatchetMessage`s. See `core/protocol/src/commonTest`.

## Next implementation steps

1. Map Kodium X3DH bundle/session types into `core:protocol`.
2. Define persisted session records without exposing Kodium objects through public APIs.
3. Add atomic session update semantics to client storage.
4. Implement prekey publication/consumption flows.
5. Add a versioned wire format for `EncryptedEnvelope` and prekey/session-init messages.
6. Add cross-platform protocol tests and Kodium persistence round-trip tests.

## Gradle wrapper

The scaffold does not bundle the Gradle wrapper binary. After opening it with a local Gradle installation, generate one with:

```bash
gradle wrapper --gradle-version 9.0.0
```
