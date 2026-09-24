# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

KSecureMessage is an early-stage Kotlin Multiplatform scaffold for a Signal-style secure messaging library built on [Kodium](https://github.com/LivotovLabs/kodium) (which provides the X3DH and Double Ratchet primitives). It adds the messaging lifecycle and infrastructure around those primitives. It does **not** aim for wire compatibility with Signal/libsignal. `KodiumProtocolEngine` implements milestone 1 (X3DH session setup, Double Ratchet, session export/restore; tests in `core/protocol/src/commonTest`). Milestone 2 added `CiphertextMessageCodec` (versioned binary wire format for `EncryptedEnvelope.payload`, spec in `docs/wire-format.md`) and the `SecureMessageClient` send/receive path; tests in `core/protocol` and `client/core` `commonTest`. Milestone 3 added client-owned identity/prekey lifecycle (`SecureMessageClient.initialize()`, `PreKeyManager`), atomic `ClientStorage.transaction` and the `storage:sqldelight` adapter; spec in `docs/storage.md`. Milestone 4 added prekey publication: `SecureMessageClient.publishPreKeys()`, the server `PreKeyRepository`/`PreKeyService` with atomic single-use one-time prekey handout, and HTTP API v1; spec in `docs/prekey-publication.md`, tests in `storage:inmemory`, `server:core`, `server:ktor` and `client:core`. Milestone 5 added remote identity trust on first use (`ClientStorage.remoteIdentities`, `SecureMessageClientException.IdentityChanged`, SQLDelight schema v2 via `1.sqm`); spec in `docs/identity-trust.md`, tests mainly in `client:core` `RemoteIdentityTrustTest`. The README's "Next implementation steps" section is the roadmap.

## Commands

The Gradle wrapper (Gradle 9.6) is checked in. Tests exist in `core:protocol`, `client:core`, `storage:inmemory`, `storage:sqldelight`, `server:core` and `server:ktor`. There is no lint setup.

```bash
./gradlew build                          # everything (all KMP targets; native/iOS need macOS)
./gradlew compileKotlinJvm               # fast check of KMP modules via JVM target
./gradlew compileAndroidMain             # Android target of all client-side modules
./gradlew :server:core:compileKotlin :server:ktor:compileKotlin
./gradlew :core:protocol:jvmTest         # KMP module tests on JVM
./gradlew :core:protocol:macosArm64Test  # same tests, native
./gradlew :core:protocol:jvmTest --tests "dev.kreienbuehl.ksecuremessage.protocol.SomeTest"
./gradlew :server:core:test :server:ktor:test  # JVM-only modules use plain `test`
./gradlew :storage:sqldelight:jvmTest :storage:sqldelight:macosArm64Test  # SQLite-backed tests (no JS/Wasm tests)
```

JS/Wasm test tasks (and so plain `./gradlew build`) fail with "repository 'Distributions at https://nodejs.org/dist' was added by unknown code". The cause is `RepositoriesMode.FAIL_ON_PROJECT_REPOS` in `settings.gradle.kts`. Until that is fixed, run `./gradlew build -x jsTest -x jsNodeTest -x jsBrowserTest -x wasmJsTest -x wasmJsNodeTest -x wasmJsBrowserTest`.

Configuration cache is on (`gradle.properties`). Android builds need `ANDROID_HOME` (a local SDK).

## Module layout and targets

- **Client-side / shared** (`core:model`, `core:protocol`, `storage:core`, `storage:inmemory`, `storage:sqldelight`, `storage:testing`, `client:core`, `client:ktor`): Kotlin Multiplatform with jvm, android, js, wasmJs, iOS, macOS, linuxX64, mingwX64. Sources live in `src/commonMain/kotlin`. Android uses the AGP 9 `com.android.kotlin.multiplatform.library` plugin with a `kotlin { android { namespace/compileSdk/minSdk } }` block. The SDK levels come from `libs.versions.toml`.
- **Server** (`server:core`, `server:ktor`): plain `kotlin.jvm` with `jvmToolchain(17)`. Sources live in `src/main/kotlin`. Do not add non-JVM targets here. The root `build.gradle.kts` sets the KMP JVM targets to Java 17 bytecode so the server can load them.
- `kotlin.mpp.applyDefaultHierarchyTemplate=false` is set, so there are no intermediate source sets (for example, no `iosMain`/`nativeMain`) unless you declare them explicitly.
- Each module's Maven group includes its parent directory (`dev.kreienbuehl.ksecuremessage.client:core`, `...storage:core`), set in the root `build.gradle.kts`. Several modules are named `core`. With a shared group, Gradle resolves `:storage:core` to itself and reports circular task dependencies, so keep coordinates unique.
- Dependency versions live only in `gradle/libs.versions.toml`.
- `storage:sqldelight` wires custom test source sets: `sqliteTest` (shared by `jvmTest` and `nativeTest`), with `expect`/`actual` test drivers. JS/Wasm have no test sources there. Its linuxX64/mingwX64 test link and run tasks are skipped unless the host OS matches (they need the target's libsqlite3).
- `storage:testing` holds `ClientStorageContractTest` and `PreKeyRepositoryContractTest` (in `commonMain`, depends on kotlin-test). Every `ClientStorage` / server `PreKeyRepository` adapter's tests extend them.

## Architecture

Dependency direction: `core:model` ← `core:protocol` ← `storage:core` ← {`client:core`, `server:core`, `storage:inmemory`, `storage:sqldelight`}. `client:core` never depends on a storage adapter; applications choose one. The transport adapters (`client:ktor`, `server:ktor`) sit on top of those. `storage:core` depends on `core:protocol` because `SessionStore` persists `SecureSession`.

Key boundaries:

- **Kodium stays behind `ProtocolEngine`** (`core:protocol`). Public models use `ByteArray` for keys (`PreKeyBundle`) and ratchet state (`SecureSession.state`, meant to be Kodium's export/import blob). Do not leak Kodium types into model, storage, client, or server APIs. `kodium` is an `implementation` dependency on purpose.
- **Ratchet state must update atomically.** `ProtocolEngine.encrypt/decrypt` return an `updatedSession`. The client must persist it inside `ClientStorage.transaction { }` together with the crypto operation (see `SecureMessageClient`).
- **Server is a blind relay.** `SecureMessageServer` only stores public prekeys and queues opaque `EncryptedEnvelope`s per recipient `DeviceAddress` (`drain` removes the envelopes it returns). It must never decrypt payloads or hold client session secrets.
- **Server prekeys:** `PreKeyRepository` (`storage:core`) keeps per device an identity key, the current signed prekey, available one-time prekeys and consumed-ID tombstones. `publish` is atomic and idempotent; conflicts throw `PreKeyPublicationException` and change nothing. `consumePreKeyBundle` removes and tombstones the lowest-ID one-time prekey in one atomic step, so no one-time prekey is handed out twice, even if the client uploads it again. Server consumption is not client consumption: the client deletes its private one-time prekey only when it accepts the `PreKeyMessage`. `PreKeyFormat` (`core:protocol`) checks publication sizes without Kodium.
- **Wire format:** `CiphertextMessageCodec` (`core:protocol`, no Kodium imports) owns the payload bytes; version-1 vectors in `CiphertextMessageCodecTest` are frozen. `EncryptedEnvelope.protocolVersion` versions only the envelope metadata. Protocol info strings live in `ProtocolConstants` and must never change.
- **Client storage:** `ClientStorage` has `identity`, `remoteIdentities` (TOFU pins), `sessions` and `preKeys` (local private prekeys). `transaction` must be atomic (rollback on throw), nested calls join the running transaction, and blocks must not do network I/O or switch threads. Accepting a `PreKeyMessage`, storing the session and removing the consumed one-time prekey happen in one `transaction`.
- **Local key lifecycle:** keys are created only by `ProtocolEngine`, never by storage. `PreKeyManager` allocates prekey IDs from persisted high-water marks (never reused, no wraparound; `PreKeyIdsExhausted`). Old signed prekeys are never deleted. Operations before `initialize()` throw `SecureMessageClientException.NotInitialized`. An existing identity is never replaced.
- **Remote identity trust (TOFU):** pins are per `DeviceAddress`, written only after the protocol accepted the key (`initiateSession` / successful decrypt) and in the same transaction as the session (and OTPK removal). Check before crypto, pin after. A pin is never replaced; a different key throws `IdentityChanged` and changes nothing. No reset/accept API yet. Never derive a pin from the envelope sender address. SQLDelight schema changes need a new `.sqm` migration (current version 2).
- **Secrets at rest:** adapters store private keys and session state unencrypted. Don't describe persistence as secure storage.
- **HTTP contract** (API v1) is defined twice and must stay in sync: `client:ktor` (`KtorSecureMessageTransport`, `HttpDtos.kt`) and `server:ktor` (`KSecureMessageRoutes`, `HttpDtos.kt`); `server:ktor` tests run the client adapter against the routes. Routes: `PUT /v1/devices/{user}/{device}/prekeys`, `GET /v1/devices/{user}/{device}/prekey-bundle`, `POST /v1/messages`, `GET /v1/devices/{user}/{device}/messages`. JSON via kotlinx.serialization; prekey bytes are Base64 strings. `client:core` transport errors are `SecureMessageTransportException`.
