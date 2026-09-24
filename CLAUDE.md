# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

KSecureMessage is an early-stage Kotlin Multiplatform scaffold for a Signal-style secure messaging library built on [Kodium](https://github.com/LivotovLabs/kodium) (which provides the X3DH and Double Ratchet primitives). It adds the messaging lifecycle and infrastructure around those primitives. It does **not** aim for wire compatibility with Signal/libsignal. `KodiumProtocolEngine` implements milestone 1 (X3DH session setup, Double Ratchet, session export/restore; tests in `core/protocol/src/commonTest`). Milestone 2 added `CiphertextMessageCodec` (versioned binary wire format for `EncryptedEnvelope.payload`, spec in `docs/wire-format.md`) and the `SecureMessageClient` send/receive path; tests in `core/protocol` and `client/core` `commonTest`. The README's "Next implementation steps" section is the roadmap.

## Commands

The Gradle wrapper (Gradle 9.6) is checked in. Tests exist in `core:protocol` and `client:core`. There is no lint setup.

```bash
./gradlew build                          # everything (all KMP targets; native/iOS need macOS)
./gradlew compileKotlinJvm               # fast check of KMP modules via JVM target
./gradlew compileAndroidMain             # Android target of all client-side modules
./gradlew :server:core:compileKotlin :server:ktor:compileKotlin
./gradlew :core:protocol:jvmTest         # KMP module tests on JVM
./gradlew :core:protocol:macosArm64Test  # same tests, native
./gradlew :core:protocol:jvmTest --tests "dev.kreienbuehl.ksecuremessage.protocol.SomeTest"
./gradlew :server:core:test              # JVM-only modules use plain `test`
```

JS/Wasm test tasks (and so plain `./gradlew build`) fail with "repository 'Distributions at https://nodejs.org/dist' was added by unknown code". The cause is `RepositoriesMode.FAIL_ON_PROJECT_REPOS` in `settings.gradle.kts`. Until that is fixed, run `./gradlew build -x jsTest -x jsNodeTest -x jsBrowserTest -x wasmJsTest -x wasmJsNodeTest -x wasmJsBrowserTest`.

Configuration cache is on (`gradle.properties`). Android builds need `ANDROID_HOME` (a local SDK).

## Module layout and targets

- **Client-side / shared** (`core:model`, `core:protocol`, `storage:core`, `storage:inmemory`, `client:core`, `client:ktor`): Kotlin Multiplatform with jvm, android, js, wasmJs, iOS, macOS, linuxX64, mingwX64. Sources live in `src/commonMain/kotlin`. Android uses the AGP 9 `com.android.kotlin.multiplatform.library` plugin with a `kotlin { android { namespace/compileSdk/minSdk } }` block. The SDK levels come from `libs.versions.toml`.
- **Server** (`server:core`, `server:ktor`): plain `kotlin.jvm` with `jvmToolchain(17)`. Sources live in `src/main/kotlin`. Do not add non-JVM targets here.
- `kotlin.mpp.applyDefaultHierarchyTemplate=false` is set, so there are no intermediate source sets (for example, no `iosMain`/`nativeMain`) unless you declare them explicitly.
- Each module's Maven group includes its parent directory (`dev.kreienbuehl.ksecuremessage.client:core`, `...storage:core`), set in the root `build.gradle.kts`. Several modules are named `core`. With a shared group, Gradle resolves `:storage:core` to itself and reports circular task dependencies, so keep coordinates unique.
- Dependency versions live only in `gradle/libs.versions.toml`.

## Architecture

Dependency direction: `core:model` ← `core:protocol` ← `storage:core` ← {`client:core`, `server:core`, `storage:inmemory`}. The transport adapters (`client:ktor`, `server:ktor`) sit on top of those. `storage:core` depends on `core:protocol` because `SessionStore` persists `SecureSession`.

Key boundaries:

- **Kodium stays behind `ProtocolEngine`** (`core:protocol`). Public models use `ByteArray` for keys (`PreKeyBundle`) and ratchet state (`SecureSession.state`, meant to be Kodium's export/import blob). Do not leak Kodium types into model, storage, client, or server APIs. `kodium` is an `implementation` dependency on purpose.
- **Ratchet state must update atomically.** `ProtocolEngine.encrypt/decrypt` return an `updatedSession`. The client must persist it inside `ClientStorage.transaction { }` together with the crypto operation (see `SecureMessageClient`).
- **Server is a blind relay.** `SecureMessageServer` only stores and serves `PreKeyBundle`s and queues opaque `EncryptedEnvelope`s per recipient `DeviceAddress` (`drain` removes the envelopes it returns). It must never decrypt payloads or hold client session secrets.
- **Wire format:** `CiphertextMessageCodec` (`core:protocol`, no Kodium imports) owns the payload bytes; version-1 vectors in `CiphertextMessageCodecTest` are frozen. `EncryptedEnvelope.protocolVersion` versions only the envelope metadata. Protocol info strings live in `ProtocolConstants` and must never change.
- **Client storage:** `ClientStorage` has `sessions` and `preKeys` (local private prekeys). Accepting a `PreKeyMessage`, storing the session and removing the consumed one-time prekey happen in one `transaction`.
- **HTTP contract** is defined twice and must stay in sync: `client:ktor/KtorSecureMessageTransport` and `server:ktor/KSecureMessageRoutes`. Routes: `POST /prekeys`, `GET /users/{user}/devices/{device}/prekeys`, `POST /messages`, `GET /users/{user}/devices/{device}/messages`. JSON is handled by kotlinx.serialization.
