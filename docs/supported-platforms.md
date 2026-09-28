# Supported platforms

Status for the v0.1 release line. **Compiled** means the target's klib or jar
is built and published. **Tests executed** means the module tests run on that
target in the named task. A target without executed tests is labelled
compile-only: it is published, but its runtime behavior is not verified.

The machine-readable version of the "tests executed" column is
`KsmRelease.testExpectations` in `buildSrc/src/main/kotlin/KsmRelease.kt`;
`./gradlew verifyTestExecution` fails when one of those test tasks did not
run on the current host.

| Target | Compiled | Tests executed | Status | Notes |
|---|---|---|---|---|
| JVM | yes | `jvmTest` (KMP modules), `test` (server modules) — default build | supported | Java 17 bytecode |
| Android | yes | `:storage:keyprovider:android:testAndroidHostTest` (default build); `connectedAndroidDeviceTest` of `storage:keyprovider:android` and `storage:client:sqldelight` (emulator, not in the default build) | supported | minSdk 26, compileSdk 37. Other modules' common tests run on the JVM, not on Android. |
| macOS arm64 | yes | `macosArm64Test` — default build on a macOS host; `macosArm64KeychainHostTest` (signed host, needs signing material) | supported | |
| iOS simulator arm64 | yes | `iosSimulatorArm64Test` — default build on a macOS host; `iosSimulatorArm64KeychainHostTest` (booted simulator) | supported | |
| iOS arm64 (device) | yes | none | compile-only | same Kotlin/Native code as the simulator; no device test runner |
| iOS x64 simulator, macOS x64 | yes | none on Apple silicon hosts | compile-only | tests would need an Intel host |
| Linux x64 | yes | `linuxX64Test` — default build on a Linux host (CI) | supported | native SQLDelight tests need the host's `libsqlite3` |
| Windows x64 (mingwX64) | yes | none | compile-only | no Windows CI yet |
| JS on Node.js | yes | `jsNodeTest` — default build | supported | slow: Kodium's pure-Kotlin Ed25519/X25519 costs about 1–2 s per signature on Kotlin/JS, so the JS tests dominate the default build: measured on an Apple silicon laptop, `client:core:jsNodeTest` about 2 h 20 min (single tests up to 6 min, Mocha timeout 900 s), `core:protocol:jsNodeTest` about 17 min |
| JS in a browser | yes | none (`jsBrowserTest` disabled) | compile-only | browser tests need Chrome and are not part of the release gate |
| Wasm (wasmJs) on Node.js | yes | none (`wasmJsNodeTest` disabled) | **compile-only, runtime unsupported** | Kodium's randomness dependency, `org.kotlincrypto.random:crypto-rand` 0.6.0 (latest), calls `eval('require')('crypto')` on Node.js. Kotlin/Wasm emits ES modules, where `require` does not exist, so every key generation fails with `RandomnessProcurementException`. Do not work around it with a `require` shim. |
| Wasm (wasmJs) in a browser | yes | none (`wasmJsBrowserTest` disabled) | compile-only | untested |

Module exceptions: `storage:keyprovider:android` has only the Android target,
`storage:keyprovider:apple` only iOS and macOS, and the server modules
(`server:core`, `server:ktor`, `storage:server:sqldelight`) only the JVM.
`storage:client:sqldelight` has no JS/Wasm tests (only a web worker SQLite
driver exists there); its JS/Wasm artifacts are compile-only.

## Toolchain

| Tool | Version | Notes |
|---|---|---|
| Gradle | 9.6.0 | wrapper checked in (`./gradlew`) |
| Kotlin | 2.4.20 | |
| JDK | 17 or newer to run Gradle; CI uses 21 | JVM bytecode and server toolchain: 17 |
| Android SDK | compileSdk 37, minSdk 26 | `ANDROID_HOME` or `local.properties` `sdk.dir` |
| Android emulator (instrumentation) | API 35 `google_apis` system image | CI: x86_64; local runs used arm64 |
| Xcode / macOS | a current Xcode with an iOS simulator runtime; R1 was verified with Xcode 27.0 on macOS 26 (Apple silicon) | only for Apple targets |
| Node.js | downloaded by the Kotlin Gradle plugin from `https://nodejs.org/dist` through the repository declared in `settings.gradle.kts` | no system Node.js needed; npm (not yarn) installs the test tooling, lock files in `kotlin-js-store/` |

## How the Node.js download works

The Kotlin Gradle plugin downloads Node.js with a Gradle dependency
(`org.nodejs:node`). By default it adds an Ivy repository named
`Distributions at https://nodejs.org/dist` to the project at execution time,
which `RepositoriesMode.FAIL_ON_PROJECT_REPOS` rejects. The build therefore
declares that repository once in `settings.gradle.kts` (restricted to
`org.nodejs:node`) and sets `downloadBaseUrl` of `NodeJsEnvSpec` /
`WasmNodeJsEnvSpec` to `null` in the root build script, so the plugin adds
nothing. Repository enforcement stays on. `kotlin.js.yarn=false` selects npm,
which comes with Node.js, so no Yarn download repository is needed.
