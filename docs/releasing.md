# Releasing

How KSecureMessage is versioned, what is published, and the checklist for a
release. R1 prepared all of this; no release has been tagged or uploaded yet.

## Versioning and compatibility

The only version is `version = …` in the root `build.gradle.kts`
(currently `0.1.0-SNAPSHOT`). `checkReleaseConventions` fails if it is not a
SemVer version.

Before 1.0:

- **0.x means the public API can still change.** A minor release (0.1 → 0.2)
  may break source or binary compatibility; a patch release (0.1.0 → 0.1.1)
  should not. Every intended API change updates the checked-in baseline
  (`api/` in each module) and is listed in the release notes.
- **API compatibility is tracked from the R1 baseline on.** `checkKotlinAbi`
  (part of `./gradlew build`) fails on any public API change that is not in
  the baseline. Declarations marked `@InternalKSecureMessageApi` are in the
  baseline but carry no compatibility promise.
- **Frozen formats do not follow the Maven version.** The ciphertext wire
  format v1, the secure payload and ACK frames v1, protocol info strings,
  `SessionInitiationId`, ServerAuth v1, the recovery, rotation, last-device
  recovery, recovery key rotation/revocation/reset statements and IDs,
  safety number v1, storage record format v1 and record type assignments,
  and the storage key rotation state machine are frozen by test vectors. An
  incompatible change needs a new explicit format version (for example a new
  domain string or version byte) with migration and tests, whatever the Maven
  version says.
- **Schema migrations stay explicit and tested**: client schema (currently
  15) and server schema (currently 7) change only through numbered `.sqm`
  migrations with a frozen fixture of the previous schema.

## Published artifacts

Group `dev.kreienbuehl.ksecuremessage`, artifact ID `ksecuremessage-` plus the
Gradle path with dashes (`KsmRelease.kt` in `buildSrc`). Kotlin Multiplatform
modules add one artifact per target (`…-jvm`, `…-android`, `…-iosarm64`, …)
plus the root artifact with Gradle module metadata.

| Gradle module | Artifact ID | Classification | Purpose | Audience |
|---|---|---|---|---|
| `:core:model` | `ksecuremessage-core-model` | public library | addresses, IDs, envelopes, bundles | all |
| `:core:protocol` | `ksecuremessage-core-protocol` | public library | `ProtocolEngine`, Kodium engine, frozen formats | all |
| `:storage:core` | `ksecuremessage-storage-core` | public library | client and server storage contracts | storage implementers |
| `:storage:encryption` | `ksecuremessage-storage-encryption` | internal support (published as dependency) | record encryption, `StorageKeyProvider` | key provider implementers |
| `:storage:rotation:core` | `ksecuremessage-storage-rotation-core` | internal support (published as dependency) | storage key rotation state machine | — |
| `:storage:client:inmemory` | `ksecuremessage-storage-client-inmemory` | public library (tests/examples) | non-persistent client storage | tests, examples |
| `:storage:client:sqldelight` | `ksecuremessage-storage-client-sqldelight` | public library | encrypted persistent client storage | applications |
| `:storage:server:inmemory` | `ksecuremessage-storage-server-inmemory` | public library (tests/examples) | non-persistent server storage | tests, examples |
| `:storage:server:sqldelight` | `ksecuremessage-storage-server-sqldelight` | public library | SQLite server storage (JVM) | server hosts |
| `:storage:keyprovider:android` | `ksecuremessage-storage-keyprovider-android` | public library | Android Keystore key provider | Android apps |
| `:storage:keyprovider:apple` | `ksecuremessage-storage-keyprovider-apple` | public library | Apple Keychain key provider | iOS/macOS apps |
| `:client:core` | `ksecuremessage-client-core` | public library | `SecureMessageClient` | applications |
| `:client:ktor` | `ksecuremessage-client-ktor` | public library | HTTP transport | applications |
| `:server:core` | `ksecuremessage-server-core` | public library | `SecureMessageServer` | server hosts |
| `:server:ktor` | `ksecuremessage-server-ktor` | public library | HTTP routes | server hosts |
| `:storage:testing` | — | testing, **not published** | contract tests for adapters | this repository |
| `apple-keychain-host/` | — | host harness, **not published** | signed keychain test host | this repository |
| `samples/jvm-e2e` | — | sample, **not published** | consumer fixture and E2E example | this repository |
| `buildSrc` | — | build logic, **not published** | release checks | this repository |

Every publication carries a POM (name, description, URL, Apache-2.0 license,
developer, SCM), Gradle module metadata, a sources jar and a Dokka HTML
documentation jar (as `-javadoc.jar`, which Maven Central requires).

## Signing and Maven Central (not executed in R1)

Signing is configured only when a key is supplied from outside the
repository. Never commit keys or passwords. Inputs (Gradle properties or
`ORG_GRADLE_PROJECT_*` environment variables):

| Property | Content |
|---|---|
| `signingInMemoryKey` | ASCII-armored PGP private key |
| `signingInMemoryKeyId` | key ID (optional) |
| `signingInMemoryKeyPassword` | key password |
| `mavenCentralUsername`, `mavenCentralPassword` | Central Portal user token |

Without `signingInMemoryKey`, publications are unsigned (fine for
`build/release-repo`). The Central upload task (`publishToMavenCentral`) is
configured with manual release and is not run by any build or CI job.

## Release checklist

Run in this order; stop at the first failure.

1. **Clean working tree**: `git status` shows nothing to commit; you are on
   the release commit.
2. **Version**: set `version` in `build.gradle.kts` (drop `-SNAPSHOT` for a
   release), update `README.md` if it names the version.
3. **Default build**: `./gradlew build` on macOS (Apple targets) — no `-x`
   exclusions. Then `./gradlew verifyTestExecution`.
4. **API compatibility**: `./gradlew checkKotlinAbi` (also part of `build`).
   On a macOS host it covers the Apple klibs too. If the API changed on
   purpose: `./gradlew updateKotlinAbi`, review the diff of `*/api/*`, list
   the changes in the release notes. Never run `updateKotlinAbi` in CI.
5. **Publication**: `./gradlew verifyPublication` publishes to
   `build/release-repo`, runs `inspectReleaseArtifacts` and the consumer
   fixture.
6. **Consumer smoke test**: part of step 5 (`consumerSmokeTest`): builds
   `samples/jvm-e2e` against the published artifacts only, runs the
   end-to-end example (`E2E PASSED`) and compiles the KMP smoke module for
   every target.
7. **Platform tests**: `./gradlew macosArm64Test iosSimulatorArm64Test`
   (part of step 3 on macOS); Linux: the `linuxX64Test` of CI.
8. **Android instrumentation** on an emulator (never a personal device):
   `./gradlew :storage:keyprovider:android:connectedAndroidDeviceTest :storage:client:sqldelight:connectedAndroidDeviceTest`.
   This runs the platform key provider contract (`StorageKeyProviderContractTest`
   via `AndroidStorageKeyProviderContractTest`) and the storage tests with the
   Keystore provider. Record the emulator API level.
9. **Apple keychain host**: boot a simulator, then
   `./gradlew iosSimulatorArm64KeychainHostTest -Pksm.apple.keychainHost.required=true`;
   with signing material, `./gradlew macosArm64KeychainHostTest -Pksm.apple.keychainHost.required=true`
   (data protection keychain provider contract, `StorageKeyProviderContractTest`,
   and relaunch). Without signing material the macOS host reports NOT
   EXECUTED; say so in the release notes.
10. **Security checklist**: walk [docs/security-review.md](security-review.md);
    confirm no frozen format, schema or state machine changed unless the
    release notes say so (`git diff <last tag> -- '*.sq' '*.sqm'` and the
    frozen-vector tests).
11. **Documentation**: README status, `docs/supported-platforms.md`,
    `docs/application-lifecycle.md`, `docs/operating-the-server.md` match
    the release; `checkReleaseConventions` passes.
12. **Artifact inspection**: read `build/reports/release-artifacts.txt`
    (every file and its size); spot-check a POM, a sources jar and a
    documentation jar.
13. **Tag and release** (maintainer only): commit the version, tag
    `v<version>`, publish with signing inputs set
    (`./gradlew publishToMavenCentral`), release in the Central Portal, then
    bump to the next `-SNAPSHOT`.

## CI

| Workflow | Trigger | Jobs |
|---|---|---|
| `.github/workflows/ci.yml` (Tier A) | push to `main`, pull requests | Linux: `./gradlew build` (JVM, JS/Node, linuxX64, server, Android host tests, `checkKotlinAbi`, `checkReleaseConventions`), `verifyTestExecution`, `verifyPublication` |
| `.github/workflows/platform.yml` (Tier B) | push to `main`, manual, weekly | macOS: Apple tests + full `checkKotlinAbi` + iOS simulator keychain host; signed macOS keychain host (only with secrets); Android emulator instrumentation (API 35) |

Secrets for the signed macOS host (never in the repository, never available
to pull requests from forks): `KSM_APPLE_TEAM_ID`,
`KSM_APPLE_DEV_CERT_P12_BASE64`, `KSM_APPLE_DEV_CERT_PASSWORD`,
`KSM_APPLE_MACOS_PROFILE_BASE64`.

Locally the keychain host reads `ksm.apple.teamId`, `ksm.apple.macosProfile`
(and the optional `ksm.apple.*` settings) from `-P`/`gradle.properties`, then
`KSM_APPLE_*` environment variables, then the git-ignored root
`local.properties`.
