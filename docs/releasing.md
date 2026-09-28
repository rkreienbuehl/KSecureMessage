# Releasing

How KSecureMessage is versioned, what is published, how it is signed,
uploaded and documented, and the checklist for a release. No public release
has been made yet.

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
- **Version strategy**: `0.1.0-SNAPSHOT` during development (uploaded to the
  Central snapshot repository), `0.1.0-internal.N` for internal prereleases,
  `0.1.0` only for a deliberate public release.
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

## Signing

Every artifact file of a release (jars, klibs, AARs, POMs, Gradle module
metadata, sources and documentation jars) is signed with the project's PGP
key. Keys come only from outside the repository; never commit or print a
private key or passphrase. Signing is on as soon as one of these is present
(`KsmRelease.signingMode`):

| Where | Setting | Content |
|---|---|---|
| Maintainer machine | `signing.gnupg.keyName` in `~/.gradle/gradle.properties` | ID of the KSecureMessage signing key in the local gpg keyring (not secret); the passphrase stays in gpg-agent / pinentry |
| CI (repository secrets) | `ORG_GRADLE_PROJECT_signingInMemoryKey`, `ORG_GRADLE_PROJECT_signingInMemoryKeyId`, `ORG_GRADLE_PROJECT_signingInMemoryKeyPassword` | ASCII-armored private key, key ID, passphrase |

The public key is published on `keys.openpgp.org` and `keyserver.ubuntu.com`
(Maven Central checks signatures against public key servers).

With signing on, `inspectReleaseArtifacts` requires a `.asc` next to every
artifact file (and always md5/sha1/sha256/sha512 checksums that match), and
`./gradlew verifyReleaseSignatures` verifies every signature in
`build/release-repo` with the **public** key only (`scripts/verify-signatures.sh`,
temporary keyring; the key comes from `-Pksm.signing.publicKey=<armored file>`
or the public part of `signing.gnupg.keyName`). Without signing inputs,
publications are unsigned, which is fine for `build/release-repo` only.

## Remote publication (Maven Central)

`publishToMavenCentral` (vanniktech plugin, Central Portal) uploads every
published module. Credentials: `mavenCentralUsername` / `mavenCentralPassword`
(a Central Portal **user token**, not the login) in `~/.gradle/gradle.properties`,
or `ORG_GRADLE_PROJECT_mavenCentralUsername` / `ORG_GRADLE_PROJECT_mavenCentralPassword`
as CI secrets. Namespace: `dev.kreienbuehl` (verified by DNS), with SNAPSHOT
publishing enabled.

- **SNAPSHOT versions** go to the Central snapshot repository
  `https://central.sonatype.com/repository/maven-snapshots/`. Verify them with
  `./gradlew verifyRemotePublication`: `mirrorRemoteRepository` downloads
  what was uploaded into `build/remote-mirror`, `inspectRemoteArtifacts`
  inspects it like the local repository (artifact set, POMs, module metadata
  and every target variant it references, sources and documentation jars, no
  test code or secret files, signatures, md5/sha1 checksums),
  `verifyRemoteSignatures` verifies every signature, and
  `remoteConsumerSmokeTest` builds and runs `samples/jvm-e2e` against the
  remote repository only, with an empty temporary Gradle user home (no cache,
  no Maven Local; `checkConsumerIsolation` rejects `mavenLocal`, project
  dependencies and substitutions).
- **Release versions** (for example `0.1.0-internal.1`) create a Central
  Portal *deployment*. `automaticRelease = false`: the upload stops at
  `VALIDATED`, and nothing is public until someone presses *Publish* in the
  Portal. While it is validated and unpublished, the Portal serves it as a
  Maven repository at
  `https://central.sonatype.com/api/v1/publisher/deployments/download/`
  (bearer: the Base64 of `mavenCentralUsername:mavenCentralPassword`), so
  `./gradlew verifyRemotePublication` works for it too: the mirror, the
  inspection, the signature check and the consumer fixture (which gets the
  token only through its environment) all read that endpoint. To only
  exercise the path, drop the validated deployment in the Portal afterwards
  instead of publishing it. The version change for such a run is a working
  tree edit that is not committed.

## Documentation site

The site is MkDocs (Material theme) over `docs/` (the only documentation
source; `SECURITY.md` is included, not copied) plus the Dokka API reference
of the published modules. Tools are pinned with hashes in
`docs/requirements.txt` (edit `docs/requirements.in`, then
`uv pip compile docs/requirements.in --python-version 3.12 --generate-hashes -o docs/requirements.txt`).

```bash
python3 -m venv .venv                     # or: uv venv .venv --python 3.12
.venv/bin/pip install --require-hashes --no-deps -r docs/requirements.txt
./gradlew docsSite                        # Dokka → docs/api/, mkdocs build --strict → build/site, checkDocsSite
.venv/bin/mkdocs serve                    # live preview (after one ./gradlew stageApiReference)
```

`mkdocs build --strict` fails on every warning: broken links and anchors,
nav entries without a page, pages missing from the nav, and a missing API
reference (`docs/api/` is generated and git-ignored). `checkDocsSite` checks
that every page, the search index and the API reference of every published
module are in the built site. `.github/workflows/docs.yml` builds the site on
every pull request and push and deploys it to GitHub Pages only for a push to
`main`.

## Release checklist

Run in this order; stop at the first failure. Record every gate as
PASSED, FAILED or NOT EXECUTED (configured but not run is not passed).

1. **Clean working tree**: `git status` shows nothing to commit; you are on
   the release commit.
2. **Version**: set `version` in `build.gradle.kts` (`0.1.0-internal.N` for
   an internal prerelease, no suffix for a public release), update
   `README.md` and `docs/getting-started.md` if they name the version.
3. **Hosted CI green** on that commit: Tier A (`ci.yml`, including the
   hosted Linux native tests: every `linuxX64Test` ran with tests, checked by
   `verifyTestExecution`), Tier B (`platform.yml`) and the documentation
   workflow (`docs.yml`). A workflow counts only if GitHub ran it and it
   succeeded.
4. **Default build** (macOS host, Apple targets): `./gradlew build` with no
   `-x` exclusions, then `./gradlew verifyTestExecution`.
5. **API compatibility**: `./gradlew checkKotlinAbi` (also part of `build`).
   On a macOS host it covers the Apple klibs too. If the API changed on
   purpose: `./gradlew updateKotlinAbi`, review the diff of `*/api/*`, list
   the changes in the release notes. Never run `updateKotlinAbi` in CI.
6. **Publication and signing**: with signing inputs set,
   `./gradlew verifyPublication verifyReleaseSignatures` publishes to
   `build/release-repo`, runs `inspectReleaseArtifacts` (signatures and
   checksums required), the consumer fixture (`consumerSmokeTest`: builds
   `samples/jvm-e2e` against the published artifacts only, runs the
   end-to-end example (`E2E PASSED`) and compiles the KMP smoke module for
   every target) and verifies every signature.
7. **Android instrumentation** on an emulator (never a personal device):
   `./gradlew :storage:keyprovider:android:connectedAndroidDeviceTest :storage:client:sqldelight:connectedAndroidDeviceTest`.
   This runs the platform key provider contract (`StorageKeyProviderContractTest`
   via `AndroidStorageKeyProviderContractTest`) and the storage tests with the
   Keystore provider. Record the emulator API level. (Also in Tier B.)
8. **Apple keychain host**: boot a simulator, then
   `./gradlew iosSimulatorArm64KeychainHostTest -Pksm.apple.keychainHost.required=true`
   and `./gradlew macosArm64KeychainHostTest -Pksm.apple.keychainHost.required=true`
   (data protection keychain provider contract, `StorageKeyProviderContractTest`,
   and relaunch). Both must report PASSED; signing settings come from one
   source (see "Apple signing"), never from ad-hoc overrides. The macOS host
   runs on the maintainer's Mac (listed in the development profile); hosted
   CI reports it NOT EXECUTED (see "Apple signing").
9. **Documentation**: `./gradlew docsSite` (`mkdocs build --strict` and
   `checkDocsSite`); after the release commit reaches `main`, the `docs.yml`
   deployment to GitHub Pages must succeed.
10. **Remote publication**: `./gradlew publishToMavenCentral`, then
    - SNAPSHOT: `./gradlew verifyRemotePublication` (`inspectRemoteArtifacts`,
      `verifyRemoteSignatures`, `remoteConsumerSmokeTest`);
    - release version: the Central Portal deployment reaches `VALIDATED`;
      publish it only for an intended release, otherwise drop it.
11. **Vulnerability reporting**: `SECURITY.md` names GitHub private
    vulnerability reporting (checked by `checkReleaseConventions`), and it is
    enabled for the repository (`gh api repos/rkreienbuehl/KSecureMessage/private-vulnerability-reporting`
    returns `"enabled": true`).
12. **Security checklist**: walk [docs/security-review.md](security-review.md);
    confirm no frozen format, schema or state machine changed unless the
    release notes say so (`git diff <last tag> -- '*.sq' '*.sqm'` and the
    frozen-vector tests).
13. **Documentation content**: README status, `docs/supported-platforms.md`,
    `docs/application-lifecycle.md`, `docs/operating-the-server.md` match
    the release; `checkReleaseConventions` passes.
14. **Artifact inspection**: read `build/reports/release-artifacts.txt` and
    `build/reports/remote-artifacts.txt` (every file and its size);
    spot-check a POM, a sources jar and a documentation jar.
15. **Tag and release** (maintainer only, never automated): commit the
    version, tag `v<version>`, publish the validated deployment in the
    Central Portal, then bump to the next `-SNAPSHOT`.

`scripts/release-dry-run.sh` runs the local gates of steps 4–6, 9 and 10 in
order and prints PASSED / FAILED / NOT EXECUTED per gate.

## CI

| Workflow | Trigger | Jobs |
|---|---|---|
| `.github/workflows/ci.yml` (Tier A) | push to `main`, pull requests, manual | Linux `build`: `./gradlew build -x jsNodeTest` (JVM, linuxX64 with `libsqlite3-dev`, server, Android host tests, `checkKotlinAbi`, `checkReleaseConventions`), `verifyTestExecution -Pksm.testMatrix=non-js`, `verifyPublication`; Linux `js`: `jsNodeTest`, `verifyTestExecution -Pksm.testMatrix=js`; `compile-only`: `verifyCompileOnlyTargets` (Wasm, JS browser, mingwX64 main and test code); `ci-passed` requires all three |
| `.github/workflows/platform.yml` (Tier B) | push to `main`, manual, weekly | macOS: Apple tests + full `checkKotlinAbi` + iOS simulator keychain host; signed macOS keychain host (only with secrets and a profile for all devices, see "Apple signing"); Android emulator instrumentation (API 35) |
| `.github/workflows/docs.yml` | push to `main`, pull requests, manual | `build`: Dokka, `mkdocs build --strict`, `checkDocsSite`, Pages artifact; `deploy` (push to `main` only): GitHub Pages |

The two Tier A test jobs together run exactly the test tasks of plain
`./gradlew build`; `verifyTestExecution` with `js` and `non-js` together
checks the whole Linux matrix. Workflow permissions are `contents: read`;
only the Pages deploy job gets `pages: write` and `id-token: write`
(checked by `checkReleaseConventions`).

## Apple signing

The signed macOS keychain host needs a team ID, a macOS provisioning profile
for `<team>.dev.kreienbuehl.ksecuremessage.keychainhost` (or a wildcard) and an
Apple Development certificate of that team **contained in the profile**. One
source of truth per environment:

- **Maintainer machine**: the git-ignored root `local.properties`
  (`ksm.apple.teamId`, `ksm.apple.macosProfile`, optional
  `ksm.apple.signingIdentity`, `ksm.apple.bundleId`). Do not also set them in
  `~/.gradle/gradle.properties` or the environment.
- **CI**: repository secrets `KSM_APPLE_TEAM_ID`,
  `KSM_APPLE_DEV_CERT_P12_BASE64`, `KSM_APPLE_DEV_CERT_PASSWORD`,
  `KSM_APPLE_MACOS_PROFILE_BASE64` (never available to pull requests from
  forks).

Lookup order per setting: Gradle properties (`-P` and
`~/.gradle/gradle.properties`), then `KSM_APPLE_*` environment variables, then
`local.properties`. If two sources set **different** values for the same
setting, the host task fails and names the setting and the sources, so a
stale lower-priority value can never be used silently. `run.sh` then checks
that the profile belongs to the team, matches the bundle ID, has not expired,
and picks the signing identity whose certificate is embedded in the profile.

**Known limitation (hosted CI).** The current profile is a development
profile: it lists the Macs it may run on, and macOS kills the signed host at
launch on any other machine (`Killed: 9`). A GitHub-hosted runner is never
listed, so `platform.yml` detects a profile without `ProvisionsAllDevices`
and reports the signed macOS host as **NOT EXECUTED** (a workflow warning),
without failing Tier B. That is not hosted coverage: the signed macOS host
stays a **maintainer-machine gate** (checklist step 8) until the CI secrets
hold a Developer ID certificate and provisioning profile for all devices;
then the hosted job runs and every failure fails it. `run.sh` reports the
same NOT EXECUTED reason on any Mac the profile does not list.
