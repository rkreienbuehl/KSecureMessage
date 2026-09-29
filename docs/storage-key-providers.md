# Platform storage key providers

Milestone 10. `storage:keyprovider:android` and `storage:keyprovider:apple`
implement `StorageKeyProvider` (`storage:encryption`) on platform key
storage, so applications no longer persist the storage key themselves.

```
M9 record encryption (AES-256-GCM, record format v1)       storage:encryption
        ↑ 32-byte StorageEncryptionKey + StorageKeyId
StorageKeyProvider                                          this document
        ↓
Android: key wrapped by a non-exportable Keystore AES key   storage:keyprovider:android
Apple:   key stored as a Keychain generic password item     storage:keyprovider:apple
```

The storage key stays the milestone 9 key: 32 random bytes from the
platform's secure random source (`StorageEncryptionKey.generate`), never
derived from a platform secret. The providers only persist and protect it.
Record format, associated data, key check and database layout are unchanged;
the database still stores only the key ID and the sealed key check.

```kotlin
// Android
val storage = SqlDelightClientStorage.open(driver, AndroidStorageKeyProvider(context, namespace = "account-42"))
// iOS, macOS (entitled apps)
val storage = SqlDelightClientStorage.open(driver, AppleStorageKeyProvider(namespace = "account-42"))
```

## Shared semantics

### `loadOrCreateKey` and `key`

- `loadOrCreateKey()` creates a key **only when the provider has no state**
  for its namespace. State that exists but cannot be read (missing platform
  key, damaged data, locked keychain, missing entitlement, any platform
  error) throws `StorageEncryptionException.KeyUnavailable`. "Cannot load"
  never becomes "create".
- A created key is returned only after it was persisted and read back.
  If persisting fails, the call fails; no transient key is handed out.
- `loadOrCreateKey()` is idempotent: later calls and new provider instances
  (application restarts) return the same key.
- `key(id)` never creates. Unknown IDs return `null`.
- With several keys (a namespace in a storage key rotation),
  `loadOrCreateKey()` throws `KeyUnavailable`: the database, not the
  provider, knows which key is current.

### `hasKeys` (S1)

`hasKeys()` reports whether the provider holds any key. It never creates,
rotates, repairs or replaces a key. State that exists but cannot be read
throws `KeyUnavailable` (Android: a damaged wrapped key file) or reports
`true` (Apple: an item exists even if its data is damaged); it is never
reported as "no key". Storage uses it to tell a database from before record
encryption from a downgraded one ([storage-encryption.md](storage-encryption.md#downgrade-protection)).
`StaticStorageKeyProvider.hasKeys()` is always `true`. Contract tests:
`StorageKeyProviderContractTest` (`hasKeys*`).

### `createKey` and `removeKey` (storage key rotation)

Milestone 11 ([storage-key-rotation.md](storage-key-rotation.md)):

- `createKey(id)` returns key `id`. If the provider already has it, that key
  is returned unchanged; otherwise a new random key is created, persisted and
  read back first. It never overwrites or replaces a key and never touches
  other keys. Concurrent calls for one ID yield one key. It requires a
  provisioned provider (at least one key); otherwise, or if the state cannot
  be read, it throws `KeyUnavailable` and changes nothing. The database
  allocates the ID; providers never choose one.
- `removeKey(id)` removes exactly key `id` and returns `true`, or `false` if
  the provider does not have it. Other keys are untouched. It never removes
  the provider's last key (`IllegalStateException`, nothing changed); there
  is no "delete all". The storage only removes a key after it proved that no
  record uses it, and never the current key.
- Concurrent first calls return one key (see the platform sections).
- `CancellationException` is rethrown unchanged. A key persisted before a
  cancellation is found by the next call; an existing key is never
  overwritten.
- Exceptions and `toString()` never contain key bytes.

### Interaction with `SqlDelightClientStorage.open`

| Database                     | Provider call        | Provider state          | Result |
|------------------------------|----------------------|-------------------------|--------|
| new (no bound key)           | `loadOrCreateKey()`  | none                    | key created, bound |
| new                          | `loadOrCreateKey()`  | present                 | existing key bound |
| milestone 8 (format 0)       | `hasKeys()`, then `loadOrCreateKey()` | none | key created, migration intent committed, records encrypted in one transaction |
| milestone 8 (format 0), interrupted migration | `hasKeys()`, then `loadOrCreateKey()` | present, intent verifies | migration resumed with that key |
| format 0 without a valid intent | `hasKeys()` | present | `DowngradeRejected` (S1, [storage-encryption.md](storage-encryption.md#downgrade-protection)) |
| encrypted, key ID bound      | `key(id)` only       | present                 | opens |
| encrypted                    | `key(id)` only       | missing (lost, deleted) | `KeyUnavailable`, nothing created |
| encrypted                    | `key(id)` only       | damaged                 | `KeyUnavailable`, nothing created |
| encrypted, unknown key ID    | `key(id)` only       | any                     | `KeyUnavailable`, nothing created |

The bound key ID in the database is what protects an encrypted database from
a replacement key: `open` never calls `loadOrCreateKey()` for it, whatever
state the provider is in. The providers add a second guard where the
platform lets them detect a loss (Android, below).

### Namespaces

Both providers take a `namespace` (letters, digits, `.`, `_`, `-`, 1–64
characters; default `"default"`). Every namespace has its own key and its own
platform state. Use one namespace per database: separate accounts, profiles
or test and production databases in one application need distinct
namespaces. Reusing a namespace for a second database is safe for
confidentiality (each database binds the key it was created with) but ties
both databases to one key. Namespaces do not change key IDs.

### Key IDs

The first key of a namespace has key ID 1. Platform state is keyed by key ID
(Android: file entries; Apple: account `v1/<id>`), so a namespace holds
several keys during a storage key rotation: key 1, key 2, … Key IDs come from
the database's high-water mark and are never reused.

### No reset API

Neither provider can reset or regenerate a key, and neither can delete all
keys of a namespace. The only deletion is `removeKey(id)` of one key the
database retires after a rotation. Losing a needed key makes the encrypted
client state permanently unreadable; a reset flow needs deliberate semantics
(identity reset, prekey republication) and is future work. Tests delete
their own state through test-only helpers.

### Application responsibilities

- Choose a stable namespace per database; never change it for an existing
  database.
- Keep the database and the provider state on the same device: back up or
  restore neither, or both with the platform secret (which Keystore and
  `ThisDeviceOnly` Keychain items do not allow).
- Treat `KeyUnavailable` on open as "state lost", never as "start fresh"
  without an explicit user decision.

## Android

`AndroidStorageKeyProvider(context, namespace = "default")`, minSdk 26
(Keystore AES-GCM needs API 23).

- **Wrapping key**: an AES-256 Android Keystore key, alias
  `dev.kreienbuehl.ksecuremessage.storage.v1.<namespace>`, purposes
  encrypt/decrypt, GCM, no padding, randomized encryption (the Keystore
  generates every IV), no user authentication. The key material never
  leaves the Keystore (`getEncoded()` is `null`).
- **Wrapping**: `AES/GCM/NoPadding`, 96-bit IV chosen by the Keystore,
  128-bit tag. Associated data:
  `"KSecureMessage-StorageKeyWrap-v1" ‖ u16 namespace length ‖ namespace ‖ i32 key ID`,
  so a wrapped key copied to another namespace or key ID does not unwrap.
- **Wrapped key file**: `noBackupFilesDir/ksecuremessage/storage-key-<namespace>.bin`,
  format version 1, big-endian:

  ```
  magic "KSKW" | version u8 = 1 | alias length u16 | alias UTF-8
  | current key ID i32 | entry count u16 (>= 1)
  | entries sorted by key ID: key ID i32 | IV length u8 = 12 | IV | length u16 = 48 | ciphertext + tag
  ```

  The file holds wrapped keys only, never a raw key. Parsing is
  strict: wrong magic or version, truncation, trailing bytes, unsorted or
  duplicate IDs, a current ID without entry or another alias fail closed.
  All entries are wrapped by the same Keystore key, each with the key ID in
  its associated data. The "current key ID" field is kept for the frozen
  format but is not rotation state: writers set it to the lowest entry; the
  database decides which key is current.
- **Writing**: a temporary file is written and synced, then moved into place
  atomically (`ATOMIC_MOVE`), then the directory is synced where possible.
  A crash leaves no file or the complete file.
- **First creation** (no file): reuse the Keystore key if one is left from an
  interrupted creation (it never protected a key that was handed out),
  otherwise generate it; generate the storage key; wrap; write; read back and
  unwrap; compare; return.
- **Rotation keys**: `createKey(id)` needs the file and the Keystore key;
  it wraps a new key under the same Keystore key and writes a new file with
  every existing entry copied byte for byte (a damaged entry included) plus
  the new one, then reads it back. `removeKey(id)` writes the file without
  that entry. Both use the same atomic write. A damaged entry makes only its
  own key ID fail with `KeyUnavailable`; it is never regenerated or dropped.
- **Loading** (file present): parse, get the Keystore key, unwrap, check 32
  bytes. A missing alias, `KeyPermanentlyInvalidatedException`, tag failure,
  damaged file or any Keystore error throws `KeyUnavailable`; the file is not
  touched, no Keystore key is generated.
- **Concurrency**: one process-wide mutex plus an exclusive file lock on
  `storage-key-<namespace>.lock` (for applications with several processes).
  Creation re-checks the file under the lock, so concurrent first calls
  return one key.
- **Hardware backing**: the Keystore may keep the key in a TEE or StrongBox
  depending on the device; the provider neither requires nor promises it.
  StrongBox-only and user-authentication-bound variants (biometric or device
  credential) could be added later; this provider favours background access.
- **Backup and restore**: `noBackupFilesDir` is excluded from Auto Backup,
  and Keystore keys are never backed up. If an application still restores
  the database (or copies the wrapped file) onto a device without the
  Keystore key, opening fails with `KeyUnavailable`; nothing is regenerated.
  Exclude the database from backup and device transfer as well
  (`android:dataExtractionRules` / `fullBackupContent`); this library does
  not change the application manifest. Clearing application data removes
  database, file and Keystore key together.

## Apple

`AppleStorageKeyProvider(namespace = "default", accessGroup = null)` for
iOS (`iosArm64`, `iosX64`, `iosSimulatorArm64`) and macOS (`macosArm64`,
`macosX64`); shared `appleMain` code on the Security framework.

- **Item**: `kSecClassGenericPassword`, service
  `dev.kreienbuehl.ksecuremessage.storage.<namespace>`, account
  `v1/<key ID>` (the prefix versions the item layout), data = the 32 raw key
  bytes, nothing else. `accessGroup` sets `kSecAttrAccessGroup` for sharing
  with app extensions.
- **Accessibility**: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`:
  readable in the background once the device was unlocked after boot; the
  item stays on this device and is never restored or migrated to another
  one.
- **Sync**: `kSecAttrSynchronizable = false`; the key does not go to iCloud
  Keychain.
- **Data protection keychain**: `kSecUseDataProtectionKeychain = true`
  (always the case on iOS). On macOS this needs a signed application with an
  application identifier or keychain access group entitlement; without it
  every call fails with `KeyUnavailable` (OSStatus -34018,
  `errSecMissingEntitlement`). There is **no automatic fallback**.
- **macOS legacy option**: `AppleStorageKeyProvider.legacyFileKeychain(namespace)`
  (macOS only) uses the file-based login keychain for applications that
  cannot have the entitlement. It is weaker: the accessibility class is not
  enforced there; the item is protected by the keychain file and its access
  control list. Choose it explicitly.
- **Not the Secure Enclave**: a generic password item is protected by the
  Keychain (data protection classes, device keys), not by the Secure
  Enclave. A Secure Enclave wrapping key could be added later.
- **First creation**: if the namespace has no item, generate the key and
  `SecItemAdd` it as `v1/1`; then read it back and return the stored bytes.
- **Rotation keys**: `createKey(id)` adds item `v1/<id>` (never
  `SecItemUpdate`; a duplicate means the stored key wins) and reads it back;
  `removeKey(id)` deletes the item of that one account with a query that
  always names the account, so it cannot match other keys.
- **Loading**: data of any size other than 32 bytes throws `KeyUnavailable`
  (never truncated, padded or regenerated). Any OSStatus other than success
  or "item not found" (for example `errSecInteractionNotAllowed` before the
  first unlock) throws `KeyUnavailable` and creates nothing.
- **Concurrency**: a process-wide mutex serializes creation; across
  processes (app and extension sharing an access group) `SecItemAdd` rejects
  the second item with `errSecDuplicateItem`, and the loser reads and
  returns the winner's key.
- **Loss**: a deleted item cannot be told apart from "never created": the
  item is the whole provider state. For an encrypted database `open` only
  calls `key(id)`, which returns `null`, so the database fails with
  `KeyUnavailable` and no key is created for it. A *new* database in the
  same namespace would get a new key.

## Tests

- `StorageKeyProviderContractTest` (`storage:testing`): first creation (32
  bytes), idempotency, `key(createdId)`, restart, unknown IDs (no creation),
  namespace separation, lost backing key (never a replacement; with
  detectable state `loadOrCreateKey` keeps failing), damaged state (fails
  twice, no repair), 16 concurrent first calls on separate instances.
  Storage key rotation (milestone 11): a second key by `createKey` differs
  from the first, both survive a restart, `createKey` is idempotent and never
  overwrites, 16 concurrent `createKey` calls for one ID yield one key,
  `createKey` without a provisioned key fails and creates nothing,
  `loadOrCreateKey` refuses several keys, `removeKey` removes only that key
  (repeat: `false`), never the last key, and not in another namespace. The
  same contract also runs on the in-memory test key store in
  `storage:client:sqldelight` (`MemoryStorageKeyProviderContractTest`).
- Android: the contract and `AndroidStorageKeyProviderTest` (no raw key in
  the file, non-exportable Keystore key, missing alias leaves the file
  byte-identical and creates no alias, namespace-swapped entry fails,
  leftover Keystore key reused, rotation keys are wrapped entries of one file
  and removal keeps the other entries byte for byte, a damaged entry fails
  only for its own ID and is preserved, `createKey` with a missing alias
  changes nothing) run instrumented on a device or emulator
  (`connectedAndroidDeviceTest`); `WrappedKeyFileTest` runs on the host.
- Apple, plain test tasks (`macos*Test`, `ios*Test`, unsigned Kotlin/Native
  binaries): the contract on the macOS legacy keychain
  (`LegacyFileKeychainContractTest`, `LegacyFileKeychainStorageTest`) and the
  missing-entitlement behavior: `KeychainWithoutEntitlementTest` (the default
  provider fails closed; on macOS writes get -34018 while lookups answer "not
  found", so `key` returns `null`; the iOS simulator runner has no keychain,
  -25291) and `NoLegacyFallbackTest` (macOS: after -34018 nothing is in the
  legacy keychain). These tasks exclude every `*DataProtection*` test: nothing
  is skipped or reported as passed without running.
- Apple, data protection keychain: every `*DataProtection*` test runs only in
  the signed keychain host (next section) and fails, never skips, when the
  keychain is unusable there.
- `PlatformKeyProviderStorageTest` (`storage:client:sqldelight`): new database and
  restart, milestone 8 migration with a new platform key, encrypted database
  with lost or damaged provider state (fails twice, database unchanged, no
  replacement), database bound to an unknown key ID, and a storage key
  rotation with a restart in the middle that ends with key 1 removed from the
  platform store. Subclassed for Android
  (instrumented; the whole SQLite suite runs on the device), the data
  protection keychain (`DataProtectionKeychainStorageTest`, signed host) and
  the macOS legacy keychain.

## Signed keychain host (Apple data protection keychain tests)

The data protection keychain needs keychain entitlements, which bare
Kotlin/Native test binaries do not have. `apple-keychain-host/run.sh` wraps
the test executable that Gradle already builds (`linkDebugTest<Target>`,
`test.kexe`) in a minimal `.app` with those entitlements and runs the
`*DataProtection*` tests in it with the Kotlin/Native test runner. There is no
Xcode project and no Swift; the tests are the Kotlin tests.

```
test.kexe -> KeychainHost.app (Info.plist, bundle ID, entitlements, signature)
          -> kotlin.test runner --ktest_filter=*DataProtection*
          -> AppleStorageKeyProvider(namespace) (data protection keychain)
          -> Security.framework -> StorageKeyProviderContractTest,
             PlatformKeyProviderStorageTest (SQLDelight)
```

```bash
./gradlew appleKeychainHostTest                 # macosArm64 + iosSimulatorArm64
./gradlew iosSimulatorArm64KeychainHostTest     # needs a booted simulator, no signing
./gradlew macosArm64KeychainHostTest            # needs macOS signing (below)
./gradlew :storage:keyprovider:apple:iosSimulatorArm64KeychainHostPurge  # after an interrupted run
```

Each target task runs, one host at a time: the provider tests
(`:storage:keyprovider:apple`), the SQLDelight tests and the relaunch test
(`:storage:client:sqldelight`), then `DataProtectionLeftoverCheck` (no
`dev.kreienbuehl.ksecuremessage.storage.*` item left in the host's groups).
Every run prints one result line per module:
`KEYCHAIN HOST <module> <target>: PASSED (...)`, `FAILED — ...` or
`NOT EXECUTED — signing/entitlement environment unavailable (<reason>)`.
NOT EXECUTED keeps the build green unless `ksm.apple.keychainHost.required=true`.
A run with zero tests, a missing runner summary or any failed test is FAILED.
The tasks are not part of `build`/`check`, like `connectedAndroidDeviceTest`.

What runs in the host:

- `DataProtectionKeychainContractTest`: the whole contract with the default
  access group (first creation, idempotency, `key(createdId)`, restart,
  unknown ID creates nothing, namespaces, lost item never replaced, 31-byte
  item fails twice, 16 concurrent first calls on separate instances).
- `DataProtectionAccessGroupContractTest`: the same contract with an explicit
  entitled group (`<prefix>.<bundle ID>.shared`).
- `DataProtectionKeychainItemTest`: the item as the Keychain reports it
  (service, account `v1/1`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
  not synchronizable, default group = first `keychain-access-groups` entry,
  32 bytes); an explicit group holds the item and the default group does not;
  a group the host is not entitled to fails with -34018 twice and nothing is
  written elsewhere (no retry without the group); lookups never recreate a
  deleted item.
- `DataProtectionNotLegacyTest` (macOS): the item is in the data protection
  keychain and not in the file-based one.
- `DataProtectionKeychainStorageTest`: `PlatformKeyProviderStorageTest` (new
  database and restart, milestone 8 migration with a new key, lost item and
  damaged item: `KeyUnavailable` twice, database unchanged, no replacement;
  database bound to an unknown key ID creates nothing).
- `DataProtectionRelaunchTest`: persistence across processes. Three separate
  launches share one `relaunch-<random>` namespace: `create` (new database,
  new key, known identity stored), `verify` (another process opens the
  database with a new provider and decrypts the identity, which only the same
  key can do), `cleanup` (item and database deleted). Key bytes are never
  printed or compared outside the process.

Entitlements (found by experiment in the simulator host):

- No keychain entitlement: every call fails with -34018.
- `application-identifier` alone: the default provider works (items go to
  the application identifier group); an explicit group fails with -34018.
- `keychain-access-groups` alone: default and explicit groups work.
- The host uses both, like a real application: application identifier
  `<prefix>.<bundle ID>` and `keychain-access-groups` =
  `[<prefix>.<bundle ID>, <prefix>.<bundle ID>.shared]`. Production
  applications have their own identifier and groups; `accessGroup` must be one
  of the application's entitled groups.

### iOS simulator host

Ad-hoc signed; no team, certificate or profile. The simulator reads
entitlements from a `__TEXT,__entitlements` section, which the
`iosSimulatorArm64` test binaries of both modules link from
`apple-keychain-host/ios-simulator.entitlements` (fixed test values: prefix
`KSMTEST000`, bundle ID `dev.kreienbuehl.ksecuremessage.keychainhost`). The
script installs the app (`simctl install`), launches it with
`simctl launch --console-pty` and `SIMCTL_CHILD_*` environment, and decides
by the runner's summary (`simctl` does not report the exit code). It checks
that the installed binary is the one it built.

### macOS host

Restricted entitlements (`com.apple.application-identifier`,
`keychain-access-groups`) need an Apple Development signature and a macOS
development provisioning profile that allows them; without the profile the
system refuses to launch the binary. The script copies the profile to
`Contents/embedded.provisionprofile`, fills `macos.entitlements.template`
(`com.apple.application-identifier`, `com.apple.developer.team-identifier`,
`keychain-access-groups`) and signs with `codesign --entitlements`, then
prints the effective entitlements (`codesign -d --entitlements -`). No
signing material is in the repository; configure it locally, for example in
`~/.gradle/gradle.properties`:

```properties
ksm.apple.teamId=<your team ID>
ksm.apple.macosProfile=/path/to/KSecureMessage_Keychain_Host.provisionprofile
# optional
ksm.apple.bundleId=dev.kreienbuehl.ksecuremessage.keychainhost
ksm.apple.signingIdentity=<SHA-1 of the Apple Development identity>   # default: the one of the team
ksm.apple.keychainHost.required=true
```

(or `KSM_APPLE_TEAM_ID`, `KSM_APPLE_MACOS_PROFILE`, ...). To get the profile,
register the App ID (with your own bundle ID if you like) and create a macOS
App Development profile for it that includes this Mac in the developer portal,
or let Xcode do it: create a macOS app target with that bundle ID, your team
and "Automatically manage signing", add a `keychain-access-groups` entitlement,
and build it once in the Xcode app. Xcode stores the profile ("Mac Team
Provisioning Profile: <bundle ID>") in
`~/Library/Developer/Xcode/UserData/Provisioning Profiles`. A free Personal
Team works too: there the portal is not available and `xcodebuild` cannot
register the Mac ("Your team has no devices"), but building once in the Xcode
app registers it. The profile used here allows
`com.apple.application-identifier` = `<team>.<bundle ID>`,
`com.apple.developer.team-identifier` and `keychain-access-groups` =
`<team>.*`, which covers both host groups.

Observed on the signed macOS host: a query without
`kSecUseDataProtectionKeychain` (as `legacyFileKeychain` issues it) searches
both keychains in an entitled process and so also finds data protection
items; only `kSecUseDataProtectionKeychain = false` restricts it to the
file-based keychain. A synchronizable attribute in a query routes it to the
data protection keychain. This does not affect the default provider, which
always sets the flag; the legacy provider is meant for processes without the
entitlement, where the data protection keychain is unreachable.

### Execution status

| Target | Data protection keychain |
|---|---|
| macosArm64 | EXECUTED (signed macOS host, Apple Development + Mac Team Provisioning Profile) |
| macosX64 | EXECUTED (same host, x86_64 binary under Rosetta) |
| iosSimulatorArm64 | EXECUTED (entitled simulator host) |
| iosX64 | NOT EXECUTED (compile only; no x86 simulator runtime) |
| iosArm64 | NOT EXECUTED (compile only; needs a device) |

## Not covered

- Deleting orphan keys left by an abandoned rotation start.
- Key reset or recovery.
- Protection against a compromised application process: the running
  application can always obtain the key.
- User-authentication-bound or StrongBox-required Android keys; Secure
  Enclave wrapping on Apple.
- JVM desktop, JS/Wasm, Linux and Windows providers.
