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
| milestone 8 (format 0)       | `loadOrCreateKey()`  | none or present         | key created/loaded, records encrypted in one transaction |
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
(Android: file entries; Apple: account `v1/<id>`), so a future rotation can
keep several keys. Milestone 10 writes only one key per namespace and has no
rotation; `loadOrCreateKey()` fails with `KeyUnavailable` if an Apple
namespace holds more than one key.

### No reset or delete API

Neither provider can delete, reset or regenerate a key. Losing the key makes
the encrypted client state permanently unreadable; a reset flow needs
deliberate semantics (identity reset, prekey republication) and is future
work. Tests delete their own state through test-only helpers.

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

  The file holds the wrapped key only, never the raw key. Parsing is
  strict: wrong magic or version, truncation, trailing bytes, unsorted or
  duplicate IDs, a current ID without entry or another alias fail closed.
- **Writing**: a temporary file is written and synced, then moved into place
  atomically (`ATOMIC_MOVE`), then the directory is synced where possible.
  A crash leaves no file or the complete file.
- **First creation** (no file): reuse the Keystore key if one is left from an
  interrupted creation (it never protected a key that was handed out),
  otherwise generate it; generate the storage key; wrap; write; read back and
  unwrap; compare; return.
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
- Android: the contract and `AndroidStorageKeyProviderTest` (no raw key in
  the file, non-exportable Keystore key, missing alias leaves the file
  byte-identical and creates no alias, namespace-swapped entry fails,
  leftover Keystore key reused) run instrumented on a device or emulator
  (`connectedAndroidDeviceTest`); `WrappedKeyFileTest` runs on the host.
- Apple: the contract runs on the data protection keychain
  (`AppleStorageKeyProviderContractTest`) and on the macOS legacy keychain
  (`LegacyFileKeychainContractTest`). Kotlin/Native test binaries are
  unsigned: on macOS the data protection keychain answers -34018, in the iOS
  simulator runner there is no keychain (-25291). There the data protection
  tests print `SKIPPED` with the OSStatus and check nothing; running them
  needs a signed host application.
- `PlatformKeyProviderStorageTest` (`storage:sqldelight`): new database and
  restart, milestone 8 migration with a new platform key, encrypted database
  with lost or damaged provider state (fails twice, database unchanged, no
  replacement), database bound to an unknown key ID. Subclassed for Android
  (instrumented; the whole SQLite suite runs on the device), the data
  protection keychain and the macOS legacy keychain.

## Not covered

- Storage key rotation and re-encryption.
- Key reset or recovery.
- Protection against a compromised application process: the running
  application can always obtain the key.
- User-authentication-bound or StrongBox-required Android keys; Secure
  Enclave wrapping on Apple.
- JVM desktop, JS/Wasm, Linux and Windows providers.
