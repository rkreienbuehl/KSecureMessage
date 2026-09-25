# Client storage encryption (record level)

Milestone 9 encrypts the sensitive records of persistent client storage with
AES-256-GCM: key pairs, session state and pending message plaintext. The
rest of the database (IDs, addresses, timestamps, public pins) stays
plaintext metadata. This is **record-level client storage encryption, not
database encryption**: the database file, its schema, row counts and
metadata are readable without the key.

Code: `storage/encryption` (`ClientRecordCipher`, `StorageKeyProvider`,
`StorageEncryptionKey`, `StorageEncryptionException`), used by
`storage/client/sqldelight` (`SqlDelightClientStorage.open`,
`LegacyPlaintextMigration`). Tests: `storage/encryption/src/commonTest`,
`storage/client/sqldelight/src/sqliteTest` (`SqlDelightEncryptionTest`,
`SqlDelightMigrationTest`).

Nothing here touches the protocol: the wire format (outer v1),
`SecurePayload` v1, `CiphertextMessageCodec`, `EncryptedEnvelope`, the HTTP
API, X3DH and ratchet info strings, `SessionInitiationId` and the transport
ordering contract are unchanged. Peers cannot tell whether a client encrypts
its storage.

## Threat model

Protected: an attacker who obtains the client database (a copied file, a
backup, a stolen disk image) but **not** the storage key.

- They cannot read private keys, session state or pending message plaintext.
- Modifying an encrypted value is detected (AEAD authentication).
- Copying an encrypted value into another row (another prekey ID, another
  remote address, another message ID) or into another record type is
  detected: the ciphertext is bound to its record type and row key through
  the associated data.
- A failure is never hidden: reads fail with `StorageEncryptionException`,
  never return "absent", never fall back to plaintext and never cause state
  to be regenerated.

Not protected:

- An attacker who has both the database and the storage key.
- A compromised running process, memory scraping, malicious application
  code, a device compromised while unlocked.
- Plaintext metadata: who the device talks to (addresses), how many
  sessions, prekeys and pending messages exist, message IDs, timestamps,
  pinned remote identity keys, retired initiations, high-water marks.
- Integrity of plaintext metadata and of the database structure. An offline
  attacker can delete rows or the whole database, change timestamps (for
  example shorten or extend a signed prekey's grace period), reorder pending
  sequence numbers, change high-water marks, or remove or replace remote
  identity pins (TOFU state is not integrity-protected at rest). Most of this
  is denial of service; a replaced pin weakens TOFU for that device.
- **Rollback**: replacing the database with an older, validly encrypted copy
  (older ratchet state, older pending set) is not detected. That would need a
  secure monotonic counter, which this milestone does not have.
- Server compromise and traffic analysis (out of scope of storage).

## What is encrypted

| Record | Sensitive fields | Encrypted | Plaintext | Bound in associated data | Reason |
|---|---|---|---|---|---|
| Device authentication key (`device_authentication_key`, milestone 12) | Ed25519 private key | whole key pair (public + private) | row ID 0 | record type | Like the identity; see [server-authentication.md](server-authentication.md). The non-secret `device_authentication_state.awaits_upgrade_key` stays plaintext. |
| Pending recovery key (`device_authentication_recovery_key`, milestone 14) | Ed25519 private key of the replacement key | whole key pair (public + private), same content layout as record type 7 | row ID 0 | record type 8 | Its own record type, so it never opens as the active key or the other way round; promotion reseals it as type 7. See [device-recovery.md](device-recovery.md). |
| Local identity (`local_identity`) | private key | whole key pair (public + private) | row ID 0 | record type | Sealing the pair keeps public and private halves consistent; the public key is not needed for lookup. |
| Signed prekeys (`signed_pre_key`) | private key | public key, signature, private key | ID, `created_at`, `replaced_at` | record type, ID | Lifecycle SQL (rotation, stamping, expiry) works on the plaintext timestamps. |
| One-time prekeys (`one_time_pre_key`) | private key | public key, private key | ID | record type, ID | Publication reads and authenticates every record, so a tampered public key is never published silently. |
| Sessions (`session`) | ratchet state | state | remote user and device ID | record type, remote address | Lookup by address. |
| Pending outbound (`pending_outbound_message`) | message plaintext (reliability frame) | frame | sequence, recipient, logical message ID | record type, recipient, logical ID | Lookup and ordering need the plaintext key and sequence. |
| Remote identity pins (`remote_identity`) | none (public keys) | nothing | all | none | Public values; see the integrity limitation above. |
| Retired initiations (`retired_session_initiation`) | none (public hashes) | nothing | all | none | Replay-protection lookups. |
| Processed inbound (`processed_inbound_message`) | metadata only | nothing | all | none | Duplicate lookups; hiding communication metadata is out of scope. |
| `pre_key_state` | none | nothing | current signed prekey ID, high-water marks | none | Needed by SQL; tampering is denial of service. |
| `storage_encryption` | none | key check records (sealed, empty) for the current and, while rotating, the retiring key | format, key IDs, rotation phase, key ID high-water mark | key check: record type, key ID | Marker, key binding, storage key rotation state. |

`InMemoryClientStorage` does not encrypt: it never persists bytes. Its
observable behavior for valid data is the same as SQLDelight's
(`ClientStorageContractTest` runs against both).

## Algorithm

AES-256-GCM from [cryptography-kotlin](https://github.com/whyoleg/cryptography-kotlin)
0.6.0 (`cryptography-provider-optimal`: JDK on JVM/Android, WebCrypto on
JS/Wasm, CryptoKit/OpenSSL 3 on Apple, OpenSSL 3 on Linux/Windows).

- Key: 256 bits, from the `StorageKeyProvider`.
- Nonce: 96 bits, fresh from the platform CSPRNG (`CryptographyRandom`) for
  every encryption, stored in the record. Never derived from time, IDs or
  counters. Writing the same value twice gives different records. With
  random 96-bit nonces a key should not seal more than about 2^32 records;
  client storage stays far below that, and key rotation (below) resets it.
- Tag: 128 bits.

Kodium 1.0.0 was not used: it has no public AEAD with associated data (only
NaCl SecretBox), and a KSecureMessage-specific composition was ruled out.
Only `storage/encryption/.../AesGcm.kt` imports cryptography-kotlin.

## Record format, version 1

Local persistence only; its version numbers are unrelated to the wire
format's.

```
offset  size  field
0       4     magic "KSMR" (4B 53 4D 52)
4       1     format version = 0x01
5       1     algorithm = 0x01 (AES-256-GCM, 12-byte nonce, 16-byte tag)
6       4     storage key ID, u32 big-endian
10      12    nonce
22      n+16  ciphertext || tag
```

Opening checks, in this order, and fails with:

- fewer than 4 bytes: `MalformedRecord`;
- wrong magic, version or algorithm: `UnsupportedFormat`;
- shorter than 38 bytes: `MalformedRecord`;
- a key ID other than the storage's bound key: `KeyUnavailable` (no other
  key is tried);
- tag mismatch: `AuthenticationFailed`;
- an invalid decrypted record encoding: `MalformedRecord` / `UnsupportedFormat`.

## Associated data

```
header (bytes 0..9 of the record)
| u32 length | "KSecureMessage-Storage-v1" (UTF-8)
| record type : u8
| field count : u8
| (u32 length | field bytes)*
```

All integers big-endian; every field is length-prefixed, so different field
lists never encode alike (`("ab","c")` ≠ `("a","bc")`). The header is part of
the associated data, so version, algorithm and key ID are authenticated.

| Record type | ID | Fields |
|---|---|---|
| local identity | 1 | none (there is one) |
| signed prekey | 2 | ID as u32 |
| one-time prekey | 3 | ID as u32 |
| session | 4 | remote user ID (UTF-8), remote device ID (UTF-8) |
| pending outbound | 5 | recipient user ID, recipient device ID, 16-byte logical message ID |
| key check | 6 | none |
| device authentication key | 7 | none (there is one; milestone 12) |
| pending device recovery key | 8 | none (there is at most one; milestone 14) |

The IDs and the domain string must never change. Because the record type is
authenticated, a record moved to another type fails even when the plaintext
sizes match (tested with an identity record and a one-time prekey record of
equal length). Because the row key is authenticated, a record copied to
another row of the same type fails.

## Record plaintext

- Identity: `u8 version = 1 | bytes(publicKey) | bytes(privateKey)`
- Device authentication key: `u8 version = 1 | bytes(publicKey) | bytes(privateKey)`
  (frozen vector in `StorageCipherTest.deviceAuthenticationKeyVector`)
- Signed prekey: `u8 version = 1 | bytes(publicKey) | bytes(signature) | bytes(privateKey)`
- One-time prekey: `u8 version = 1 | bytes(publicKey) | bytes(privateKey)`
- Session: `SecureSession.state` as is (versioned inside)
- Pending: the `SecurePayload` frame as is (versioned inside)
- Key check: empty

`bytes(x)` is a u32 big-endian length followed by x. Lengths are checked
against the remaining input; trailing data is rejected. IDs and addresses are
not repeated in the plaintext.

## Fixed vector

Key `00 01 … 1f`, key ID 7, nonce `a0 a1 … ab`, record type session, fields
`"bob"`, `"laptop"`, plaintext `"ratchet-state"` (computed independently with
Python `cryptography`'s AESGCM; frozen in `StorageCipherTest.fixedVector`):

```
associated data  4b534d52010100000007 000000194b5365637572654d6573736167652d53746f726167652d7631 04 02 00000003626f62 000000066c6170746f70
record           4b534d52010100000007 a0a1a2a3a4a5a6a7a8a9aaab 9479084e2dae76921111e6a762 f6e5f769cd5531b252c0472a9e5067b2
```

## Storage key and key provider

```kotlin
interface StorageKeyProvider {
    suspend fun loadOrCreateKey(): StorageEncryptionKey   // storage with no bound key yet
    suspend fun key(id: StorageKeyId): StorageEncryptionKey?  // existing storage; never creates
}

val storage = SqlDelightClientStorage.open(driver, keyProvider)
```

- `StorageEncryptionKey(id, bytes)`: exactly 32 bytes, copied in; `copyBytes()`
  returns a copy (for providers that persist it); `toString()` is redacted;
  `StorageEncryptionKey.generate(id)` draws a random key.
- The storage key is its own cryptographic domain. It is never derived from
  or used as an identity, prekey, X3DH or ratchet key.
- **Key storage is the provider's responsibility, never the database's.** A
  key stored next to the database protects nothing.
- `StaticStorageKeyProvider(current, others…)` wraps keys the application
  already holds (for example loaded from its own secret store) and is used by
  tests. It keeps keys in memory and is not secure key storage.
- Platform providers (milestone 10): `AndroidStorageKeyProvider` (random
  storage key wrapped by an Android Keystore key) and
  `AppleStorageKeyProvider` (key in the Keychain; its data protection
  keychain default is tested in a signed host application), see
  [storage-key-providers.md](storage-key-providers.md). Other platforms
  (JVM/desktop/server: an application or OS secret store; JS/Wasm: a
  non-extractable WebCrypto key or an application secret) still need an
  application provider. A plain file next to the database is not key
  storage.
- There is no plaintext mode and no API to delete the storage key. Losing
  the key makes identity, sessions, prekeys and pending messages
  permanently unreadable; a future reset needs deliberate semantics.

## Opening storage

`SqlDelightClientStorage.open(driver, keyProvider)` reads the
`storage_encryption` row. The row is authoritative; storage never guesses
whether bytes are plaintext by trying to decrypt them.

| `format` | `key_id` | What `open` does |
|---|---|---|
| 1 | set | `keyProvider.key(key_id)`; `null` or a throw → `KeyUnavailable`. Opens the key check record; the wrong key fails here with `AuthenticationFailed`, before anything is read. Never creates a key. During a storage key rotation the retiring key is required too ([storage-key-rotation.md](storage-key-rotation.md)). |
| 1 | NULL | A new database (created with format 1). `loadOrCreateKey()`, then binds the key ID and a key check in one transaction. If sensitive rows exist without a bound key, the database was tampered with → `KeyUnavailable`, nothing is bound. |
| 0 | NULL | A database upgraded from schema version 5 or older: still milestone 8 plaintext. `loadOrCreateKey()`, then the legacy migration (below). |
| other | | `UnsupportedFormat`. |

The provider is always called outside database transactions. Provider
exceptions are wrapped in `KeyUnavailable` (the provider's exception is the
cause). No path creates a replacement key for existing encrypted state, and
no path falls back to plaintext.

A record that fails later (tampering after open) throws from the store call.
`IdentityStore.store` checks for an existing row without opening it, so an
unreadable identity is never "absent" and never replaced;
`SecureMessageClient.initialize()` fails. An unreadable session makes `send`
and `decrypt` fail: no new X3DH session replaces it and nothing is handed to
the transport. An unreadable pending message makes `retryPendingMessages`
and `pendingMessages` fail without a hand-off. An unreadable signed prekey
means no initiation is accepted with it.

## Migration from milestone 8

1. Opening the driver with `SqlDelightClientStorage.Schema` runs `5.sqm`
   (schema 5 → 6). It only creates `storage_encryption` with `format = 0`;
   SQL cannot encrypt, and no key is available at that point. Nothing else is
   read or changed.
2. `SqlDelightClientStorage.open` sees `format = 0` and gets the key with
   `loadOrCreateKey()`. If that fails the database is left exactly as it was.
3. In **one SQLite transaction** (`LegacyPlaintextMigration`), each sensitive
   table (`local_identity`, `signed_pre_key`, `one_time_pre_key`, `session`,
   `pending_outbound_message`) is rebuilt as SQLite documents for schema
   changes: create `<table>_m9` with the final columns, read the plaintext
   rows, seal and insert them, drop the old table, rename the new one. IDs,
   addresses, timestamps and pending sequence numbers are copied unchanged;
   the `sqlite_sequence` high-water mark of pending messages is restored, so
   sequence numbers are never reused. During the signed prekey rebuild
   `pre_key_state.current_signed_pre_key_id` is detached and restored, so
   the migration also works with foreign keys enforced.
4. In the same transaction: `format = 1`, the key ID and the key check.

Any failure rolls the whole transaction back: the marker stays 0, every
legacy row and the schema are byte-for-byte unchanged, no `_m9` table
remains, and the next `open` runs the migration again. There is never a
mixed state. Tests inject a failure at every single seal of the migration.

After migration the schema equals a new database's (tested). Identities,
prekeys (with lifecycle timestamps and high-water marks), sessions, pins,
retired initiations, pending messages and processed IDs are kept; an
existing ratchet session continues without a new X3DH, and a pending
milestone 8 message is resent with its logical ID and acknowledged normally.
Older databases (schema 1 to 4) run the `.sqm` chain and then this
migration.

A new database never holds plaintext: it is created with `format = 1`, and
every sensitive value is sealed before it is written.

### Forensic limitation

Migration re-encrypts the **active** records. It does not erase plaintext
that milestone 8 (or earlier) wrote: SQLite free pages, the WAL or rollback
journal, filesystem snapshots, backups and copies of the old file can still
contain old private keys, session states and pending messages. Milestone 9
does not run `VACUUM`, `secure_delete` or file wiping. An application that
needs that must take its own measures (for example `PRAGMA secure_delete`
plus `VACUUM` after the migration, and handling of backups), and even then
flash storage may keep old blocks.

## Key IDs and rotation

Every record carries the ID of the key that sealed it, and the database binds
one current key ID. Milestone 11 adds explicit storage key rotation on top of
this format, without changing it: a new key becomes current, records of the
previous key are re-sealed in resumable batches (each opened with the key its
header names, re-sealed with the same associated data and a fresh nonce), and
the previous key is retired after a scan proves no record uses it. See
[storage-key-rotation.md](storage-key-rotation.md); the rotation state machine
is in `storage:rotation:core`, which uses this module's key types and
`StorageKeyProvider` but none of its record format. Records of a key the
storage does not hold still fail with `KeyUnavailable`; no key is ever tried
at random. There is no background re-encryption.

## Memory handling

Key bytes and temporary plaintext buffers (encoded key records, decrypted
key records, the key copy passed to the AEAD) are overwritten after use.
This is **best effort**: the JVM, Kotlin/Native and JS runtimes, the
cryptography provider and the returned `LocalIdentity`/`SecureSession`
objects keep copies that are not wiped. The storage keeps its key in memory
while it is open.

## Transactions

Sealing and opening are CPU work inside the storage transaction; no network
or key-provider I/O happens there. The JDK and native providers compute
synchronously, so the transaction does not change threads. Atomicity is
unchanged: a failing encryption throws inside the transaction and rolls it
back (tested for identity, signed prekey, one-time prekey, session and
pending frame), so no partial or plaintext row is written and `send` hands
nothing to the transport.

## Not covered

- Platform key providers other than Android Keystore and Apple Keychain
  (milestone 10, [storage-key-providers.md](storage-key-providers.md)).
- Automatic or scheduled storage key rotation (rotation is explicit, see
  [storage-key-rotation.md](storage-key-rotation.md)).
- Rollback protection, integrity of plaintext metadata, hiding metadata.
- Secure erasure of pre-milestone-9 plaintext.
- SQLDelight tests on JS/Wasm (no web worker in the test runner).
