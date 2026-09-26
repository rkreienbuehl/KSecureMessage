# Identity verification and identity-change acceptance

Milestone 15 adds three things on top of trust on first use
([identity-trust.md](identity-trust.md)):

1. **Safety numbers**: a value two devices derive from their messaging
   identity keys and addresses, for users to compare out of band.
2. **Verification state**: a local record that the user compared the safety
   number of exactly the pinned key.
3. **Explicit acceptance** of a changed remote identity: the application,
   on the user's decision, replaces a pin. The old session is dropped and the
   new key starts unverified.

All of it is client-local. The server does not store, check or see any of
it; the server schema and the HTTP API are unchanged.

Code: `core/protocol/.../protocol/SafetyNumber.kt` (derivation, formats,
types), `RemoteIdentityStore` in `storage/core/.../storage/ClientStorage.kt`
(persistence contract), `client/core/.../client/SecureMessageClient.kt` and
`RemoteIdentityTrust.kt` (workflow).

## Scope: the messaging identity only

Safety numbers, verification and acceptance concern the **messaging identity
key** (the X3DH identity key in bundles and `PreKeyMessage`s). They do not
touch, and are not touched by:

- the device authentication key and its registration, recovery or routine
  rotation ([server-authentication.md](server-authentication.md),
  [device-recovery.md](device-recovery.md),
  [device-authentication-rotation.md](device-authentication-rotation.md));
- the storage encryption key and its rotation;
- signed prekeys, one-time prekeys and ratchet session keys.

A device authentication recovery or routine rotation changes neither side's
safety number nor any verification state (tested in
`DeviceAuthenticationRecoveryTest`, `DeviceAuthenticationRotationTest`,
`DeviceAuthenticationRotationRoutesTest` and
`DeviceAuthenticationRotationStorageTest`).

## Safety number, version 1

Trust is per `DeviceAddress`, so safety numbers are too: Alice's phone and
Bob's laptop have one safety number, Alice's phone and Bob's phone another.
Two devices of one user have separate identities and separate verification
states; nothing is combined per `UserId`.

### Derivation

For each device, the address encoding is

```
u32 length | userId (UTF-8) | u32 length | deviceId (UTF-8)
```

and the device's side is its address encoding followed by its 64-byte public
identity key (X25519 key, then Ed25519 key). The two sides are put in
canonical order: the side whose **address encoding** is smaller,
unsigned-lexicographically (a proper prefix first), comes first. The
fingerprint is

```
SHA-256( u32 length | "KSecureMessage-SafetyNumber-v1" | first side | second side )
```

32 bytes, big-endian integers throughout. Because the order depends only on
the addresses, Alice and Bob derive the same value, and each key stays tied
to its own address (swapping the keys between the addresses gives another
value). Nothing else goes in: no session, prekey, ratchet or server state,
so session setup, replacement and ratchet steps never change it. It changes
when either identity key or either address changes. The two addresses must
differ, and addresses must be valid Unicode (a lone surrogate would encode
like `?`).

The domain `KSecureMessage-SafetyNumber-v1` is used for nothing else.

### Human-readable form

`SafetyNumber.displayString`: 60 decimal digits in 12 groups of 5, separated
by single spaces, for example

```
21181 68061 76315 60300 92879 50157 99880 13601 55948 43789 09305 08968
```

Bytes 0..29 of the fingerprint (240 bits) are split into 12 big-endian
20-bit chunks (two per 5-byte block, read as a 40-bit integer). Each chunk
is reduced modulo 100000 and written with 5 digits, zero-padded. This is
plain 64-bit integer arithmetic, identical on every target, and does not
depend on a locale. Each group carries about 16.6 bits, the whole string
about 199 bits, so an accidental or brute-forced match is not a practical
concern. `SafetyNumber.groups` returns the 12 groups.

### Machine-readable payload

`SafetyNumber.encode()` / `SafetyNumberCodec`, version 1, for a QR code or
another channel the application chooses (the library renders no QR code):

```
version:u8 = 1
| first address encoding | second address encoding
| fingerprint (32)
```

Addresses are in the canonical order, so both devices produce identical
bytes. The payload holds no key material. Decoding is strict: the version,
valid UTF-8, strictly canonical order (so also two different addresses),
exact sizes and no trailing bytes; anything else throws
`IllegalArgumentException`.

`SafetyNumber.compare(payload)` returns

| Result | Meaning |
|---|---|
| `MATCH` | same two devices, same fingerprint |
| `MISMATCH` | same two devices, different fingerprint: one side sees another identity key |
| `DIFFERENT_DEVICES` | the payload is about another pair (wrong contact or wrong device scanned) |

### Frozen vectors

`SafetyNumberTest` (`core:protocol`), computed independently with Python
`hashlib`: Alice phone ↔ Bob phone (fingerprint, display string, payload),
reversed caller order, another device ID, another user ID, one identity bit
flipped, UTF-8 addresses (`jürg/📱` ↔ `zoë/ordinateur-été`, fingerprint,
display and payload), the domain string, and the display edge cases (all
zero, all one, bytes 30–31 ignored). Keys in the vectors are
`key(n)[i] = n + i`. Changing any of them breaks every comparison users
make.

## Client API

| Call | Effect |
|---|---|
| `remoteIdentityTrust(remote)` | `RemoteIdentityTrust(address, identityKey, verification)` or `null` if nothing is pinned |
| `safetyNumber(remote)` | derived from the local identity and the **pinned** key; `RemoteIdentityNotKnown` if nothing is pinned. Never fetches a bundle. |
| `safetyNumber(change)` | the safety number the presented key of a `RemoteIdentityChange` would have, to compare before accepting |
| `compareSafetyNumber(remote, scanned)` | decodes and compares; `InvalidSafetyNumberPayload` for bytes that do not decode. Never changes trust. |
| `markRemoteIdentityVerified(safetyNumber)` | the pin in that safety number becomes `VERIFIED`, only if the pin is still the one it was derived from (`RemoteIdentityConflict` otherwise) |
| `markRemoteIdentityUnverified(remote)` | back to `UNVERIFIED`; the pin stays |
| `acceptRemoteIdentityChange(change)` | see below |

`PublicIdentityKey` (64 bytes, copied in and out), `SafetyFingerprint`,
`SafetyNumber`, `SafetyNumberPayload`, `SafetyNumberComparison` and
`VerificationState` live in `core:protocol`; `RemoteIdentityTrust` and
`RemoteIdentityChange` in `client:core`. None of them prints key bytes.

A verification workflow keeps the steps separate:

1. `val number = client.safetyNumber(bob)`; show `number.displayString` or
   `number.encode()` as a QR code.
2. The user compares with Bob's device, visually or by scanning:
   `client.compareSafetyNumber(bob, scanned)`.
3. Only if the user confirms: `client.markRemoteIdentityVerified(number)`.

Decoding or matching a payload never marks anything verified, and a
mismatched payload never changes or accepts anything.

## Verification state

`VerificationState` is `UNVERIFIED` or `VERIFIED`. The pin stays the trust
anchor; verification is an additional, local property of it.

- A first TOFU pin is `UNVERIFIED`.
- `markRemoteIdentityVerified` sets `VERIFIED` for exactly the pinned key.
  At the storage level (`RemoteIdentityStore.setVerification`) the call names
  the key and fails if another one is pinned.
- A new session with the same identity keeps the state.
- An accepted identity change always resets it to `UNVERIFIED`. A
  verification is never carried to another key, even when the user believes
  the change is legitimate.
- Verification is local: Bob verifying Alice changes nothing on Alice's side.

## Identity changes

Normal traffic never accepts a change. A different key in a
`PreKeyMessage`, or in a fetched bundle when there is no session, still
throws `SecureMessageClientException.IdentityChanged` and changes nothing,
as before. The exception now carries a `RemoteIdentityChange` (`change`):
the address, the pinned key and the presented key (`pinnedIdentityKey`,
`presentedIdentityKey`). The message text still has no key material.

The presented key is not authenticated at that point: it is what the
message header or bundle claimed. The user should compare
`safetyNumber(change)` with the other device before accepting.

### Acceptance

`acceptRemoteIdentityChange(change)` runs under the client's send mutex (so
no send, retry or acknowledgement sees a half-done change) and in one
storage transaction:

1. The pin must exist (`RemoteIdentityNotKnown`) and must equal
   `change.previousIdentityKey` (`RemoteIdentityConflict`). This is a
   compare-and-set: of two competing acceptances from the same pin, one
   wins and the other fails; there is no last-write-wins.
2. If there is a session with the device, its initiation is retired with
   the existing milestone 6/7 mechanism (`SessionInitiationStore.retire`,
   with the local signed prekey it was accepted with, for pruning), and the
   session is removed.
3. `RemoteIdentityStore.replace` installs exactly `change.presentedIdentityKey`
   as `UNVERIFIED` (again compare-and-set on the old key).

If any step fails, the transaction rolls back: pin, verification, session
and retired initiations stay as they were (`IdentityChangeAcceptanceTest`).
Other devices' sessions and pins are not touched. No network I/O happens.

The key installed is the one the user saw, never "whatever the network
serves now". If the server swaps the identity again (K3) after the user
confirmed K2, acceptance still installs K2, and K3 fails with a new
`IdentityChanged`.

Walkthrough:

```
Alice has Bob pinned as K1 (maybe VERIFIED) and a session with him
Bob reinstalls: identity K2, new bundle
Bob → Alice: PreKeyMessage with K2        → IdentityChanged(K1 → K2), nothing changes
user compares safetyNumber(change) with Bob and approves
acceptRemoteIdentityChange(change)        → session K1 removed, its initiation retired,
                                            pin K2, UNVERIFIED
Alice decrypts the same envelope again    → new session under K2, ACK to Bob
user verifies again                       → VERIFIED for K2
```

### Old identity traffic

After acceptance, a `PreKeyMessage` with K1 is a changed identity again
(`IdentityChanged`), and K1 ratchet messages have no session or fail to
decrypt on the K2 session without changing it. Even if the user later
accepted K1 again, the old session never comes back: its initiation is
retired, so a replayed `PreKeyMessage` of it fails with
`StaleSessionInitiation`. There is no second replay mechanism.

### Pending and processed messages

Acceptance keeps the pending outbound messages to the device
([message-reliability.md](message-reliability.md)). They were encrypted for
the old session, but they are stored as frames, not as ciphertext: after
acceptance, `retryPendingMessages` encrypts them again on the new session
(fetching a K2 bundle if there is no session yet), with the same logical IDs
and new envelope IDs, and the new device's acknowledgement clears them.
Nothing is dropped silently. Processed inbound IDs are kept too: they are
scoped by sender address and logical ID, and a new identity does not reuse
the old one's random logical IDs.

The envelope that raised `IdentityChanged` changed nothing, so the
application may pass it to `decrypt` again after accepting.

## Storage

`RemoteIdentityStore` (`storage:core`) gains `record` (key + state),
`setVerification(address, identityKey, state)` and
`replace(address, expectedIdentityKey, newIdentityKey)`, both
compare-and-set on the pinned key. `store` still never replaces a pin and
creates new pins `UNVERIFIED`. Contract tests: `ClientStorageContractTest`.

`storage:client:sqldelight` stores the state in
`remote_identity.verification INTEGER NOT NULL DEFAULT 0 CHECK (verification IN (0, 1))`
(0 unverified, 1 verified; an integer leaves room for later states, an
unknown value fails closed and is never read as verified). Schema version
10, migration `9.sqm`: `ALTER TABLE … ADD COLUMN`, so every existing pin
becomes `UNVERIFIED`; no verification is guessed and no other row changes.
Frozen fixture `Version9Schema`. The table stays unsealed, like before:
public keys and the verification flag are not secret (see
[storage-encryption.md](storage-encryption.md)); no storage record format
changes. `storage:client:inmemory` implements the same semantics.

## Compatibility

Unchanged: ciphertext wire format v1, `SecurePayload` v1, ServerAuth v1,
DeviceRecovery v1, X3DH/Ratchet info strings, `SessionInitiationId`, the
milestone 6 collision and replay rules, the signed prekey lifecycle, message
reliability, storage record format v1 and key rotation, server storage and
the HTTP API. The only behavior change is the new explicit APIs; changed
identities still fail until accepted. One small tightening: a bundle whose
identity key does not have 64 bytes now fails with
`ProtocolException.InvalidPreKeyBundle` even when a pin exists (before, a
pinned device got `IdentityChanged`).

## Limitations

- Verification is per device; there is no per-user or cross-device
  verification.
- The value of verification depends on the user actually comparing the
  numbers over a trusted channel. The library only records the decision.
- The presented key in `IdentityChanged` is unauthenticated until a session
  with it works; accepting without comparing trusts the server.
- No messaging identity recovery, reset or backup, and no account or
  last-device recovery. A reinstalled device is a new identity.
- No server attestation of identities and no key transparency.
- No sealed sender; the server sees who talks to whom.
- No UI and no QR rendering.
