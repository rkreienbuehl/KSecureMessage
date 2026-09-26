# KSecureMessage server authentication

Milestone 12. Explains how a device proves to the KSecureMessage server that
a request comes from the device registered for a `DeviceAddress`. Without
this, anyone who knows an address could replace its published prekeys or
drain its mailbox.

Code:

- Canonical request format, signing, verification and paths:
  `core/protocol/.../protocol/DeviceAuthentication.kt`
  (`ServerRequestAuthentication`, `ServerApiPaths`, `RequestNonce`,
  `DeviceAuthenticationKeyPair`)
- Registration model: `core/model/.../model/DeviceRegistration.kt`
- Server contracts: `storage/core/.../storage/ServerStorage.kt`
  (`DeviceRegistrationRepository`, `AuthenticationNonceRepository`)
- Server logic: `server/core/.../server/DeviceAuthenticator.kt`,
  `SecureMessageServer`
- HTTP: `server/ktor/.../KSecureMessageRoutes.kt`,
  `client/ktor/.../KtorSecureMessageTransport.kt`
- Client: `SecureMessageClient.registerDevice()`, `publishPreKeys()`,
  `receive()`, and the local key lifecycle in `PreKeyManager`

## What this is and what it is not

M12 gives the server one guarantee: **the server recognizes a previously
registered device authentication key.** After an address is registered, only
the holder of that key can publish prekeys for it or drain its mailbox.

M12 does **not** establish:

- human identity, accounts, phone number or email ownership;
- account recovery (device recovery through another device of the same
  user was added in M14, docs/device-recovery.md);
- who registered an address first (see [Bootstrap](#bootstrap-trust-on-first-registration));
- trust between messaging peers: TOFU pins ([identity-trust.md](identity-trust.md))
  and future safety numbers are unchanged and independent of this;
- sender authentication for `POST /v1/messages`, or hiding metadata from the
  server (no sealed sender).

## The device authentication key

Each device has a dedicated **Ed25519** signing key pair, separate from the
messaging identity key:

| | Messaging identity key | Device authentication key |
|---|---|---|
| Used for | X3DH, Double Ratchet associated data, signed prekey signatures, TOFU pins | signing requests to the KSecureMessage server |
| Seen by | peers (in bundles and `PreKeyMessage`s), the server (published) | the server (public half, registered once) |
| Encoding | 64-byte unified Kodium key (X25519 ‖ Ed25519) | 32-byte Ed25519 public key; 32-byte seed as private key |
| Stored | `ClientStorage.identity` | `ClientStorage.deviceAuthentication` |

The two keys are never mixed: a compromise or a change of one does not
affect the other's security domain, and each can get its own lifecycle
later (auth-key rotation is not part of M12).

The key is created by `ProtocolEngine.createDeviceAuthenticationKey()`
(Kodium's TweetNaCl Ed25519; Kodium types stay inside `core:protocol`). The
private key never leaves the device and never appears in `toString()`,
exceptions or logs.

### Local lifecycle

`SecureMessageClient.initialize()` stays local-only. In its one transaction
it now also makes sure the key exists:

| Local state | `initialize()` does |
|---|---|
| no identity (new installation) | creates identity **and** device authentication key together |
| no identity, but an auth key is stored | `InconsistentStorage`: nothing is created |
| identity and key | nothing (a record that fails to open throws `StorageEncryptionException`) |
| identity, no key, storage says `awaitsUpgradeKey()` | creates the key once (installation from before M12) |
| identity, no key, `awaitsUpgradeKey()` is `false` | `InconsistentStorage`: the key was **lost**; no new key is created |

A lost key is never replaced silently: `initialize()` never creates a new
key for it. Since M14 the explicit way back is device recovery
(docs/device-recovery.md): another registered device of the same user
authorizes a replacement key, which the device keeps as a pending recovery
key until the server accepted it. A user without another registered device
still has no way back and needs a new `DeviceAddress`. A device that still
holds its key can replace it itself with a routine rotation (M16,
docs/device-authentication-rotation.md).

`DeviceAuthenticationKeyStore.store` refuses a second key, also an identical
one (existence check only, so a damaged record never looks absent).

### Telling "before M12" apart from "lost"

SQLDelight schema version 8 (`7.sqm`) adds two tables:

- `device_authentication_key`: one row, `sealed_key_pair` (record type 7,
  [storage-encryption.md](storage-encryption.md)).
- `device_authentication_state`: one row, `awaits_upgrade_key`.

The migration sets `awaits_upgrade_key = 1` only if the database already had a
local identity, and creates no key material (SQL cannot, and must not). A new
database starts with `0`. Storing the key sets it to `0` in the same
transaction, for good. So:

- a milestone 11 installation gets exactly one key on its next `initialize()`;
- a database that had a key and lost it (row deleted) has `0` and fails
  closed;
- a damaged record fails to open and fails closed.

Record-level encryption does not protect rows against an attacker with write
access to the database file (see [storage-encryption.md](storage-encryption.md)):
such an attacker could set the flag and delete the key. The distinction
protects against accidental loss and bugs, not against that attacker.
`InMemoryClientStorage` never holds pre-M12 data; its `awaitsUpgradeKey()` is
always `false`.

## Bootstrap: trust on first registration

The server binds `DeviceAddress → device authentication public key`:

| Case | Result |
|---|---|
| address unregistered | the key is registered (`201 Created`) |
| same address, same key | idempotent success (`204 No Content`) |
| same address, other key | `DeviceRegistrationException.Conflict` (`409`); registration never replaces the registered key |

Only device recovery (M14, docs/device-recovery.md), authorized by another
registered device of the same user, and routine rotation (M16,
docs/device-authentication-rotation.md), authorized by the registered key
itself, replace a registered key; both are proven by the new key.
Registration semantics are unchanged by them.

**First registration is trust-on-first-registration at the server layer. M12
prevents later unauthorized replacement but does not authenticate ownership
of an unregistered `DeviceAddress`.** Whoever registers a free address first
owns it on this server.

Registration is explicit: `SecureMessageClient.registerDevice()`. Neither
`initialize()` nor any protected request registers a key implicitly, so the
state transition is auditable: unregistered → registration → registered →
authenticated requests.

The registration request is signed like every other request (format below),
but it is the **only** request verified with a key from its own body: the key
it registers. That is a proof of possession: the registrant holds the private
key, and a malformed 32-byte value can never become a registration, because
it cannot verify a signature (Kodium has no separate point validation). Keys
of another size are rejected (`400`) before anything else. Every other
authenticated endpoint verifies with the key the server already has.

`DeviceRegistrationRepository.register` is atomic: of concurrent registrations
of one address with different keys, exactly one wins; identical ones converge.

## Signed request format v1 (frozen)

The signature covers an explicit binary input, not JSON:

```
u32 length | "KSecureMessage-ServerAuth-v1"          (UTF-8, 28 bytes)
u32 length | userId                                   (UTF-8)
u32 length | deviceId                                 (UTF-8)
u32 length | HTTP method                              (ASCII, upper case, [A-Z]+)
u32 length | canonical path                           (UTF-8, see below)
SHA-256(exact HTTP request body bytes)                (32 bytes)
timestamp                                             (i64, epoch milliseconds)
nonce                                                 (16 bytes)
```

All integers are big-endian. The signature is Ed25519 over these bytes (64
bytes). The domain string versions the format: signed prekey signatures
(64-byte public keys signed by the identity key), and anything else signed in
another context, never verify as a request signature. A new format gets a new
domain string.

- **Body**: SHA-256 over the exact bytes sent. The client encodes the JSON
  itself, signs those bytes and sends them unchanged; the server hashes the
  raw bytes it received and parses JSON only after verification. JSON field
  order, serializer details, whitespace, locale and map order play no part. A
  request without body hashes the empty array
  (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
- **Canonical path**: `/v1/devices/{user}/{device}/{endpoint}` where `user`
  and `device` are percent-encoded per RFC 3986: `A–Z a–z 0–9 - . _ ~` stay,
  every other UTF-8 byte becomes `%XX` (upper-case hex). `ServerApiPaths`
  builds it; the client uses it for its URLs, and the server rebuilds it from
  the decoded route parameters. It never signs or verifies a raw request URI,
  so proxies and path prefixes do not matter.
- **Address**: bound twice, as its own fields and inside the path.
- **Timestamp**: the client's clock (the injected `Clock`), whole milliseconds.
- **Nonce**: 16 bytes from the platform CSPRNG (`Uuid.random()`, 122 random
  bits), new for every signature, including retries.

`ServerRequestAuthenticationTest` freezes vectors computed independently
(Python `hashlib`, `urllib.parse.quote`, `cryptography` Ed25519) from a fixed
seed `40 41 … 5f`: an empty-body GET, a prekey PUT with a JSON body, another
nonce, timestamp 0, and a path with `ä`, space and `/`.

## HTTP representation

Four headers, all required together:

| Header | Value |
|---|---|
| `X-KSecureMessage-Auth-Version` | `1` |
| `X-KSecureMessage-Timestamp` | epoch milliseconds, decimal ASCII digits only (1–18), no sign |
| `X-KSecureMessage-Nonce` | 16 bytes, Base64 (RFC 4648 standard alphabet, with padding, canonical) |
| `X-KSecureMessage-Signature` | 64 bytes, same Base64 rules |

No header carries a public key; the server uses the registered one. None of
the headers present → `missing_authentication`. Some present, repeated,
unknown version, or malformed → `invalid_authentication`.

## Server verification

`DeviceAuthenticator` checks, in this order:

1. authentication present, else `MissingAuthentication`;
2. the address has a registered key, else `DeviceNotRegistered` (registration
   uses the key in its body instead);
3. `now − 5 min ≤ timestamp ≤ now + 5 min`, both bounds inclusive, `now` =
   the server's injected `Clock` truncated to milliseconds, else
   `ExpiredAuthentication`;
4. the signature over the canonical input (method and path fixed by the
   endpoint, the exact body) verifies with that key, else
   `InvalidAuthentication`;
5. the nonce is claimed for the address, else `AuthenticationReplay`.

Only then does the protected operation run. The nonce is claimed last, so a
request that fails steps 1–4 consumes nothing.

### Replay protection

- **Scope**: per `DeviceAddress`. The same nonce of two devices is independent.
- **Claim**: `AuthenticationNonceRepository.claim` records the nonce and
  returns whether it was new, atomically. Of concurrent identical requests
  exactly one is accepted, so the protected operation (a drain, a publication)
  runs at most once per signed request.
- **Final**: a claimed nonce stays claimed even if the operation then fails
  (for example a publication conflict). Clients sign every attempt anew.
- **Retention**: an entry is needed only while its timestamp is inside the
  window; afterwards step 3 rejects the request anyway. Every claim first
  removes entries with `timestamp < now − 5 min` (in the same lock hold in the
  in-memory repository, in the same SQLite transaction in
  `storage:server:sqldelight`, see docs/server-storage.md). With persistent
  storage, claimed nonces survive a server restart: a request replayed after
  a restart, while its timestamp is still in the window, is rejected.
- **Device recovery** (M14) claims its nonce under the target's address in
  the same table, inside the recovery transaction. A recovery does not clear
  the target's nonces: old-key requests fail verification against the new
  key anyway, and keeping an earlier recovery's nonce claimed is what rejects
  its replay (docs/device-recovery.md).
- **Routine rotation** (M16) does the same with its statement nonce, under
  the device's own address: it shares the namespace with the device's
  ServerAuth nonces (a nonce used for an ordinary request is a replay as a
  rotation nonce), is claimed inside the rotation's compare-and-set
  transaction, and a rotation clears no nonces
  (docs/device-authentication-rotation.md).
- **Clock**: the window assumes the server clock does not jump back by more
  than the window; after such a jump a pruned nonce could be accepted again
  until the clock catches up.

### Atomicity and ordering

- Registration: one atomic `register` (compare-and-insert).
- Replay: one atomic `claim` per request, before the operation. There is no
  transaction spanning the claim and the operation: M12 guarantees *at most
  one execution per nonce*, not exactly-once. The SQLDelight adapter keeps
  this boundary: the claim commits in its own transaction, the publication or
  drain runs in a separate one, so a failed operation never un-claims the
  nonce.
- Protected operations take an `AuthenticatedDevice`, which only
  `DeviceAuthenticator` can create (internal constructor) and which names the
  endpoint and address it was issued for. `publishPreKeys` and `receive`
  refuse a mismatch. Routes authenticate the raw body before they parse it.
  An unauthenticated request never publishes, drains, consumes a one-time
  prekey or claims a nonce.

## Endpoint policy (HTTP API v1)

| Endpoint | Authentication | Success | Errors |
|---|---|---|---|
| `PUT /v1/devices/{u}/{d}/registration` `{"publicKey": "<b64, 32 bytes>"}` | signed with the key in the body | `201` first, `204` identical | `400 invalid_registration`, `401`, `409 device_registration_conflict` |
| `PUT /v1/devices/{u}/{d}/prekeys` | registered device | `204` | `401` first; then `400 invalid_publication`, `409 *_conflict` |
| `GET /v1/devices/{u}/{d}/prekey-bundle` | public | `200` | `404 device_not_found` |
| `POST /v1/messages` | public | `202` | – |
| `GET /v1/devices/{u}/{d}/messages` | registered device | `200` | `401` |
| `PUT /v1/devices/{u}/{d}/registration/recovery` (M14) | authorizer signature + proof of possession in the body (docs/device-recovery.md) | `204` | `400 invalid_recovery`, `401`, `403`, `404`, `409 recovery_conflict`, `409 device_auth_epoch_exhausted` |
| `GET /v1/devices/{u}/{d}/registration` (M16) | registered device (`ProtectedEndpoint.READ_REGISTRATION`, empty body) | `200 {"authEpoch": N}` | `401` |
| `PUT /v1/devices/{u}/{d}/registration/rotation` (M16) | current-key authorization + proof of possession in the body, no headers (docs/device-authentication-rotation.md) | `204` | `400 invalid_device_auth_rotation`, `401`, `404`, `409 device_auth_rotation_conflict`, `409 device_auth_epoch_exhausted` |

`401` bodies: `missing_authentication`, `invalid_authentication`,
`expired_authentication`, `authentication_replay`, `device_not_registered`.
Every exception is mapped explicitly; none falls through to `500`.
`KtorSecureMessageTransport` maps them to
`SecureMessageTransportException.AuthenticationFailed(failure)` (`MISSING`,
`INVALID`, `EXPIRED`, `REPLAY`, `NOT_REGISTERED`),
`DeviceRegistrationConflict` and `RegistrationRejected`.

### Compatibility boundary

This is an intentional, breaking change of HTTP API v1 behavior: prekey
publication and mailbox drain now require the headers above, and a device
must register first. Paths stay `/v1`; clients from before M12 get `401`.
Unchanged: the ciphertext wire format v1, `SecurePayload` v1, X3DH/Ratchet
info strings, `SessionInitiationId`, TOFU, collision and replay handling of
sessions, the signed prekey lifecycle, message reliability, per-pair FIFO,
the KSMR record format v1 and its associated data, storage key provider
formats and the storage key rotation state machine.

## Client usage

```kotlin
client.initialize()      // local only: identity, device auth key, prekeys
client.registerDevice()  // once; safe to repeat
client.publishPreKeys()  // signed automatically
val envelopes = client.receive() // signed drain of this device's mailbox
```

The client loads the key in a short transaction, then signs and sends outside
it (`ServerRequestSigner`, one signature per attempt). The signer refuses
requests for another address. Applications never build signatures.

## Limitations

- First registration is not proof of human or account ownership.
- Auth-key recovery only through another registered device of the same
  user (M14, docs/device-recovery.md); routine rotation needs the current
  key and is explicit, without a policy (M16,
  docs/device-authentication-rotation.md); no reset, deletion or multiple
  active keys per device.
- Persistent server storage (`storage:server:sqldelight`, M13) is SQLite
  only, single node, unencrypted (docs/server-storage.md).
- The server still sees sender and recipient metadata; `POST /v1/messages`
  does not authenticate the envelope sender (no sealed sender).
- Replay protection is at most once per signed request, not exactly-once
  application side effects.
