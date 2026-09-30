# KSecureMessage server authentication

Milestone 12, extended by S1 (docs/security-review-remediation.md).
Explains how a device proves to the KSecureMessage server that
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

Since S1 (docs/security-review-remediation.md) two more guarantees hold:

- **A device becomes one of a user's devices only with the host
  application's authorization** ([Registration authorization](#bootstrap-registration-authorization)).
  Every other device-scoped authority (device recovery, the offline recovery
  key, its reset) rests on this membership.
- **An envelope is queued only if its sender is the device that signed the
  submission** ([Message submission](#message-submission)).

KSecureMessage does **not** establish:

- human identity, accounts, phone number or email ownership: the host
  application decides who may register which `DeviceAddress`;
- account recovery (device recovery through another device of the same
  user was added in M14, docs/device-recovery.md);
- trust between messaging peers: TOFU pins ([identity-trust.md](identity-trust.md))
  and safety numbers are unchanged and independent of this;
- hiding metadata from the server (no sealed sender): the server sees who
  sends to whom.

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

## Bootstrap: registration authorization

The server binds `DeviceAddress → device authentication public key`:

| Case | Result |
|---|---|
| address unregistered, host authorizes | the key is registered (`201 Created`) |
| address unregistered, host denies | `DeviceRegistrationException.NotAuthorized` (`403 registration_not_authorized`); nothing is registered |
| same address, same key | idempotent success (`204 No Content`); the host is not asked |
| same address, other key | `DeviceRegistrationException.Conflict` (`409`); registration never replaces the registered key, and the host is not asked |

Only device recovery (M14, docs/device-recovery.md), authorized by another
registered device of the same user, routine rotation (M16,
docs/device-authentication-rotation.md), authorized by the registered key
itself, and last-device recovery (M18) replace a registered key; all are
proven by the new key. The registration authorizer can never replace a key.

### Registration authorization (S1, findings F1/F2)

Until S1 registration was trust on first registration: whoever registered a
free address first owned it. A stranger could register `alice/evil` and then
act as one of Alice's devices: authorize a device recovery of Alice's phone,
provision Alice's offline recovery key, manage its reset.

Since S1 every first registration of an address, **including the first
device of a user**, needs both:

1. proof of possession of the device authentication key (the signed request
   below), and
2. the host application's decision, made with the host's own authentication
   of the request: `DeviceRegistrationAuthorizer<C>` (`server:core`), a
   required constructor parameter of `SecureMessageServer<C>(storage, clock,
   deviceRegistrationAuthorizer, recoveryKeyResetPolicy)`. There is no
   default and no allow-all class in production code.

**Host context (S1.1, finding N1).** `C` is the host's request
authentication context: the account principal its login established, a
session, an OAuth subject, an enrollment grant. KSecureMessage does not
define or interpret it. The Ktor adapter takes a required
`DeviceRegistrationContextExtractor<C>`:

```kotlin
fun <C : Any> Route.kSecureMessageRoutes(
    server: SecureMessageServer<C>,
    registrationContext: DeviceRegistrationContextExtractor<C>, // suspend (ApplicationCall) -> C?
)
```

The registration route calls the extractor, then
`SecureMessageServer.registerDevice(context, registration, body,
authentication)`. `server:core` never sees Ktor types. The context is
request-scoped: never logged, serialized, stored, returned in a response or
put into a signed or hashed input.

The authorizer gets the context and a `DeviceRegistrationAuthorizationRequest`:
the address and the proposed public key (a copy). It returns `Authorized` or
`Denied`; a denial carries no reason, so nothing host-specific reaches HTTP.
The request deliberately carries **no view of KSecureMessage's
registrations** (S1.1, finding N2): S1 passed a `DeviceRegistrationUserState`
("the user has no registered devices"), read outside the atomic
registration write, so two racing first registrations could both be told
"first device". That type and `DeviceRegistrationRepository.hasRegisteredDevices`
are removed. "No device yet" is not ownership; the decision rests on the
principal and the host's own account and device records. The only storage
precondition, "this address is not registered", is enforced by the atomic
`register` (a concurrent winner gives `204` for the same key, `409` for
another).

A typical host:

```kotlin
data class AccountPrincipal(val userId: UserId) // from the host's own login
val server = SecureMessageServer(storage, Clock.System, DeviceRegistrationAuthorizer<AccountPrincipal> { principal, request ->
    if (request.address.userId == principal.userId && accounts.mayAddDevice(principal, request.address)) Authorized else Denied
})
routing {
    kSecureMessageRoutes(server) { call -> call.principal<UserIdPrincipal>()?.let { AccountPrincipal(UserId(it.name)) } }
}
```

| Case | Result |
|---|---|
| extractor returns `null` (no valid host authentication) | `403 registration_not_authorized`, authorizer not called, nothing stored |
| authorizer `Denied` (for example Mallory's principal for `alice/…`) | `403 registration_not_authorized`, nothing stored |
| extractor or authorizer throws | `500 internal_error`; logged as `Registration authorization failed (<exception class>)` only, never the message, stack, cause or context; nothing stored |
| same key as registered | `204`, no host decision (lost-response retries and the recovery/rotation probes need no context) |
| other key for a registered address | `409 device_registration_conflict`, no host decision |

Order in `SecureMessageServer.registerDevice`: key size → authentication
(signature with the key in the body, window, nonce claim) → existing
registration (same key: `false`/`204`; other key: conflict) → context
present → host authorization (outside every storage transaction) → atomic
`register`. Nothing is stored before the host authorized; a denied request
consumes only its own nonce.

The flows that treat "a registered device of the same user" as an authority
(M14 device recovery, M18 recovery key registration, M19 rotation and
revocation, M23 reset request, status and cancellation) are unchanged; their
authority is exactly the host-authorized membership. Registrations stored
before S1 were never host-authorized: see
[operating-the-server.md](operating-the-server.md#registrations-from-before-s1).

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
- **Retention** ([Nonce lifetime](#nonce-lifetime)): an entry is kept as
  long as any request carrying it could still pass the window, and pruned
  only after that, in the same atomic step as a claim (the same lock hold in
  the in-memory repository, the same SQLite transaction in
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
- **Clock**: the prune watermark below never moves back. After the server
  clock jumped back, requests with a timestamp before the watermark are
  refused as replays until the clock has caught up; they are never accepted
  twice.

### Nonce lifetime

S1, finding F8. The window accepts `serverNow − W ≤ ts ≤ serverNow + W`
(`W` = 5 minutes, bounds inclusive). A request with timestamp `ts` passes
the window at every server time `t` with `ts − W ≤ t ≤ ts + W`, so its nonce
must stay claimed at least until `t = ts + W`, and may be pruned only once
`ts < t − W`.

Before S1 every claim pruned `ts < now − W` with its **own** `now`. Freshness
and claim read the clock at different times, so a request checked at
`ts + W` (still fresh) could claim after another request checked at
`ts + W + 1 ms` had already pruned the original nonce: one replay got
through.

Since S1 `AuthenticationNonceRepository.claim(address, nonce, ts, pruneBefore)`
keeps a **monotonic prune watermark** `P` = the largest `pruneBefore` any
claim applied, and in one atomic step:

1. `P := max(P, pruneBefore)`;
2. refuses the claim if `ts < P` (the nonce may already be pruned);
3. prunes every entry with timestamp `< P`;
4. records the nonce, or refuses it if already recorded.

Invariant: every entry with timestamp `≥ P` is retained, and every claim
with timestamp `< P` is refused. A replay of `(nonce, ts)` either finds the
entry (`ts ≥ P`) or is refused by step 2 (`ts < P`), whatever the
interleaving. A legitimate request is refused by step 2 only if another
request already moved `P` past its timestamp, that is, when it is at most
the difference of the two callers' clock reads away from leaving its window.
The server schema v8 (`7.sqm`) stores `P` in `authentication_nonce_watermark`
(docs/server-storage.md). Device recovery, routine rotation and recovery key
transitions claim through the same step.

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
| `PUT /v1/devices/{u}/{d}/registration` `{"publicKey": "<canonical b64, 32 bytes>"}` | signed with the key in the body, plus the host's `DeviceRegistrationAuthorizer` (S1) | `201` first, `204` identical | `400 invalid_registration`, `401`, `403 registration_not_authorized`, `409 device_registration_conflict`, `500 internal_error` (authorizer failure) |
| `PUT /v1/devices/{u}/{d}/prekeys` | registered device | `204` | `401` first; then `400 invalid_publication`, `409 *_conflict` |
| `GET /v1/devices/{u}/{d}/prekey-bundle` | public | `200` | `404 device_not_found` |
| `POST /v1/messages` (signed since S1) | the envelope's sender device (`ProtectedEndpoint.SEND_MESSAGE`, `X-KSecureMessage-Device` header, signed body) | `202` | `401` first; then `400 invalid_envelope`, `403 sender_mismatch` |
| `GET /v1/devices/{u}/{d}/messages` | registered device | `200` | `401` |
| `PUT /v1/devices/{u}/{d}/registration/recovery` (M14) | authorizer signature + proof of possession in the body (docs/device-recovery.md) | `204` | `400 invalid_recovery`, `401`, `403`, `404`, `409 recovery_conflict`, `409 device_auth_epoch_exhausted` |
| `GET /v1/devices/{u}/{d}/registration` (M16, extended M17) | registered device (`ProtectedEndpoint.READ_REGISTRATION`, empty body) | `200 {"authEpoch":N,"authKeyInstalledAt":T}` (T: server time the registered key was installed at, epoch ms; docs/device-authentication-rotation.md) | `401` |
| `PUT /v1/devices/{u}/{d}/registration/rotation` (M16) | current-key authorization + proof of possession in the body, no headers (docs/device-authentication-rotation.md) | `204` | `400 invalid_device_auth_rotation`, `401`, `404`, `409 device_auth_rotation_conflict`, `409 device_auth_epoch_exhausted` |
| `PUT /v1/devices/{u}/{d}/last-device-recovery/key` (M18) | registered device (`ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY`, signed body) plus the recovery key's proof of possession in the body (docs/last-device-recovery.md) | `201` first, `204` identical | `401` first; then `400 invalid_last_device_recovery_key`, `409 last_device_recovery_key_conflict` |
| `POST /v1/devices/{u}/{d}/last-device-recovery/challenge` (M18) | public | `200` challenge | `404 last_device_recovery_not_configured`, `404 last_device_recovery_target_not_registered` |
| `PUT /v1/devices/{u}/{d}/last-device-recovery` (M18) | offline recovery key signature + proof of possession over a server-issued challenge in the body, no headers | `204` | `400 invalid_last_device_recovery`, `401 last_device_recovery_{challenge_invalid,expired,proof_invalid}`, `404`, `409 last_device_recovery_conflict`, `409 device_auth_epoch_exhausted` |
| `GET /v1/devices/{u}/{d}/last-device-recovery/key` (M19) | registered device (`ProtectedEndpoint.READ_LAST_DEVICE_RECOVERY_KEY`, empty body) | `200` recovery key status of the device's user (docs/recovery-key-lifecycle.md) | `401` |
| `PUT /v1/devices/{u}/{d}/last-device-recovery/key/rotation` (M19) | registered device (`ProtectedEndpoint.ROTATE_LAST_DEVICE_RECOVERY_KEY`, signed body) **and** the current recovery key's signature + the new key's proof of possession in the body | `204` | `401` first; then `400 invalid_recovery_key_rotation`, `401 recovery_key_rotation_{expired,invalid_proof,replay}`, `404 recovery_key_not_configured`, `409 recovery_key_rotation_conflict`, `409 recovery_key_epoch_exhausted` |
| `PUT /v1/devices/{u}/{d}/last-device-recovery/key/revocation` (M19) | registered device (`ProtectedEndpoint.REVOKE_LAST_DEVICE_RECOVERY_KEY`, signed body) **and** the current recovery key's signature in the body | `204` | `401` first; then `400 invalid_recovery_key_revocation`, `401 recovery_key_revocation_{expired,invalid_proof,replay}`, `404 recovery_key_not_configured`, `409 recovery_key_revocation_conflict`, `409 recovery_key_epoch_exhausted` |

`401` bodies: `missing_authentication`, `invalid_authentication`,
`expired_authentication`, `authentication_replay`, `device_not_registered`.
Every exception is mapped explicitly; none falls through to `500`.
`KtorSecureMessageTransport` maps them to
`SecureMessageTransportException.AuthenticationFailed(failure)` (`MISSING`,
`INVALID`, `EXPIRED`, `REPLAY`, `NOT_REGISTERED`),
`DeviceRegistrationConflict`, `DeviceRegistrationNotAuthorized` (S1),
`RegistrationRejected` and, for submission, `EnvelopeSenderRejected` (S1).

The registration status response (M17) is trusted because the request is
ServerAuth-signed with the registered key and the server is the authority
for its registration metadata. ServerAuth authenticates requests, not
responses; there are no signed responses. The server records a key's
installation time with its own clock at first registration, recovery and
rotation; a repeated registration of the registered key (idempotent, `204`)
never changes it.

### Compatibility boundary

This is an intentional, breaking change of HTTP API v1 behavior: prekey
publication and mailbox drain now require the headers above, and a device
must register first. Paths stay `/v1`; clients from before M12 get `401`.
Unchanged: the ciphertext wire format v1, `SecurePayload` v1, X3DH/Ratchet
info strings, `SessionInitiationId`, TOFU, collision and replay handling of
sessions, the signed prekey lifecycle, message reliability, per-pair FIFO,
the KSMR record format v1 and its associated data, storage key provider
formats and the storage key rotation state machine.

S1 is a second intentional change of HTTP API v1 behavior (not of the
signed input format v1, which is unchanged): registration needs the host's
authorization (`403 registration_not_authorized`), and `POST /v1/messages`
needs ServerAuth by the sender plus the `X-KSecureMessage-Device` header
(`401`/`403 sender_mismatch`). Clients from before S1 can no longer send;
upgrade servers and clients together (docs/security-review-remediation.md).

## Message submission

S1, finding F4. Before S1 `POST /v1/messages` was public and the server
queued any envelope, so a client could name any sender. The recipient takes
the sender address of a first contact from the envelope, so a malicious
client could claim `alice/phone` with its own identity key and have the
recipient pin that key for Alice.

Since S1 the submission is a ServerAuth v1 request of the sending device:

- the path stays `/v1/messages`; the signed canonical path is exactly
  `/v1/messages` (`ServerApiPaths.SUBMIT_MESSAGE`, `ProtectedEndpoint.SEND_MESSAGE`);
- the header `X-KSecureMessage-Device` names the signing device as
  `{user}/{device}`, each component percent-encoded like a path segment
  (`ServerApiPaths.encodeDevice`/`decodeDevice`; only the canonical encoding
  is accepted);
- order: device header → authentication with that device's **registered**
  key (window, signature over the exact body, nonce) → parse the body →
  `envelope.sender` must equal the authenticated device, else
  `403 sender_mismatch` and nothing is queued → enqueue;
- a missing header or missing authentication headers are `401
  missing_authentication`; a malformed or repeated device header is `401
  invalid_authentication`.

The client signs every submission, including acknowledgements and retries
(`SecureMessageTransport.send(envelope, signer)`); the key is loaded in its
own short transaction and the request is sent outside any storage
transaction. The server now vouches for the sender address; the session
initiation v2 transcript additionally binds both addresses cryptographically,
which catches a relay that rewrites them (docs/session-lifecycle.md). A
device without its device authentication key cannot submit; its messages
stay pending.

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

- Registration proves possession of the device key; account ownership is
  whatever the host's `DeviceRegistrationAuthorizer` checks with the
  principal its extractor supplies. A host that authorizes carelessly (an
  extractor that returns a shared context for unauthenticated calls, an
  authorizer that ignores the principal) reopens F1/F2.
- Registrations stored before S1 were never host-authorized and keep their
  same-user authority until the operator audits them; removing a malicious
  one is not enough, because an offline recovery key it registered outlives
  it: the offline cleanup also revokes the affected users' recovery keys
  ([operating-the-server.md](operating-the-server.md#pre-s1-cleanup), S1.2,
  finding N5).
- Auth-key recovery through another registered device of the same user
  (M14, docs/device-recovery.md) or, for the last device, with the user's
  offline recovery key (M18, docs/last-device-recovery.md); routine rotation
  needs the current key and is explicit (M16/M17,
  docs/device-authentication-rotation.md); no reset, deletion or multiple
  active keys per device. ServerAuth v1 is unchanged by M18 and M19: the
  recovery key registration, status, rotation and revocation endpoints are
  ordinary signed requests. Rotation and revocation additionally need the
  current recovery key's signature in the body (two authorities,
  docs/recovery-key-lifecycle.md); their statement nonce is claimed in the
  same per-device nonce namespace, atomically with the recovery key
  transition. `AuthenticatedDevice` also carries (internally) the
  registration its request was verified with, so a recovery key transition
  commits only while that registration is still current.
- Persistent server storage (`storage:server:sqldelight`, M13) is SQLite
  only, single node, unencrypted (docs/server-storage.md).
- The server sees sender and recipient metadata, and since S1 it is also the
  authority for the sender address of a submission (no sealed sender). A
  malicious server could still fabricate a first contact with a key of its
  choice under any address, as it could hand out a bundle with a key of its
  choice: first contact trusts the server (TOFU); safety numbers detect it.
- Replay protection is at most once per signed request, not exactly-once
  application side effects.
