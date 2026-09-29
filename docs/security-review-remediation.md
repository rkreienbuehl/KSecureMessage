# Security review remediation (S1)

Re-review packet for the first security review of KSecureMessage (after
milestones 1–25, R1 and R2). The review reported nine findings, F1–F9. S1
fixes their trust roots. Where the vulnerable behavior was part of a format
or an API, S1 versions or breaks it on purpose: security takes precedence
over compatibility with the vulnerable behavior.

**Status of every finding: FIXED — PENDING RE-REVIEW.** Nothing here is
closed until an independent reviewer has checked it. S1 is not an audit.

Path prefixes: `P` = `core/protocol/src/commonMain/kotlin/dev/kreienbuehl/ksecuremessage/protocol`,
`C` = `client/core/src/commonMain/kotlin/dev/kreienbuehl/ksecuremessage/client`,
`S` = `server/core/src/main/kotlin/dev/kreienbuehl/ksecuremessage/server`,
`K` = `server/ktor/src/main/kotlin/dev/kreienbuehl/ksecuremessage/server/ktor`,
`Q` = `storage/client/sqldelight/src/commonMain`,
`V` = `storage/server/sqldelight/src/main`,
`E` = `storage/encryption/src/commonMain/kotlin/dev/kreienbuehl/ksecuremessage/storage/encryption`.

## Summary

| ID | Severity | Root cause | Fix | Status |
|---|---|---|---|---|
| F1/F2 | HIGH | Registration was trust on first registration: anyone could register a device under an existing `UserId` and then act as one of the user's devices | Host-provided `DeviceRegistrationAuthorizer`, required for every first registration, including a user's first device | FIXED — PENDING RE-REVIEW |
| F3 | MEDIUM | `SessionInitiationId` v1 hashed ephemeral-key bytes (Ed25519 half) and prekey IDs that X3DH and the v1 associated data do not authenticate | Session initiation v2: ID = SHA-256 of a canonical transcript that is also the session's associated data | FIXED — PENDING RE-REVIEW |
| F4 | MEDIUM | The sender `DeviceAddress` of a first contact came from the unauthenticated envelope; submission was public | Signed message submission (server checks sender = signer) **and** addresses in the v2 transcript | FIXED — PENDING RE-REVIEW |
| F5/F6 | LOW | Request-supplied identifiers (possibly with CR/LF) were interpolated into log lines | Log-only escaping (`logSafe`, `forLog`) of every request-supplied identifier | FIXED — PENDING RE-REVIEW |
| F7 | LOW | A plaintext `storage_encryption.format = 0` marker sent an encrypted database back through the plaintext migration | Structural checks, `StorageKeyProvider.hasKeys()` and an authenticated migration intent (record type 13) | FIXED — PENDING RE-REVIEW |
| F8 | LOW | Freshness check and nonce prune used different callers' clocks; a nonce could be pruned while its request was still fresh | Monotonic prune watermark inside the atomic claim | FIXED — PENDING RE-REVIEW |
| F9 | LOW | A `PreKeyMessage` on a locally initiated legacy session was checked against the initiator slot, which is the local key, and then pinned | Responder-role check in the engine; legacy pins only from `sessionRemoteIdentityKey` | FIXED — PENDING RE-REVIEW |

## F1/F2 — Unauthenticated user membership at registration

**Original severity:** HIGH.

**Root cause.** `SecureMessageServer.registerDevice` accepted any
`DeviceAddress` whose key signed the request. Device recovery (M14), offline
recovery key registration (M18), rotation/revocation (M19) and reset
(M23) treat "a registered device of the same `UserId`" as an authority. A
stranger who registered `alice/evil` could authorize a recovery of Alice's
phone, provision Alice's offline recovery key if none existed, and manage
its reset. E2EE plaintext stayed encrypted.

**Fix.**

- `DeviceRegistrationAuthorizer` (`S/DeviceRegistrationAuthorizer.kt`),
  required constructor parameter of `SecureMessageServer(storage, clock,
  deviceRegistrationAuthorizer, recoveryKeyResetPolicy = null)`; no default,
  no allow-all class in production code.
- `registerDevice` order: size → proof of possession (ServerAuth with the
  key in the body, window, nonce) → existing registration (same key → `204`
  without asking; other key → `409`) → host authorization (`USER_HAS_NO_…` /
  `USER_HAS_REGISTERED_DEVICES`) → atomic `register`. Nothing is stored
  before `Authorized`.
- `DeviceRegistrationException.NotAuthorized` → `403
  registration_not_authorized`; an authorizer exception → `500
  internal_error` without its text.
- `DeviceRegistrationRepository.hasRegisteredDevices(userId)` (in-memory
  and SQLDelight).
- Registration's public key is now decoded as canonical Base64 like every
  other field.
- Client: `SecureMessageTransportException.DeviceRegistrationNotAuthorized`.
- Recovery flows are unchanged: their authority is now exactly the
  host-authorized membership (one trust root, no scattered checks).

**Changed files:** `S/DeviceRegistrationAuthorizer.kt` (new),
`S/SecureMessageServer.kt`, `storage/core/.../ServerStorage.kt`,
`storage/server/inmemory/.../InMemoryServerStorage.kt`,
`V/kotlin/.../SqlDelightServerStorage.kt`, `V/sqldelight/.../ServerState.sq`,
`K/KSecureMessageRoutes.kt`, `K/HttpDtos.kt`, `C/SecureMessageTransportException.kt`,
`client/ktor/.../KtorSecureMessageTransport.kt`, `samples/jvm-e2e/app/.../Main.kt`.

**Invariant.** A `DeviceAddress` becomes registered only if the request
proved possession of the key **and** the host authorizer returned
`Authorized` for that address and key. The authorizer never replaces a key.

**Adversarial tests.**
`server:core` `DeviceRegistrationAuthorizationTest`:
`f1FakeDeviceCannotJoinAnExistingUser` (after denial: every
`ProtectedEndpoint` is `DeviceNotRegistered`, M14 authorization is
`AuthorizerNotRegistered`, M18 provisioning impossible, drain/publish of
Alice's address fail; registration, recovery key and reset state,
prekeys and mailbox unchanged), `f1FakeFirstDeviceOfAUserIsDenied`,
`f2AuthorizedSecondDeviceParticipatesInSameUserFlows`,
`sameKeyRetryIsIdempotentWithoutAskingTheHost`,
`authorizerFailureRegistersNothing`, `authenticationFailsBeforeTheHostIsAsked`.
`server:ktor` `SecurityRemediationRoutesTest`:
`f1DeniedRegistrationIs403AndStoresNothing`,
`f1ClientTransportReportsTheDenial`, `sameKeyRetryIs204WithoutAskingTheHost`,
`authorizerFailureIsAGeneric500`, `registrationKeyMustBeCanonicalBase64`.
`storage:testing` `DeviceRegistrationRepositoryContractTest.hasRegisteredDevicesComparesTheExactUserIdAndChangesNothing`
(in-memory, SQLDelight, file-backed).

**Remaining limitations.** KSecureMessage still does not authenticate human
or account ownership: the host's authorizer does. A host that authorizes
everyone reopens F1/F2. A denied request consumes its own nonce.

## F3 — Unauthenticated bytes in `SessionInitiationId`

**Original severity:** MEDIUM.

**Root cause.** Kodium's X3DH uses only the X25519 half of the 64-byte
ephemeral key; the v1 associated data was `initiatorIK || responderIK`. The
Ed25519 half of the ephemeral key (and, indirectly, the prekey IDs) fed the
v1 `SessionInitiationId` unauthenticated. A relay could flip a bit, the
first message still decrypted, the ID was new and not retired: the retired
initiation replay protection was bypassed (session rollback /
desynchronization).

**Fix.** Session initiation **v2** (PreKeyMessage wire type `0x03`):
canonical transcript = domain `KSecureMessage-SessionInitiation-v2` ‖
sender and recipient address ‖ both identity keys ‖ the whole ephemeral key
‖ signed prekey ID ‖ one-time prekey flag/ID. The transcript is the ratchet
associated data of the whole session and `SessionInitiationId` v2 =
SHA-256(transcript). Engine `acceptSession` refuses v1. A repeated v2
`PreKeyMessage` on an existing session is matched field by field. Session
state format v4 records the initiation version, both identity keys and the
v2 header.

**Changed files:** `P/SessionInitiationId.kt`, `P/KodiumProtocolEngine.kt`,
`P/ProtocolEngine.kt`, `P/SessionState.kt`, `P/CiphertextMessageCodec.kt`,
`P/ProtocolConstants.kt`, `core/model/.../Messages.kt`
(`PreKeyMessage.initiationVersion`, `SessionInitiationVersion`),
`C/SecureMessageClient.kt`.

**Invariant.** Changing any byte a v2 `SessionInitiationId` depends on makes
the first message fail to decrypt; there is never a second valid ID with an
accepted session for one initiation.

**Adversarial tests.** `core:protocol` `SessionInitiationV2Test`:
`f3MutatedEphemeralSigningHalfFailsAcceptance`,
`f3MutatedSignedPreKeyIdFailsAcceptanceEvenWithTheSameKey`,
`f3MutatedOneTimePreKeyIdFailsAcceptanceEvenWithTheSameKey`,
`repeatedInitiationWithAnyChangedFieldIsRejectedOnTheSession`,
`versionDowngradeOfTheTypeByteIsRejected`; `SessionInitiationIdTest`
v2 vectors (independently computed). `client:core`
`SecurityReviewRegressionTest`:
`f3MutatedEphemeralSigningHalfCannotBypassRetiredInitiationReplayProtection`
(after a replacement retired the first initiation, without one-time
prekey), `f3MutatedFirstContactCreatesNothing`.

**Remaining limitations.** Withheld initiations that never reached the
device are still accepted as new (unchanged, docs/session-lifecycle.md).

## F4 — Unauthenticated sender address on first contact

**Original severity:** MEDIUM.

**Root cause.** The responder pinned the initiator's identity key under
`EncryptedEnvelope.sender`, which nothing authenticated: `POST /v1/messages`
was public and the v1 associated data had no addresses. A malicious client
could build a valid initiation with its own key and claim `alice/phone`,
poisoning the pin for Alice; a relay could move an honest initiation to
another address.

**Fix (two parts).**

1. **Signed submission:** `POST /v1/messages` is `ProtectedEndpoint.SEND_MESSAGE`:
   header `X-KSecureMessage-Device` names the signer, ServerAuth v1 over the
   exact body with that device's registered key, then `envelope.sender` must
   equal the authenticated device (`403 sender_mismatch`, nothing queued).
   `SecureMessageTransport.send(envelope, signer)`; every client submission
   (send, retry, ACK) is signed.
2. **Transcript binding:** the v2 transcript contains sender and recipient
   address, so a relay that rewrites either fails decryption before any pin.

TOFU order for v2 first contact: pin check (refusal only) → AEAD over the
address-bound transcript → pin, in one transaction with the session.

**Changed files:** `S/DeviceAuthenticator.kt` (`SEND_MESSAGE`, `path`),
`S/SecureMessageServer.kt` (`relay(device, envelope)`,
`EnvelopeSenderMismatchException`), `P/DeviceAuthentication.kt`
(`SUBMIT_MESSAGE`, `encodeDevice`/`decodeDevice`), `K/KSecureMessageRoutes.kt`,
`K/HttpDtos.kt`, `client/ktor/.../KtorSecureMessageTransport.kt`,
`client/ktor/.../HttpDtos.kt`, `C/SecureMessageTransport.kt`,
`C/SecureMessageClient.kt`, plus the F3 files.

**Invariant.** The server queues an envelope only if its sender is the
device that signed the submission; a v2 first contact is accepted and pinned
only if sender and recipient address are the ones the initiator bound.

**Adversarial tests.** `server:core` `DeviceAuthenticationServerTest`:
`f4SubmissionAsAnotherSenderIsRejectedAndQueuesNothing`,
`submissionAuthenticationCoversTheExactBodyAndIsNotReusableForOtherEndpoints`,
`bundleFetchStaysPublicAndSubmissionIsSignedByTheSender`. `server:ktor`
`SecurityRemediationRoutesTest`: `f4SubmissionWhoseSenderIsNotTheSignerIs403AndQueuesNothing`,
`unsignedOrUnnamedSubmissionIs401`, `submissionSignatureCoversTheExactBody`,
`f4ClientTransportCannotSubmitAsAnotherDevice`. `client:core`
`SecurityReviewRegressionTest`: `f4RelayRewritingTheSenderIsRejectedBeforeAnyPin`,
`f4MaliciousClientClaimingAnotherAddressIsRejectedBeforeAnyPin`,
`f4RelayRewritingTheRecipientIsRejected`,
`f4SignedSubmissionStopsAClientSendingAsAnotherDevice`. `core:protocol`
`SessionInitiationV2Test`: `f4RewrittenSenderFailsAcceptance`,
`f4RewrittenRecipientFailsAcceptance`.

**Remaining limitations.** The server is now the authority for the sender
address of a submission. A malicious server can still fabricate a first
contact under any address with a key of its choice, as it can hand out a
bundle with a key of its choice: first contact trusts the server (TOFU);
safety numbers detect it. No sealed sender.

## F5/F6 — Log injection

**Original severity:** LOW.

**Root cause.** `UserId`/`DeviceId` accept any UTF-8. Public and
authenticated routes logged `DeviceAddress`/`UserId` from path and body with
string interpolation, so `%0A` could end a log line and forge the next.

**Fix.** `K/LogSanitizer.kt`: `logSafe` quotes and escapes `\`, `"`, CR,
LF, TAB, every other C0/C1 control, DEL, U+2028 and U+2029;
`DeviceAddress.forLog()` / `UserId.forLog()`. Every route log line uses
them. Identifiers themselves are not restricted or changed.

**Invariant.** Every log event written by the routes is one line; a
request-supplied identifier appears only escaped.

**Adversarial tests.** `server:ktor` `LogInjectionTest`:
`logSafeEscapesEveryLineBreakAndControl`,
`hostileAddressesOnPublicRoutesLogOneLineEachAndAreProcessedUnchanged`
(recording SLF4J logger; `\n`, `\r`, `\r\n`, U+2028, U+2029, U+0085, TAB,
NUL on the public challenge and reset-status routes).

**Remaining limitations.** A log pipeline that unescapes fields reopens the
issue; the exception text of `500` failures is logged as the exception.

## F7 — Storage encryption downgrade through the plaintext migration

**Original severity:** LOW.

**Root cause.** `SqlDelightClientStorage.open` trusted the plaintext
`storage_encryption.format` marker. An attacker with write access to the
database could set it to 0, rebuild the sensitive tables in the milestone 8
layout with chosen rows and have them sealed with the legitimate key.

**Fix.**

- Structural check for `format = 0`: no key, key check or rotation state;
  the five legacy tables in plaintext layout; no record type written only by
  encrypted storage. Otherwise `StorageEncryptionException.DowngradeRejected`.
- `StorageKeyProvider.hasKeys()` (never creates anything; Android, Apple,
  static and test providers).
- Provider empty → genuine first migration: key created, **migration
  intent** (record type 13, `E/ClientRecordCipher.kt`) sealed with it and
  committed before migrating. Provider has a key → only a valid intent
  (opens as type 13 with that key) resumes; otherwise `DowngradeRejected`.
- The migration transaction re-checks everything, migrates, binds and clears
  the intent. A `format = 1` database with an intent is refused.
- Client schema v16 (`Q/.../15.sqm`, `storage_encryption.migration_intent`),
  frozen fixture `Version15Schema`; `SEALED_COLUMNS` scans the intent.

**Changed files:** `Q/kotlin/.../SqlDelightClientStorage.kt`,
`Q/kotlin/.../LegacyPlaintextMigration.kt` (`hasPlaintextLayout`),
`Q/kotlin/.../StorageKeyRotation.kt`, `Q/sqldelight/.../ClientState.sq`,
`Q/sqldelight/.../15.sqm`, `E/StorageKeys.kt`, `E/ClientRecordCipher.kt`,
`E/EncryptedRecordFormat.kt`, `E/StorageEncryptionException.kt`,
`storage/keyprovider/android/.../AndroidStorageKeyProvider.kt`,
`storage/keyprovider/apple/.../AppleStorageKeyProvider.kt`.

**Invariant.** A database that was ever bound to a storage key is never
migrated from plaintext again: forcing `format` back fails closed and
nothing is encrypted.

**Adversarial tests.** `storage:client:sqldelight` `StorageDowngradeTest`:
`f7EncryptedDatabaseRewrittenAsPlaintextIsRejected` (the full attack),
`f7OnlyTheFormatMarkerFlippedIsRejectedTyped`,
`f7MarkersClearedButPostPlaintextRecordsKeptIsRejected`,
`f7KeyColumnsOnlyClearedIsRejected`,
`f7FlippedDatabaseIsRejectedByItsStructureEvenWithAnEmptyProvider`,
`f7ForgedMigrationIntentIsRejected` (key check, garbage, intent of another
key), `f7CrashBetweenKeyCreationAndTheIntentFailsClosed`,
`f7StaticProviderCannotProveAFirstMigration`,
`genuinePlaintextDatabaseMigratesWithAnEmptyProvider`,
`encryptedDatabaseCarryingAnIntentIsRejected`,
`version15DatabaseGainsAnEmptyMigrationIntent`. `SqlDelightMigrationTest`
(frozen milestone 8 database, `failedMigrationRollsBackCompletely` resumes
with the intent). `storage:encryption` `StorageCipherTest.migrationIntentVector`
(independently computed), `migrationIntentIsNoKeyCheckAndNeedsItsKey`.
`storage:testing` `StorageKeyProviderContractTest.hasKeys*`.

**Remaining limitations.** Not whole-database rollback protection. A crash
between key creation and the intent commit fails closed (manual recovery).
A copy of the file taken while a genuine first migration was interrupted
could be replayed later. `StaticStorageKeyProvider` cannot migrate a
milestone 8 database (deliberate).

## F8 — Nonce pruned while its request is still fresh

**Original severity:** LOW.

**Root cause.** Accepted: `now − W ≤ ts ≤ now + W`. A request with `ts` is
replayable while server time `t ≤ ts + W`. Each claim pruned `ts < now − W`
with its own `now`; the freshness check used another. A replay checked at
`ts + W` could claim after a concurrent request checked at `ts + W + 1 ms`
had pruned the original nonce.

**Fix.** Monotonic prune watermark `P` in `AuthenticationNonceRepository.claim`,
one atomic step: `P := max(P, pruneBefore)`; refuse `ts < P`; prune `< P`;
insert. In-memory field; SQLDelight server schema v8 (`V/.../7.sqm`,
`authentication_nonce_watermark`, frozen fixture `ServerVersion7Schema`).
Recovery, rotation and recovery key CAS helpers claim through the same step.

**Invariant.** Every nonce with timestamp `≥ P` is retained and every claim
with timestamp `< P` is refused; therefore a nonce is refused for the whole
time its request can pass the window, whatever the interleaving.

**Adversarial tests.** `storage:testing` `AuthenticationNonceRepositoryContractTest`
(in-memory, SQLDelight, file-backed): `f8InterleavedPruneBeforeReplayClaimIsRejected`,
`f8NonceIsRetainedForItsWholeReplayLifetime` (earliest valid, current,
future-dated `ts = now + W`), `f8ExactPruneBoundary` (±1 ms),
`f8WatermarkNeverDecreases`, `f8ConcurrentPruneAndReplayClaimsNeverAcceptAReplay`.
`server:core` `NonceLifetimeServerTest`.

**Remaining limitations.** After a backward jump of the server clock,
requests older than the watermark are refused (never accepted twice) until
the clock catches up. A legitimate request can be refused only in the
last clock tick of its window when another request already advanced `P`.

## F9 — Legacy locally initiated session pins the local identity

**Original severity:** LOW (confirmed by 2 of 3 review checkers).

**Root cause (confirmed in the source).** Engine `decrypt` accepted a
`PreKeyMessage` if `associatedData.startsWith(message.identityKey)` — the
initiator slot. For a session this device initiated, that slot is the
**local** key. On a pre-milestone-6 session (`origin == null`) the origin
check was skipped, and the client then pinned `message.identityKey` for an
unpinned session. A relay could wrap the peer's genuine ratchet message in a
`PreKeyMessage` naming the victim's own key: the victim pinned itself.

**Fix.** `checkRepeatedInitiation` (`P/KodiumProtocolEngine.kt`): a
`PreKeyMessage` on an existing session requires that this device is the
**responder** (responder slot = local key, initiator slot ≠ local key), that
the message names the initiator key and has the session's initiation
version. `ProtocolEngine.decrypt` gains `localIdentityKey`. Legacy pins come
only from `ProtocolEngine.sessionRemoteIdentityKey(session, localIdentityKey)`
(the one non-local slot; `null` if ambiguous) and only if it equals the
message's key (`C/SecureMessageClient.kt` `pinLegacySession`).

**Invariant.** A remote pin is only ever the authenticated remote identity
key of the session; never the local identity; never guessed.

**Adversarial tests.** `client:core` `SecurityReviewRegressionTest`:
`f9LocallyInitiatedLegacySessionNeverPinsTheLocalIdentity` (frozen pre-S1
fixture), `f9ResponderLegacySessionPinsTheAuthenticatedInitiatorKey`,
`f9AmbiguousLegacySessionFabricatesNoPin`, `f9ExistingVerifiedPinIsUnchanged`.
`core:protocol` `SessionInitiationV2Test`:
`f9InitiatorNeverAcceptsAPreKeyMessageOnItsOwnSession`,
`f9LegacyInitiatorSessionRejectsARewrappedMessageNamingItsOwnIdentity`,
`sessionRemoteIdentityKeyNeverReturnsTheLocalKey`.

**Remaining limitations.** A locally initiated session from before pinning
stays unpinned until an authenticated new initiation replaces it.

## Version changes

Kept apart on purpose:

| Layer | Before S1 | After S1 |
|---|---|---|
| Maven version | `0.1.0-SNAPSHOT` | unchanged |
| HTTP API v1 paths | — | unchanged; semantics changed: registration needs host authorization (`403 registration_not_authorized`); `POST /v1/messages` needs ServerAuth + `X-KSecureMessage-Device` (`401`, `403 sender_mismatch`, `400 invalid_envelope`) |
| ServerAuth signed input | v1 | v1, unchanged (new endpoint only) |
| Ciphertext wire format | v1, types `0x01`, `0x02` | v1, new type `0x03` = PreKeyMessage with initiation v2 |
| Session initiation | v1 (AD = identity keys) | v2 for every new initiation (AD = transcript); v1 only continues existing sessions |
| `SessionInitiationId` | v1 domain `…-SessionInitiation-v1` | v2 domain `…-SessionInitiation-v2` (SHA-256 of the transcript); v1 kept for stored IDs |
| Session state (local) | format 3 | format 4 (v1–3 still read) |
| `SecurePayload` frame, ACK | v1 | unchanged |
| KSMR record format | v1, types 1–12 | v1, new type 13 (migration intent) |
| Client SQLDelight schema | 15 | 16 (`15.sqm`) |
| Server SQLDelight schema | 7 | 8 (`7.sqm`) |
| Recovery, rotation, reset, safety number crypto formats | frozen | unchanged |

**Unchanged:** established-session ratchet messages (type `0x01`), the
`SecurePayload` frame and ACK, the KSMR record format and existing record
types, ServerAuth v1, device recovery / rotation / last-device recovery /
recovery key lifecycle / reset formats and vectors, safety numbers, X3DH and
ratchet info strings.

**Intentionally changed:** session initiation / first-contact version,
sender-address authentication, `SessionInitiationId` derivation, device
registration authorization semantics, message submission authentication,
nonce retention, plaintext migration eligibility.

## Upgrade behavior

- Established sessions survive and keep ratcheting; no new X3DH.
- A pending v1 initiation the peer accepted before upgrading continues. A v1
  initiation the peer never accepted is rejected; the initiator must start a
  new (v2) session.
- A pre-S1 peer cannot decode type `0x03`, and a pre-S1 client cannot submit
  to an S1 server. **Upgrade servers and clients together.** There is no
  automatic v1 fallback that a relay could force.
- Servers: construct `SecureMessageServer` with a `DeviceRegistrationAuthorizer`;
  migrate the server database to schema 8 before `open`.
- Clients: pending messages of a device without its device authentication
  key cannot be submitted (they stay pending).

## Public API changes

- `server:core`: new `DeviceRegistrationAuthorizer`,
  `DeviceRegistrationAuthorizationRequest`, `DeviceRegistrationUserState`,
  `DeviceRegistrationAuthorizationResult`, `EnvelopeSenderMismatchException`;
  `SecureMessageServer(storage, clock, deviceRegistrationAuthorizer,
  recoveryKeyResetPolicy = null)` (clock no longer defaulted);
  `relay(device, envelope)`; `ProtectedEndpoint.SEND_MESSAGE`,
  `ProtectedEndpoint.path(address)`.
- `storage:core`: `DeviceRegistrationRepository.hasRegisteredDevices`,
  `DeviceRegistrationException.NotAuthorized`; `AuthenticationNonceRepository.claim`
  contract (watermark).
- `core:model`: `SessionInitiationVersion`, `PreKeyMessage.initiationVersion`.
- `core:protocol`: `ProtocolEngine.initiateSession(localIdentity,
  localAddress, bundle)`, `acceptSession(localIdentity, localAddress, …)`,
  `decrypt(session, message, localIdentityKey)`,
  `sessionRemoteIdentityKey`; `SessionInfo.initiationVersion`;
  `SessionInitiationId.v2Of`; `ServerApiPaths.SUBMIT_MESSAGE`,
  `encodeDevice`, `decodeDevice`; `CiphertextMessageCodec.TYPE_PREKEY_MESSAGE_V2`
  (internal API).
- `client:core`: `SecureMessageTransport.send(envelope, signer)`;
  `SecureMessageTransportException.DeviceRegistrationNotAuthorized`,
  `EnvelopeSenderRejected`.
- `storage:encryption`: `StorageKeyProvider.hasKeys()`,
  `StorageEncryptionException.DowngradeRejected`,
  `ClientRecordCipher.sealMigrationIntent`/`verifyMigrationIntent` (internal API).

## Mutation testing

Each mutation was applied temporarily, the named suites run, the source
restored; the working tree was compared with a snapshot afterwards.

| # | Mutation | Caught by |
|---|---|---|
| 1 | authorizer bypassed for a second device | `DeviceRegistrationAuthorizationTest.f1FakeDeviceCannotJoinAnExistingUser` |
| 2 | authorizer bypassed for a first device | `DeviceRegistrationAuthorizationTest.f1FakeFirstDeviceOfAUserIsDenied` |
| 3 | denial still inserts the registration | `f1FakeDeviceCannotJoinAnExistingUser`, `f1FakeFirstDeviceOfAUserIsDenied` |
| 4 | recovery accepts an unregistered authorizer | `DeviceRecoveryServerTest.authorizerAndTargetMustBeRegistered`, `f1FakeDeviceCannotJoinAnExistingUser` |
| 5 | sender address omitted from the transcript | `SecurityReviewRegressionTest.f4RelayRewritingTheSenderIsRejectedBeforeAnyPin`, `f4MaliciousClientClaimingAnotherAddressIsRejectedBeforeAnyPin`, `SessionInitiationIdTest` v2 vectors |
| 6 | unauthenticated ephemeral bytes (identity-key-only AD) | `f3MutatedEphemeralSigningHalfFailsAcceptance`, `f3MutatedEphemeralSigningHalfCannotBypassRetiredInitiationReplayProtection` |
| 7 | initiation ID from raw message bytes | `f3MutatedEphemeralSigningHalfCannotBypassRetiredInitiationReplayProtection`, `SessionLifecycleTest` (replacement, collision) |
| 8 | TOFU pin written before transcript authentication (same transaction) | Not independently observable because pin and session persist atomically; the adversarial no-pin-after-auth-failure tests cover the security property (`f4RelayRewritingTheSenderIsRejectedBeforeAnyPin`, `f4MaliciousClientClaimingAnotherAddressIsRejectedBeforeAnyPin`, `f3MutatedFirstContactCreatesNothing`). |
| 9 | v1 fallback (v1 initiation accepted with v1 AD) | `SessionInitiationV2Test.versionDowngradeOfTheTypeByteIsRejected`, `SessionLifecycleTest.preS1InitiationTheResponderNeverAcceptedIsRejected` |
| 10 | raw CR/LF in logs | `LogInjectionTest` (both) |
| 11 | format rollback migrates although the provider holds a key | `StorageDowngradeTest.f7EncryptedDatabaseRewrittenAsPlaintextIsRejected`, `f7CrashBetweenKeyCreationAndTheIntentFailsClosed`, `f7StaticProviderCannotProveAFirstMigration` |
| 12 | structural check skipped | `StorageDowngradeTest.f7FlippedDatabaseIsRejectedByItsStructureEvenWithAnEmptyProvider` |
| 13 | watermark refusal removed (in-memory) | `InMemoryAuthenticationNonceRepositoryTest.f8*`, `NonceLifetimeServerTest.f8ReplayAfterAConcurrentPruneAtTheWindowEdgeIsRejected` |
| 14 | pre-S1 claim (SQLDelight) | `SqlDelight/FileBackedAuthenticationNonceRepositoryTest.f8*` |
| 15 | engine role check removed | `f9LocallyInitiatedLegacySessionNeverPinsTheLocalIdentity`, `f9InitiatorNeverAcceptsAPreKeyMessageOnItsOwnSession`, `f9LegacyInitiatorSessionRejectsARewrappedMessageNamingItsOwnIdentity` |
| 16 | `sessionRemoteIdentityKey` guesses when ambiguous | `sessionRemoteIdentityKeyNeverReturnsTheLocalKey` |

Mutation 9 first survived at the client level because the legacy test's
responder lacked the prekeys the initiation named (it failed for another
reason); the fixture now includes them and the test checks the exact error.

## Remaining limitations (overall)

- The host application authenticates and authorizes `UserId` membership;
  KSecureMessage still does not prove human or account identity.
- The server sees metadata and vouches for sender addresses; no sealed
  sender. First contact trusts the server (TOFU); safety numbers detect key
  substitution.
- No formal verification; Kodium is a dependency with its own review status.
- No finding is closed until the independent reviewer re-runs the review.
- Legacy: v1 initiations not accepted before the upgrade are lost; peers and
  servers must be upgraded together; `StaticStorageKeyProvider` cannot
  migrate milestone 8 databases.
