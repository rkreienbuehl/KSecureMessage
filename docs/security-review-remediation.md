# Security review remediation (S1)

Re-review packet for the first security review of KSecureMessage (after
milestones 1–25, R1 and R2). The review reported nine findings, F1–F9. S1
fixes their trust roots. Where the vulnerable behavior was part of a format
or an API, S1 versions or breaks it on purpose: security takes precedence
over compatibility with the vulnerable behavior.

**S1 re-review result:** passed with residual risks (F1/F2, F3, F4, F5/F6,
F8, F9 closed; F7 partially fixed), plus new findings N1–N3 and
documentation findings D1–D7. **S1.1** (section [S1.1 follow-up](#s11-follow-up))
addresses exactly those. **S1.1 re-review result:** passed with residual
risks, plus findings N4 and N5; **S1.2** (section [S1.2
follow-up](#s12-follow-up)) addresses those. **S1.2 re-review result:**
passed with residual risks (N5 closed), plus two LOW findings N6 and N7
and the cleanup side effects INFO-3; **S1.3** (section [S1.3
follow-up](#s13-follow-up)) addresses those. Status of N1–N4: **FIXED —
PENDING RE-REVIEW**; N5: **CLOSED** by the independent S1.2 re-review;
N6, N7: **FIXED — PENDING RE-REVIEW**; F7: **PARTIALLY FIXED — RESIDUAL
RISK DOCUMENTED**. Only the independent re-review closes a finding: rows
marked CLOSED were closed by it, everything else in the summary is open
until it has been re-checked. Neither S1, S1.1, S1.2 nor S1.3 is an audit.

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
| F1/F2 | HIGH | Registration was trust on first registration: anyone could register a device under an existing `UserId` and then act as one of the user's devices | Host-provided `DeviceRegistrationAuthorizer`, required for every first registration, including a user's first device | CLOSED (re-review) |
| F3 | MEDIUM | `SessionInitiationId` v1 hashed ephemeral-key bytes (Ed25519 half) and prekey IDs that X3DH and the v1 associated data do not authenticate | Session initiation v2: ID = SHA-256 of a canonical transcript that is also the session's associated data | CLOSED (re-review) |
| F4 | MEDIUM | The sender `DeviceAddress` of a first contact came from the unauthenticated envelope; submission was public | Signed message submission (server checks sender = signer) **and** addresses in the v2 transcript | CLOSED (re-review) |
| F5/F6 | LOW | Request-supplied identifiers (possibly with CR/LF) were interpolated into log lines | Log-only escaping (`logSafe`, `forLog`) of every request-supplied identifier | CLOSED (re-review) |
| F7 | LOW | A plaintext `storage_encryption.format = 0` marker sent an encrypted database back through the plaintext migration | Structural checks, `StorageKeyProvider.hasKeys()` and an authenticated migration intent (record type 13); S1.1: residual risks documented (intent replay, provider state trust, Android `hasKeys`) | PARTIALLY FIXED — RESIDUAL RISK DOCUMENTED |
| F8 | LOW | Freshness check and nonce prune used different callers' clocks; a nonce could be pruned while its request was still fresh | Monotonic prune watermark inside the atomic claim | CLOSED (re-review) |
| F9 | LOW | A `PreKeyMessage` on a locally initiated legacy session was checked against the initiator slot, which is the local key, and then pinned | Responder-role check in the engine; legacy pins only from `sessionRemoteIdentityKey` | CLOSED (re-review) |
| N1 | MEDIUM | The registration authorizer received no host authentication context, so "may *this caller* register for this `UserId`?" was not expressible | Generic `DeviceRegistrationAuthorizer<C>` with the host's context; required `DeviceRegistrationContextExtractor<C>` in the Ktor routes; no context = denied | FIXED — PENDING RE-REVIEW |
| N2 | LOW | `userState` ("user has no devices") was read outside the atomic registration write and presented as a fact | `DeviceRegistrationUserState` and `hasRegisteredDevices` removed; no authorization input depends on KSecureMessage's registrations | FIXED — PENDING RE-REVIEW |
| N3 | LOW | An unanswered v1 initiation could win the collision comparison against a v2 initiation that the upgraded peer needs, deadlocking both sides | Unanswered v1 initiations never win, are never sent again and are replaced by v2 on receive and on send | FIXED — PENDING RE-REVIEW |
| N4 | LOW | Host code throwing an `Error` (`AssertionError`, `NotImplementedError`) bypassed the `Exception`-only wrapper at the authorizer and extractor boundaries and reached Ktor's logging with message and stack | One boundary policy: every host `Throwable` wrapped and logged by class name only; the propagated exceptions are refined by N7 (S1.3) | FIXED — PENDING RE-REVIEW |
| N5 | MEDIUM | The pre-S1 cleanup removed a malicious device but left the offline recovery key it may have planted ACTIVE, so the attacker kept same-user authority | Offline, transactional, tested cleanup that also revokes the user's recovery key state and deletes its reset and challenges; fresh key from a legitimate device | CLOSED (re-review) |
| N6 | LOW | The cleanup could be pasted into an interactive `sqlite3` prompt, which continues after a failure and then commits a partial cleanup; a mistyped device matched nothing and still revoked the recovery key while the attacker's device stayed registered | One script file run only as `sqlite3 -bail db < script`; in-transaction guards before the first change (listed devices exist, none duplicated, list not empty, schema 8, exhausted epochs only where listed); mandatory post-cleanup verification | FIXED — PENDING RE-REVIEW |
| N7 | LOW | The host boundaries rethrew every `CancellationException` and every `VirtualMachineError`, so host code could leak its message (on CIO into the 500 body and the log) with a synthetic cancellation or `InternalError` | Only genuine cancellation (coroutine no longer active), `OutOfMemoryError` and `StackOverflowError` propagate; everything else is sanitized, identically at both boundaries | FIXED — PENDING RE-REVIEW |
| D1–D7 | DOC | Documentation described unreachable authorizer inputs, a racy value as authoritative, and understated legacy and storage residuals | Corrected, see [S1.1 follow-up](#s11-follow-up) | FIXED — PENDING RE-REVIEW |

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
  without asking; other key → `409`) → host authorization (S1: with `USER_HAS_NO_…` /
  `USER_HAS_REGISTERED_DEVICES`; S1.1: with the host context instead) → atomic `register`. Nothing is stored
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
(in-memory, SQLDelight, file-backed; removed with `hasRegisteredDevices` in S1.1).

**Remaining limitations.** KSecureMessage still does not authenticate human
or account ownership: the host's authorizer does. A host that authorizes
everyone reopens F1/F2. A denied request consumes its own nonce.

**S1.1 changes to this fix:** the authorizer now receives the host's
authentication context and no longer a `DeviceRegistrationUserState`;
`hasRegisteredDevices` and its contract test are removed (findings N1, N2).
The S1 test names above were kept and adapted.

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

<!-- ksm-security-claim:f7-partial -->
**Remaining limitations (S1.1: stated precisely, finding D6/D7).**

- **What S1 protects:** a database whose provider holds its key cannot be
  pushed back through the plaintext migration by editing the database file
  alone, unless the attacker holds a valid migration intent.
- **Intent replay across time:** an intent captured while a genuine first
  migration was interrupted stays valid as long as that storage key exists.
  Completing the migration clears it in that database only, not in the
  attacker's copy.
- **Intent replay across databases:** the intent is bound to the provider
  key, not to a database; under the same provider (namespace and key) it
  opens in any reconstructed database. The window closes when that storage
  key is rotated out and removed. A per-database random ID was not added: it
  would sit in the same attacker-writable file.
- **Provider state is trusted:** the check assumes the provider's backing
  state is intact. `AndroidStorageKeyProvider.hasKeys()` reads the wrapped
  key file, not the Keystore alias: an attacker who can delete that file in
  the app sandbox makes the provider look empty, and a downgraded database
  then passes as a first migration. No protection against modification of
  both database and provider state.
- Not whole-database or provider rollback protection. A crash between key
  creation and the intent commit fails closed (manual recovery).
  `StaticStorageKeyProvider` cannot migrate a milestone 8 database
  (deliberate).

F7 remains partially fixed; the residual risks above are accepted for
v0.x and documented, not closed.

**Status:** PARTIALLY FIXED — RESIDUAL RISK DOCUMENTED (accepted for v0.x).
<!-- /ksm-security-claim:f7-partial -->

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

**Remaining limitations (corrected in S1.1, finding D4).** The S1 text said
a locally initiated session from before pinning "stays unpinned until an
authenticated new initiation replaces it", but the S1 code refused every
replacement of an unpinned session. Since S1.1: an unpinned session is
replaced only by a v2 initiation naming exactly the identity it was
established with as remote (`sessionRemoteIdentityKey`), which is then
pinned; any other key, or an undeterminable one, is still refused
(`InvalidMessage`) and only the application can remove such a session. An
unanswered v1 initiation is replaced by any authenticated v2 initiation
(finding N3).

## S1.1 follow-up

The S1 re-review passed with residual risks and reported N1–N3 and D1–D7.
S1.1 addresses only those. No new wire, cryptographic or record format, no
client or server schema change.

### N1 — Registration authorizer without the host's request context

**Severity:** MEDIUM.

**Root cause.** `DeviceRegistrationAuthorizer.authorize(request)` saw only
the address, the proposed key and `userState`. The docs suggested account
tokens, sessions or enrollment codes, but nothing carried them from the
HTTP call to the authorizer, so a host could not answer "may *this caller*
register this device for this `UserId`?" without side channels
(thread-locals, global request state).

**Fix.**

- `S/DeviceRegistrationAuthorizer.kt`: `fun interface
  DeviceRegistrationAuthorizer<in C : Any> { suspend fun authorize(context: C,
  request): DeviceRegistrationAuthorizationResult }`. `C` is opaque host
  state (principal, session, OAuth subject, enrollment grant); never logged,
  serialized, stored, returned or put into a signed or hashed input.
- `SecureMessageServer<C : Any>(storage, clock, deviceRegistrationAuthorizer:
  DeviceRegistrationAuthorizer<C>, recoveryKeyResetPolicy = null)`;
  `registerDevice(context: C?, registration, body, authentication)`. Order:
  size → proof of possession → existing registration (same key `false`,
  other key `Conflict`, no host call, no context needed) → `context == null`
  → `NotAuthorized` → authorizer (outside every storage transaction) →
  atomic `register`. An authorizer exception becomes
  `DeviceRegistrationAuthorizationFailedException` (fixed message, host
  exception as `cause`).
- `K/DeviceRegistrationContextExtractor.kt`: `fun interface
  DeviceRegistrationContextExtractor<out C : Any> { suspend fun
  extract(call: ApplicationCall): C? }`; `fun <C : Any>
  Route.kSecureMessageRoutes(server: SecureMessageServer<C>,
  registrationContext: DeviceRegistrationContextExtractor<C>)`: both
  required, no default, the type parameter ties extractor and authorizer
  together. `server:core` has no Ktor dependency.
- HTTP: no context or `Denied` → `403 registration_not_authorized`;
  extractor or authorizer exception → `500 internal_error`, logged only as
  `Registration authorization failed (<exception class>)` (no message,
  stack, cause or context); same key → `204`; other key → `409`.
- Sample (`samples/jvm-e2e`): DEMO ONLY bearer-token table → `DemoPrincipal`
  → authorizer `request.address.userId == principal.userId`; the clients
  send the token through their own `HttpClient`; the sample checks that
  Mallory's principal and no principal cannot register `alice/tablet` and
  Alice's principal can.

A normal host wires it like this: its own authentication (Ktor
`Authentication`, a session, a bearer token) establishes a principal for the
call → the extractor returns that principal, `null` if the call is not
authenticated → the authorizer allows the registration iff the principal
owns `request.address.userId` (and the host's device policy agrees).

**Changed files:** `S/DeviceRegistrationAuthorizer.kt`,
`S/SecureMessageServer.kt`, `K/DeviceRegistrationContextExtractor.kt` (new),
`K/KSecureMessageRoutes.kt`, `samples/jvm-e2e/app/build.gradle.kts`,
`samples/jvm-e2e/app/.../Main.kt`; test support
`TestDeviceRegistrationAuthorizer`/`TestRegistrationPrincipal` (server:core,
server:ktor), `TestServer.kt`, `RecordingLogger.kt`.

**Invariant.** Every new registration decision receives the host
application's authenticated request context; without one no registration is
created.

**Adversarial tests.** `server:core` `DeviceRegistrationAuthorizationTest`:
`n1RegistrationAuthorizationReceivesTheAuthenticatedApplicationPrincipal`
(the exact context object reaches the authorizer),
`n1WrongPrincipalCannotRegisterAnotherUsersDevice`,
`n1MissingContextIsDeniedAndRegistersNothing` (even an allow-all authorizer
is not called), `n1MalloryCannotBecomeAlicesRecoveryAuthority` (denied
registration → `AuthorizerNotRegistered`; her own user's device →
`CrossUser`), `sameKeyRetryIsIdempotentWithoutAskingTheHost` (also without
context), `authorizerFailureRegistersNothing`. `server:ktor`
`SecurityRemediationRoutesTest`: `n1RegistrationAuthorizationReceivesTheAuthenticatedApplicationPrincipal`,
`n1WrongPrincipalCannotRegisterAnotherUsersDevice`,
`n1MissingContextIsDeniedAndRegistersNothing` (403, then 201 with the
principal, 204 retry without it, 409 other key),
`n1HostFailuresLeakNoContext` (authorizer and extractor throwing with
secret text: `500 internal_error`, secret in neither body nor log, nothing
stored), `n1ClientWithTheHostsAuthenticationRegistersThroughTheKtorAdapter`.
Sample E2E (`verifyPublication`).

**Remaining assumptions.** The host's extractor and authorizer are correct:
an extractor that returns a shared principal for unauthenticated calls or
an authorizer that ignores the principal reopens F1/F2.

**Status:** FIXED — PENDING RE-REVIEW.

### N2 — Non-atomic `userState`

**Severity:** LOW.

**Root cause.** `registerDevice` read `hasRegisteredDevices(userId)` before
the authorizer and wrote with a separate atomic `register`. Two concurrent
first registrations of one user could both be told
`USER_HAS_NO_REGISTERED_DEVICES`; a policy "the first device may enroll
itself" would admit both, while the value was documented as a fact.

**Fix (design: remove, not make atomic).** `DeviceRegistrationUserState`,
`DeviceRegistrationAuthorizationRequest.userState` and
`DeviceRegistrationRepository.hasRegisteredDevices` are removed (in-memory,
SQLDelight, the `countRegisteredDevicesOfUser` query; no schema change).
The authorizer decides only from the host context, the address, the
proposed key and host-owned state. "The user has no devices yet" is not
ownership. The only storage precondition of a registration, "this address
is not registered", is enforced by the atomic `register` (primary key plus
`INSERT OR IGNORE`, or the in-memory mutex).

**Invariant.** No authorization decision depends on a KSecureMessage read
outside the registration's atomic write.

**Adversarial tests.** `server:core` `RegistrationRaceTest` (in-memory,
SQLDelight in-memory, file-backed SQLite; every host decision held open by
a barrier until all racing requests are inside the authorizer; gates, no
sleeps): `n2ConcurrentFirstDeviceClaimsCannotBothWin` (32 concurrent claims
on 32 device IDs of a user with no devices, 16 by Alice's principal, 16 by
Mallory's: exactly Alice's 16 registered, none of Mallory's),
`n2LegitimateAndAttackerFirstDeviceRaceOnlyThePrincipalWins` (a new user's
legitimate first device vs an attacker's, both decisions open at once, in
both completion orders: the legitimate one registered, the loser not),
`n2SameAddressConflictingKeysHaveExactlyOneWinner` (32 authorized keys for
one address: one registered, 31 conflicts).
`DeviceRegistrationAuthorizationTest.n2NoAuthorizationInputDependsOnExistingDevices`
(the request type carries only address and key; the same principal gets
the same decision for a user with and without devices).
`storage:testing` `DeviceRegistrationRepositoryContractTest.concurrentRegistrationsOfOneNewUsersDevicesAreAllStored`.

**Remaining assumptions.** A host that wants a "first device only" policy
must enforce it with its own atomic state (for example a single-use
enrollment grant in its account database), not with KSecureMessage's
registrations.

**Status:** FIXED — PENDING RE-REVIEW.

### N3 — Unanswered v1 initiation deadlocks v2 after the upgrade

**Severity:** LOW.

**Root cause.** A device could hold a pending (never answered) v1 initiation
from before S1. The collision rule compared its v1 ID with an incoming v2
ID; if v1 was smaller, the v2 initiation lost and was retired, while the
upgraded peer refuses every v1 initiation. The device also kept sending the
v1 initiation. Neither side could make progress, and there was no reset
path. An unpinned pending v1 session additionally refused every v2
initiation (`!pinned`).

**Fix** (`C/SecureMessageClient.kt`, session collision policy only):

- *receive:* a v2 initiation always replaces an own v1 session awaiting a
  reply (`isUnansweredVersion1Initiation`), before the pin and collision
  rules: no ID comparison, also without a pin (nothing was ever
  established on it; a pin that exists is still checked first). The v1
  origin is retired in the same transaction.
- *send:* `usableSession` never returns such a session. `send`,
  `retryPendingMessages`, `encryptRaw` and session setup fetch a bundle
  (outside transactions) and `initiateReplacingUnanswered` starts a v2
  session, retires the v1 origin and stores the new session with the
  encryption in one transaction. A pending logical message keeps its ID and
  sequence and is re-encrypted on v2.
- *acknowledge:* never on such a session (`ackSent = false`, nothing
  written); the sender's retry on the v2 session triggers a new ACK.
- Consequence: an unpinned *established* legacy session whose peer now
  sends v2 instead of the v1 repetition that used to pin it is replaced only
  by a v2 initiation naming the identity it was established with
  (`isLegacySessionIdentity`, the F9 check), which is then pinned (D4).
- Established v1 sessions (`awaitingReply` false) are unchanged. A peer's
  reply on a v1 initiation it accepted before upgrading still completes it.

**Invariant.** After the upgrade an unanswered, locally initiated v1
initiation can never block a v2 initiation and is never retransmitted;
accepted established v1 sessions continue.

**Adversarial tests.** `client:core` `SessionLifecycleTest`:
`n3PendingV1CanNeverBlockIncomingV2AfterUpgrade` (v2 ID larger than the v1
origin — the old deadlock order — and smaller, precondition asserted;
converges, bidirectional), `n3UnpinnedPendingV1IsReplacedByV2`,
`n3PinnedPendingV1StillRefusesAnotherIdentity`,
`n3BothPeersPendingV1ConvergeAfterUpgrade` (new frozen fixture
`LegacySessionFixture.bobPendingV3`; sequential and simultaneous),
`n3PendingV1IsNeverRetransmittedAndItsLogicalMessageMovesToV2` (peer never
accepted / accepted before upgrading; same logical ID, one delivery, ACK
clears pending), `n3AckIsNeverSentOverPendingV1`,
`n3DiscardedV1InitiationCannotRevive`,
`sessionWithoutPinIsNeverReplacedByAnotherIdentity`, and
`preS1EstablishedSessionsKeepRatchetingAfterTheUpgrade`,
`preS1InitiationTheResponderNeverAcceptedIsRejected`,
`preS1InitiationNeverReplacesAVersion2Session` (now asserts the exact
error), `preS1PendingInitiationContinuesWhenTheResponderAcceptedItBefore`
(continuation by the responder's reply). Legacy v1 repetitions in tests are
made with the engine directly (`legacyV1Repetition`), since the client no
longer sends them; `SecurityReviewRegressionTest` `f9*` use the same helper.

**Remaining assumptions.** Replacing an unanswered v1 initiation that the
peer did accept before upgrading drops that peer's in-flight v1 replies
(they no longer decrypt); its reliability layer resends them. Peers must
still be upgraded together.

**Status:** FIXED — PENDING RE-REVIEW.

### D1–D7 — Documentation

| Finding | Correction |
|---|---|
| D1 authorizer mechanisms not reachable | Real host-context API documented with an integration pattern: [server-authentication.md](server-authentication.md#registration-authorization-s1-findings-f1f2), [operating-the-server.md](operating-the-server.md#deviceregistrationauthorizer), README, sample |
| D2 `userState` presented as authoritative | Removed from API and docs (N2); the docs say why no KSecureMessage state is passed |
| D3 pre-S1 registrations never host-authorized | [operating-the-server.md](operating-the-server.md#registrations-from-before-s1): impact, read-only audit SQL, offline removal guidance, upgrade checklist; limitation in server-authentication.md |
| D4 identity-trust legacy wording | [identity-trust.md](identity-trust.md#sessions-from-before-pinning) and F9 above describe the actual behavior (now: replaced only by its own remote identity; otherwise refused) |
| D5 obsolete session-lifecycle limitations | [session-lifecycle.md](session-lifecycle.md#limitations): stale "no safety numbers / authenticated API / persistent mailbox / encryption at rest" removed; N3 rules and step table updated |
| D6 F7 intent replay understated | [storage-encryption.md](storage-encryption.md#downgrade-protection) and F7 above: replay across time and across databases under the same provider key, window closed only by key rotation, no rollback protection |
| D7 Android `hasKeys()` limitation | [storage-key-providers.md](storage-key-providers.md#haskeys-s1): reads the wrapped key file, not the Keystore alias; F7 assumes intact provider state |

### S1.1 mutation testing

Each mutation was applied temporarily, the named suites run, the source
restored; the working tree diff was compared byte for byte with a snapshot
afterwards.

| # | Mutation | Caught by |
|---|---|---|
| S1.1-1 | route drops the host context (passes `null` / an anonymous context) | `SecurityRemediationRoutesTest.n1*` and every route test that registers (76 `server:ktor` tests) |
| S1.1-2 | sample extractor derives the principal from the target `UserId` in the path | sample E2E: `alice/tablet with mallory's principal must be refused` |
| S1.1-3 | missing context treated as authorized | `DeviceRegistrationAuthorizationTest.n1MissingContextIsDeniedAndRegistersNothing`, `SecurityRemediationRoutesTest.n1MissingContextIsDeniedAndRegistersNothing` |
| S1.1-4 | sample authorizer ignores the principal | sample E2E: `alice/tablet with mallory's principal must be refused` |
| S1.1-5 | host denial ignored, first writer wins | `RegistrationRaceTest.n2ConcurrentFirstDeviceClaimsCannotBothWin`, `n2LegitimateAndAttackerFirstDeviceRaceOnlyThePrincipalWins` (in-memory, SQLDelight, file-backed) |
| S1.1-6a | in-memory conditional insert made unconditional | `InMemoryRegistrationRaceTest.n2SameAddressConflictingKeysHaveExactlyOneWinner` |
| S1.1-6b | SQLDelight `INSERT OR IGNORE` → `INSERT OR REPLACE` | `SqlDelight/FileBackedRegistrationRaceTest.n2SameAddressConflictingKeysHaveExactlyOneWinner` |
| S1.1-7 | v1 collision uses ordinary ID ordering against v2 | `SessionLifecycleTest.n3PendingV1CanNeverBlockIncomingV2AfterUpgrade`, `n3UnpinnedPendingV1IsReplacedByV2` |
| S1.1-8 | unanswered v1 session reused on send, retry and ACK | `n3PendingV1IsNeverRetransmittedAndItsLogicalMessageMovesToV2`, `n3BothPeersPendingV1ConvergeAfterUpgrade`, `n3AckIsNeverSentOverPendingV1`, `n3DiscardedV1InitiationCannotRevive` |
| S1.1-9 | established v1 sessions dropped as well | `preS1EstablishedSessionsKeepRatchetingAfterTheUpgrade`, `preS1PendingInitiationContinuesWhenTheResponderAcceptedItBefore`, `SecurityReviewRegressionTest.f9LocallyInitiatedLegacySessionNeverPinsTheLocalIdentity` |
| S1.1-10 | unpinned legacy session replaced by any identity | `sessionWithoutPinIsNeverReplacedByAnotherIdentity` |
| S1.1-11 | host failure logged with message and stack | `SecurityRemediationRoutesTest.n1HostFailuresLeakNoContext` |
| S1.1-12 | docs claim F7 closed | `checkReleaseConventions` since S1.2 (claim `f7-partial` and the F7 summary row) |
| S1.1-13 | Android `hasKeys()` limitation removed from the docs | `checkReleaseConventions` since S1.2 (claim `android-haskeys`) |
| S1.1-14 | pre-S1 registration audit warning removed | `checkReleaseConventions` since S1.2 (claim `pre-s1-audit`) |

Mutations 12–14 were guarded only by review in S1.1; S1.2 automated them
(see [Documentation guardrails](#documentation-guardrails)).

## S1.2 follow-up

The S1.1 re-review passed with residual risks and reported two more
findings, N4 and N5, plus documentation issues. S1.2 addresses exactly
those: an operator procedure, a tested SQL script, host-boundary hardening
and automated documentation checks. No new protocol, wire format, schema
(client 16, server 8), record type, HTTP path or public API; the
`checkKotlinAbi` baselines are unchanged.

### N5 — Pre-S1 cleanup left the attacker's recovery key authoritative

**Root cause.** The S1.1 guidance removed an unrecognized pre-S1 device's
rows and then told the operator to "cancel the reset and have the user
rotate or re-register the recovery key". Before S1, such a device could
register the user's offline recovery key (or rotate one in, or complete a
reset). Removing the device leaves that key ACTIVE, and the attacker holds
it: with it alone it can cancel the legitimate user's reset (public
R1-signed cancellation), obtain a last-device recovery challenge for any of
the user's devices and replace that device's authentication key, and so
regain same-user authority. A rotation needs the suspect key's own
signature, and re-registration is refused while a key is ACTIVE, so the
guidance could not remove it.

**Fix (documentation and verification; no code change).**
[operating-the-server.md](operating-the-server.md#pre-s1-cleanup) now
states that any unrecognized pre-S1 device makes the user's recovery-key
authority suspect, and prescribes an offline cleanup (server stopped,
backup, one `BEGIN IMMEDIATE … COMMIT` transaction, then a fresh key from a
legitimate device):

- device-scoped rows of each suspicious registration: `device_registration`,
  `authentication_nonce`, `device_prekey_state`, `available_one_time_prekey`,
  `consumed_one_time_prekey`, and `mailbox_message` rows addressed to it or
  sent as it;
- per affected user: `last_device_recovery_key_state` forced to REVOKED
  (`state = 2`, `public_key`/`installed_at` NULL, all transition IDs NULL,
  as the table CHECK requires) at `epoch + 1`; at `Long.MAX_VALUE` the
  script fails on the NOT NULL constraint and changes nothing (never wraps),
  and a documented manual variant revokes without an epoch change;
  `last_device_recovery_key_reset` and `last_device_recovery_challenge`
  rows of the user deleted;
- afterwards a legitimate device calls `createLastDeviceRecoveryKey()` and
  `registerLastDeviceRecoveryKey(r2)` (registration after revocation, M18/M19).

The audit now shows, besides addresses, each registration's current auth
public key, epoch, installation time and `recovery_id` / `rotation_id` /
`last_device_recovery_id`, the recovery key state with its public key and
transition IDs, pending resets with requester and key/epoch binding, and
outstanding challenges: **addresses alone are not enough**, because a
pre-S1 recovery may have put an attacker's key on a legitimate address.

**Tests** (`server:ktor` `PreS1CleanupTest`, file-backed SQLite at server
schema 8 with the real constraints, real clients over HTTP; the SQL is read
verbatim from the documentation page):

- `n5DeviceOnlyCleanupLeavesAttackerRecoveryAuthority` reproduces the
  finding: with only the device-scoped part, R1 still cancels the reset and
  takes over `alice/phone` through last-device recovery.
- `n5PreS1CleanupRevokesCompromisedRecoveryAuthority`: the device is gone,
  cannot authenticate, publish or re-register (the host now refuses), its
  bundle is not found; recovery key REVOKED at epoch 2; reset and challenges
  gone; the legitimate device's key, epoch, installation time, prekeys and
  nonces, Bob's state and the mailbox rows between legitimate devices are
  unchanged.
- `n5OldRecoveryKeyCannotRecoverAfterOfflineCleanup`: R1 cannot cancel or
  query the reset, get a challenge, or use the statement it signed before
  the cleanup; the phone's key stays.
- `n5LegitimateDeviceCanProvisionFreshRecoveryKeyAfterCleanup`: R2 becomes
  ACTIVE at epoch 3, new challenges carry recovery key epoch 3, R1 stays
  rejected, R2 recovers a device.
- `n5CleanupAtExhaustedEpochFailsClosedAndRollsBack`: at `Long.MAX_VALUE`
  the script aborts with nothing applied; the manual variant revokes, R1 is
  dead, and a new registration gets `EPOCH_EXHAUSTED`.
- `n5AuditQueriesRunOnSchemaV8`: the audit queries run and expose the
  attacker's key and the planted recovery key.

S1.3 replaced the in-page script by one script file with guards and
verification and narrowed its scope (N6, INFO-3); the N5 tests now run that
file with the `sqlite3` shell.

**Status:** CLOSED by the independent S1.2 re-review.

### N4 — Host errors bypassed the exception wrapper

**Root cause.** The authorizer call in `SecureMessageServer.registerDevice`
and the extractor call in the registration route caught `Exception` only.
An `AssertionError`, `NotImplementedError` or other `Error` from host code
reached Ktor's default handler, which logs the message and stack (and in
development mode can show them), although host failures may carry the
request's authentication context.

**Fix.** One policy at both host boundaries (`S/DeviceRegistrationAuthorizer.kt`
`runHostRegistrationBoundary`, `K/KSecureMessageRoutes.kt`
`runHostExtractionBoundary`, both `internal`):

- `CancellationException`: rethrown unchanged (coroutine cancellation).
- `VirtualMachineError`: rethrown unchanged in S1.2. That was too broad:
  host code can throw `InternalError` or `UnknownError` with its own
  message, and the class of a `CancellationException` is no proof of
  cancellation. S1.3 narrows both ([N7](#n7-host-thrown-cancellation-and-vm-errors-leaked-their-message)).
- every other `Throwable` (exceptions, `AssertionError`,
  `NotImplementedError`, `LinkageError`, …): wrapped in
  `DeviceRegistrationAuthorizationFailedException` (fixed message; the
  original is its `cause` for the host's own diagnostics). The route answers
  `500 {"error":"internal_error"}`, also in development mode, and logs
  `Registration authorization failed (<class name>)` without passing any
  throwable to the logger: no message, stack, cause chain or context.
  Nothing is registered.

**Tests:** `server:core` `DeviceRegistrationAuthorizationTest.n4AuthorizerErrorIsWrappedWithoutMessage`
(the S1.2 tests `n4CancellationIsRethrown`, `n4VirtualMachineErrorIsNotWrapped`
and `n4BoundaryPolicy` were replaced by the `n7…` tests of S1.3); `server:ktor` `SecurityRemediationRoutesTest.n4AuthorizerErrorLeaksNoMessageOrStack`,
`n4ExtractorErrorLeaksNoMessageOrStack` (`SECRET-A/B/C` in an
`IllegalStateException`, `NotImplementedError` and `AssertionError`,
development mode on: neither body nor log contains them, no throwable is
logged, nothing is registered; since S1.3 in development and production
mode, with the N7 cases added).

**Status:** FIXED — PENDING RE-REVIEW.

### Documentation guardrails

`checkReleaseConventions` (part of `check` and therefore of `build`) now
fails if a guarded security statement disappears. Each statement is a
marked region (`<!-- ksm-security-claim:<id> -->`) or an operator SQL block
(`<!-- ksm-sql:<id>:begin -->`) that must keep its required tokens:

| Claim | Page | Guarded content |
|---|---|---|
| `f7-partial` | this page | F7 is PARTIALLY FIXED — RESIDUAL RISK DOCUMENTED (never "CLOSED"), and so is the F7 summary row |
| `android-haskeys` | [storage-key-providers.md](storage-key-providers.md#haskeys-s1) | `AndroidStorageKeyProvider.hasKeys()` reads the wrapped key file, not the Keystore alias |
| `pre-s1-audit` | [operating-the-server.md](operating-the-server.md#registrations-from-before-s1) | pre-S1 registrations never host-authorized, audit, addresses alone are not enough, keys and transition IDs |
| `pre-s1-recovery-key-cleanup` | same | removing only the device is insufficient, key compromised, server stopped, one transaction, revocation, reset/challenge deletion, fresh key; never "rotate or re-register" |
| SQL `pre-s1-audit`, `pre-s1-cleanup` | same | every audited column; every cleanup statement, including the REVOKED update with its non-wrapping epoch |

The SQL blocks are additionally executed by `PreS1CleanupTest`.

### Stale statements corrected

- Client schema is 16, not 15 ([operating-the-server.md](operating-the-server.md#client-storage),
  `SqlDelightClientStorage` KDoc); the M25 page now says its schema versions
  were those at M25.
- The status wording at the top of this page matches the summary table
  (closed only by the independent re-review).
- `SecureMessageClient.registerDevice` KDoc no longer says the server trusts
  the first registration (host authorization since S1).
- Pre-S1 guidance in security-review.md, server-authentication.md,
  device-recovery.md and the README points to the recovery-key cleanup.

### S1.2 mutation testing

Each mutation was applied alone, the named test or check was run, and the
mutation was reverted (checksums compared).

| # | Mutation | Caught by |
|---|---|---|
| S1.2-1 | cleanup leaves the recovery key ACTIVE (UPDATE removed) | `PreS1CleanupTest` (4 tests), `checkReleaseConventions` |
| S1.2-2 | cleanup keeps the pending reset | `n5PreS1CleanupRevokesCompromisedRecoveryAuthority`, `n5OldRecoveryKeyCannotRecoverAfterOfflineCleanup`, `checkReleaseConventions` |
| S1.2-3 | cleanup keeps the challenges | `n5PreS1CleanupRevokesCompromisedRecoveryAuthority`, `checkReleaseConventions` |
| S1.2-4 | docs say "rotate or re-register" instead of revoke | `checkReleaseConventions` (forbidden phrase, missing `SET state = 2`), 3 `PreS1CleanupTest` tests |
| S1.2-5 | audit query omits the auth public key and transition IDs | `n5AuditQueriesRunOnSchemaV8`, `checkReleaseConventions` |
| S1.2-6 | authorizer boundary catches `Exception` only | `n4AuthorizerErrorIsWrappedWithoutMessage`, `n4BoundaryPolicy`, `n4AuthorizerErrorLeaksNoMessageOrStack` |
| S1.2-7 | extractor boundary catches `Exception` only | `n4ExtractorErrorLeaksNoMessageOrStack`, `n4CancellationIsRethrown` (route) |
| S1.2-8 | host failure logged with the throwable | `n1HostFailuresLeakNoContext`, `n4AuthorizerErrorLeaksNoMessageOrStack`, `n4ExtractorErrorLeaksNoMessageOrStack` |
| S1.2-9a | authorizer boundary wraps cancellation | `server:core` `n4CancellationIsRethrown`, `n4BoundaryPolicy` (end to end the route still rethrows a wrapped cancellation) |
| S1.2-9b | extractor boundary wraps cancellation | `server:ktor` `n4CancellationIsRethrown` |
| S1.2-10 | F7 claim region removed / F7 row says CLOSED | `checkReleaseConventions` |
| S1.2-11 | Android `hasKeys()` limitation removed | `checkReleaseConventions` |
| S1.2-12 | pre-S1 audit warning removed | `checkReleaseConventions` |
| S1.2-13 | fresh-recovery-key provisioning step removed | `checkReleaseConventions` |

## S1.3 follow-up

The S1.2 re-review passed with residual risks, closed N5 and reported two
LOW findings, N6 and N7, plus INFO-3 (cleanup side effects). S1.3 addresses
exactly those: internal server exception handling, the operator script and
documentation, tests and release checks. No protocol, wire format, schema
(client 16, server 8), record type, HTTP path, crypto domain or public API
change; the `checkKotlinAbi` baselines are unchanged.

### N6 — Pre-S1 cleanup not robust against operator mistakes

**Root cause.** Two independent ones. (1) The page said to open the
database with the `sqlite3` shell and run the script. Pasted into the
interactive prompt, `.bail on` has no effect: the shell continues after a
failed statement, and the script's `COMMIT` then commits whatever ran
(`n6InteractiveExecutionCommitsPartialCleanupRootCause` reproduces it with
`sqlite3 -interactive`). (2) A listed device that does not exist (a typo,
`alice/evl` for `alice/evil`) matched no row: the script "succeeded",
revoked the user's recovery key and left the attacker's device registered.

**Fix.**

- One executable source of truth:
  [`operator/ksecuremessage-pre-s1-cleanup.sql`](operator/ksecuremessage-pre-s1-cleanup.sql),
  shown in the page by inclusion (no copy), run by the tests.
- One supported invocation, `sqlite3 -bail /path/to/server.db <
  ksecuremessage-pre-s1-cleanup.sql`; the page forbids interactive pasting
  and says why.
- Guards inside the transaction, after the input and before the first
  `DELETE`/`UPDATE`, as named `CHECK` constraints of a temporary table:
  `server_schema_is_version_8`, `at_least_one_device_listed` (the unedited
  file is refused), `every_listed_device_is_registered`,
  `no_unlisted_exhausted_epoch`,
  `every_exhausted_user_is_listed_active_and_exhausted`; duplicates fail on
  the input table's primary key. Any failure: non-zero exit, rollback,
  nothing changed.
- Recovery keys: only ACTIVE rows are revoked (`WHERE state = 1`), so an
  already REVOKED user is unchanged (idempotent); several devices of one
  user cause one transition. The no-epoch-change variant for an exhausted
  epoch applies only to users the operator lists in `ksm_exhausted_user`
  (no hand-edited `UPDATE` any more); all others get epoch + 1.
- Post-cleanup verification in the same run (the same list, nothing typed
  twice): one `name|violations` line per check, a `CHECK` that fails the
  run on any violation, and the final line
  `ksm-pre-s1-cleanup: verification passed`; the page additionally requires
  re-running the audit in a fresh session before the restart.

**Tests** (`server:ktor` `PreS1CleanupTest`, the real `sqlite3` binary with
the documented command; the test fails, never skips, if `sqlite3` is not on
`PATH`; every failure case compares a snapshot of every server table):
`n6MissingListedDeviceAbortsWithoutChanges`,
`n6DuplicateListedDeviceAbortsWithoutChanges`, `n6EmptyCleanupIsRejected`
(also the file as shipped), `n6CleanupFailureRollsBackEverything` (a
failing statement just before `COMMIT`), `n6SchemaGuardRejectsAnotherServerSchema`,
`n6ExhaustedEpochAbortsUnlessListed`, `n6ListingANonExhaustedUserAsExhaustedAborts`,
`n6ExhaustedEpochPathAffectsOnlyListedUsers` (REVOKED, epoch stays
`Long.MAX_VALUE`, R1 dead, `EPOCH_EXHAUSTED` afterwards; another user in the
same run gets epoch + 1), `n6MultipleDevicesOfOneUserIncrementEpochOnce`,
`n6MultipleUsersRemainIsolated`, `n6AlreadyRevokedUserIsUnchanged`,
`n6VerificationOutputReportsZeroViolations`, `n6VerificationFailsLoudly`,
`n6GuardRunsBeforeFirstDestructiveStatement`,
`n6OperatorPageDocumentsExactlyTheTestedInvocation` and
`n6InteractiveExecutionCommitsPartialCleanupRootCause`. The N5 tests run the
same file.

**Status:** FIXED — PENDING RE-REVIEW.

### INFO-3 — Cleanup side effects

The cleanup removes **authority and reachability, not history**:

- `consumed_one_time_prekey` is kept. Deleting it let a legitimate device
  returning to a known address publish a one-time prekey ID that had
  already been handed out, and the server handed it out again. Publication
  skips consumed IDs, so keeping the tombstones never blocks a returning
  device (its `device_prekey_state` is deleted, so it may publish a new
  identity key).
- `mailbox_message` rows **sent as** a listed address are kept, for a
  wholly malicious address as for a known one: they are opaque ciphertext
  that confers no authority, end-to-end authenticity is decided by the
  recipient's session and identity trust, and a known address may have
  legitimate envelopes in flight. Rows **addressed to** a listed
  registration are deleted (the invalidated device instance); senders
  resend pending messages.
- `device_registration`, `authentication_nonce`, `device_prekey_state` and
  `available_one_time_prekey` of listed registrations, and the recovery key
  state, reset and challenges of affected users, are handled as before.

**Tests:** `info3ConsumedOneTimePreKeyIdIsNotReissued` (a one-time prekey
of `alice/phone` handed to Bob, cleanup, the phone re-registers under host
authorization and publishes again: the consumed ID is never handed out
again) and `info3KnownAddressWithAttackerKeyCanReturn` (the attacker took
over `alice/phone` with R1 before S1: after the cleanup the attacker's key
is not registered, the recovery key is REVOKED, the phone's earlier
envelope to Bob is delivered, envelopes to the phone are gone, the phone
re-registers its own key with the host's authorization, publishes, never
re-issues a consumed ID and provisions a fresh recovery key at epoch 3);
`n5PreS1CleanupRevokesCompromisedRecoveryAuthority` checks the kept
tombstones and sent-as envelopes of `alice/evil`.

### N7 — Host-thrown cancellation and VM errors leaked their message

**Root cause.** Both host boundaries rethrew every `CancellationException`
and every `VirtualMachineError` unchanged, and the route's failure handler
rethrew a `CancellationException` cause. Host code can throw
`CancellationException("…")` while its coroutine is still active, or
`InternalError("…")`; Ktor then handled an uncaught throwable, and on a
real CIO engine its message could become the 500 body and appear in the
log. The class alone is no proof of cancellation or of a JVM condition.

<!-- ksm-security-claim:host-boundary-throwables -->
**Fix (N7).** One policy, implemented as `classifyHostFailure`
(`S/DeviceRegistrationAuthorizer.kt`, used by `runHostRegistrationBoundary`)
and mirrored as `classifyExtractionFailure` (`K/KSecureMessageRoutes.kt`,
used by `runHostExtractionBoundary`): sharing one function across the two
modules would make it public API, so both are `internal` and tested to
classify every throwable identically:

- genuine coroutine cancellation (a `CancellationException` while the
  calling coroutine is no longer active): propagates unchanged, preserving
  structured concurrency; KSecureMessage neither answers nor logs it;
- `OutOfMemoryError` and `StackOverflowError`: process-health failures,
  propagate unchanged and are never turned into an ordinary HTTP answer.
  KSecureMessage does not sanitize their message, and what the engine does
  with them after they leave its boundary is outside its control;
- everything else is sanitized: a `CancellationException` thrown while the
  coroutine is still active (also with a secret cause), `InternalError`,
  `UnknownError`, other `VirtualMachineError`s, `LinkageError` and every
  other `Throwable` are wrapped in `DeviceRegistrationAuthorizationFailedException`
  (fixed message) and answered `500 {"error":"internal_error"}`, logged by
  class name only, with nothing registered.
<!-- /ksm-security-claim:host-boundary-throwables -->

The route's failure handler no longer rethrows a `CancellationException`
cause: the boundaries hand it only failures they sanitized.

**Tests:** `server:core` `DeviceRegistrationAuthorizationTest.n7SyntheticCancellationAndHostVmErrorsAreSanitized`,
`n7RealCancellationPropagates` (the authorizer cancels its own coroutine:
the job ends cancelled, the cancellation is not wrapped, nothing is
registered), `n7FatalVmErrorPolicyIsPreserved` (plain `OutOfMemoryError` /
`StackOverflowError` objects; nothing is exhausted), `n7BoundaryPolicy`;
`server:ktor` `SecurityRemediationRoutesTest.n4AuthorizerErrorLeaksNoMessageOrStack`
and `n4ExtractorErrorLeaksNoMessageOrStack` (now also synthetic
cancellation, cancellation with a `SECRET-CAUSE`, `InternalError`,
`UnknownError`, in development and production mode),
`n7RealCancellationPropagates`, `n7ExtractorAndAuthorizerClassifyIdentically`,
`n1HostFailuresLeakNoContext`; and on a real CIO engine (not the test host)
`HostBoundaryCioTest.n7ExtractorFailuresAreSanitizedOnCio` /
`n7AuthorizerFailuresAreSanitizedOnCio` (development mode off and on: body
exactly `{"error":"internal_error"}`, no secret in body or log).

**Status:** FIXED — PENDING RE-REVIEW.

### S1.3 documentation guardrails

`checkReleaseConventions` additionally guards:

| Claim | Where | Guarded content |
|---|---|---|
| `pre-s1-recovery-key-cleanup` | [operating-the-server.md](operating-the-server.md#pre-s1-cleanup) | the exact script command, "Do not paste the cleanup statements interactively", why, the guards, mandatory post-cleanup verification, restart only afterwards; forbids "open the database with the sqlite3 shell", "paste into", a hand-edited `UPDATE` |
| SQL `pre-s1-cleanup-script` | same | the page includes the script file, holds no copy of its statements |
| `pre-s1-cleanup` | the script file | `.bail on`, transaction, input table keys, every guard, every statement, verification; forbids deleting tombstones or envelopes sent as a cleaned address; the guard runs after the input and before the first `DELETE`/`UPDATE` |
| `pre-s1-audit` | operating-the-server.md | also: an address alone never clears a registration whose key cannot be established as legitimate |
| `host-boundary-throwables` | operating-the-server.md, this page | genuine cancellation propagates, active cancellation, `InternalError`, `UnknownError` sanitized, OOM/SOE policy; no page may attribute a throwable's message to the JVM |

### S1.3 mutation testing

Each mutation was applied alone, the named test or check was run, and the
mutation was reverted (checksums compared).

| # | Mutation | Caught by |
|---|---|---|
| S1.3-1 | device-existence guard removed from the script | `n6MissingListedDeviceAbortsWithoutChanges`, `n6InteractiveExecutionCommitsPartialCleanupRootCause`, `checkReleaseConventions` (after this run the guard's subquery became a required token) |
| S1.3-2 | guard moved after the first destructive `DELETE` | `checkReleaseConventions` (order), `n6GuardRunsBeforeFirstDestructiveStatement` and 15 more `PreS1CleanupTest` tests (the guard then refuses every run) |
| S1.3-3 | page allows pasting into the sqlite3 prompt | `checkReleaseConventions`, `n6OperatorPageDocumentsExactlyTheTestedInvocation` |
| S1.3-4 | post-cleanup verification removed from the script | `n6VerificationOutputReportsZeroViolations`, `n6VerificationFailsLoudly`, `n6ExhaustedEpochPathAffectsOnlyListedUsers`, `checkReleaseConventions` |
| S1.3-5 | consumed one-time prekey tombstones deleted again | `info3ConsumedOneTimePreKeyIdIsNotReissued`, `info3KnownAddressWithAttackerKeyCanReturn`, `n5PreS1CleanupRevokesCompromisedRecoveryAuthority`, `checkReleaseConventions` |
| S1.3-6 | envelopes sent as a cleaned address deleted again | `n5PreS1CleanupRevokesCompromisedRecoveryAuthority`, `info3KnownAddressWithAttackerKeyCanReturn`, `checkReleaseConventions` |
| S1.3-7 | no-epoch-change revocation applied to every affected user | `n6ExhaustedEpochPathAffectsOnlyListedUsers`, `checkReleaseConventions` |
| S1.3-8 | every `CancellationException` rethrown (both boundaries) | `server:core` `n7BoundaryPolicy`, `n7SyntheticCancellationAndHostVmErrorsAreSanitized`; `server:ktor` `n4…LeaksNoMessageOrStack` (2), `HostBoundaryCioTest` (2) |
| S1.3-9 | synthetic cancellation logged with its throwable | `n4AuthorizerErrorLeaksNoMessageOrStack`, `n4ExtractorErrorLeaksNoMessageOrStack`, `HostBoundaryCioTest` (2) |
| S1.3-10 | every `VirtualMachineError` rethrown (both boundaries) | as S1.3-8 |
| S1.3-11 | `InternalError` bypasses sanitization (both boundaries) | as S1.3-8 |
| S1.3-12 | extractor boundary classifies differently from the authorizer boundary | `n7ExtractorAndAuthorizerClassifyIdentically`, `n4ExtractorErrorLeaksNoMessageOrStack`, `HostBoundaryCioTest.n7ExtractorFailuresAreSanitizedOnCio` |
| S1.3-13 | genuine cancellation wrapped into a 500 (both boundaries) | `server:core` `n7RealCancellationPropagates`, `n7BoundaryPolicy`; `server:ktor` `n7RealCancellationPropagates` |
| S1.3-14 | host failure text logged | `n1HostFailuresLeakNoContext`, `n4…LeaksNoMessageOrStack` (2) |
| S1.3-15 | script-only warning removed from the page | `checkReleaseConventions`, `n6OperatorPageDocumentsExactlyTheTestedInvocation` |
| S1.3-16 | missing-device guard removed from script and page | `n6MissingListedDeviceAbortsWithoutChanges`, `n6InteractiveExecutionCommitsPartialCleanupRootCause`, `checkReleaseConventions` |
| S1.3-17 | post-cleanup verification step removed from the page | `checkReleaseConventions` |

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
- A v1 initiation the peer never accepted is rejected. Since S1.1 the
  initiator never sends its unanswered v1 initiation again: the next send
  or retry starts a v2 session, and an incoming v2 initiation always
  replaces it (finding N3). A peer's reply on a v1 initiation it accepted
  before upgrading still completes it.
- A pre-S1 peer cannot decode type `0x03`, and a pre-S1 client cannot submit
  to an S1 server. **Upgrade servers and clients together.** There is no
  automatic v1 fallback that a relay could force.
- Servers: construct `SecureMessageServer` with a `DeviceRegistrationAuthorizer<C>`
  and pass a `DeviceRegistrationContextExtractor<C>` to `kSecureMessageRoutes`
  (S1.1); migrate the server database to schema 8 before `open`; audit
  registrations from before S1 (see the checklist in
  [operating-the-server.md](operating-the-server.md#upgrade-checklist-s1-s11)).
- Clients: pending messages of a device without its device authentication
  key cannot be submitted (they stay pending).

## Public API changes

S1.1 (deliberate, breaking; `checkKotlinAbi` baselines updated):

- `server:core`: `DeviceRegistrationAuthorizer` → `DeviceRegistrationAuthorizer<in C : Any>`
  with `authorize(context: C, request)`; `SecureMessageServer` →
  `SecureMessageServer<C : Any>`; `registerDevice(context: C?, registration,
  body, authentication)`; `DeviceRegistrationAuthorizationRequest(address,
  proposedAuthenticationPublicKey)` (no `userState`);
  `DeviceRegistrationUserState` removed; new
  `DeviceRegistrationAuthorizationFailedException`.
- `server:ktor`: new `DeviceRegistrationContextExtractor<out C : Any>`;
  `kSecureMessageRoutes(server: SecureMessageServer<C>, registrationContext)`.
- `storage:core`: `DeviceRegistrationRepository.hasRegisteredDevices` removed.
- `client:core`: no public API change (N3 is internal session policy).

S1:

- `server:core`: new `DeviceRegistrationAuthorizer`,
  `DeviceRegistrationAuthorizationRequest`, `DeviceRegistrationUserState` (removed in S1.1),
  `DeviceRegistrationAuthorizationResult`, `EnvelopeSenderMismatchException`;
  `SecureMessageServer(storage, clock, deviceRegistrationAuthorizer,
  recoveryKeyResetPolicy = null)` (clock no longer defaulted);
  `relay(device, envelope)`; `ProtectedEndpoint.SEND_MESSAGE`,
  `ProtectedEndpoint.path(address)`.
- `storage:core`: `DeviceRegistrationRepository.hasRegisteredDevices` (removed in S1.1),
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
- A finding is closed only by the independent re-review (the CLOSED rows);
  N1–N4, N6, N7 and D1–D7 are pending it.
- Legacy: v1 initiations not answered before the upgrade are replaced by v2
  (their messages resent by the reliability layer); peers and servers must
  be upgraded together; `StaticStorageKeyProvider` cannot migrate milestone
  8 databases.
- Registrations from before S1 were never host-authorized and keep their
  authority, and any offline recovery key they planted, until the operator
  audits them and runs the offline cleanup (D3, N5). A server whose
  operator skips the cleanup keeps that exposure.
- The operator is responsible for auditing pre-S1 state and running the
  cleanup correctly (N6 makes mistakes fail closed, it cannot choose the
  suspicious registrations).
- `OutOfMemoryError` and `StackOverflowError` from host code propagate
  unsanitized (N7); KSecureMessage cannot control what happens after a
  process-health failure leaves its boundary.
- The server's wall clock is a security input (freshness windows, challenge
  expiry, reset delay).
- F7: intent replay and provider-state trust (see F7), accepted for v0.x.
- The correctness of the host's context extractor and authorizer (N1).
