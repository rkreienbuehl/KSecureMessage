# Security review guide

Material for an external security reviewer. **R1 is not an independent
security audit, and KSecureMessage has not been audited.** Nothing here
claims otherwise.

A first review produced nine findings (F1–F9); S1 addresses them. The
re-review packet with root causes, changed files, invariants and test names
is [security-review-remediation.md](security-review-remediation.md). Every
finding stays **FIXED — PENDING RE-REVIEW** until an independent reviewer
has checked it.

KSecureMessage is Signal-style secure messaging: it uses the X3DH and Double
Ratchet primitives of [Kodium](https://github.com/LivotovLabs/kodium), with
KSecureMessage-specific wire, storage, authentication and recovery protocols.
It is **not** Signal, not wire-compatible with Signal/libsignal, not formally
verified, and does not implement sealed sender.

Paths below are relative to the repository root. `P` = `core/protocol/src/commonMain/kotlin/dev/kreienbuehl/ksecuremessage/protocol`,
`C` = `client/core/src/commonMain/kotlin/dev/kreienbuehl/ksecuremessage/client`,
`S` = `server/core/src/main/kotlin/dev/kreienbuehl/ksecuremessage/server`,
`E` = `storage/encryption/src/commonMain/kotlin/dev/kreienbuehl/ksecuremessage/storage/encryption`,
`Q` = `storage/client/sqldelight/src/commonMain/kotlin/dev/kreienbuehl/ksecuremessage/storage/client/sqldelight`.

## Threat model summary

Assumptions and non-goals, collected from the specifications in `docs/`:

- **Server trust.** The server is trusted for availability, routing and
  server-authoritative metadata (key installation times, recovery key
  epochs, reset `eligibleAt`, one-time prekey hand-out). It is not trusted
  with message content: it relays opaque envelopes and must never hold
  client private messaging keys, ratchet state, device authentication
  private keys or offline recovery keys. A malicious server can withhold,
  delay, drop or replay envelopes (clients deduplicate by logical ID), hand
  out stale prekeys, and see all metadata.
- **Metadata is visible to the server**: sender and recipient addresses,
  envelope IDs, sizes, timing, protocol version. No sealed sender, no
  metadata privacy, no anonymity.
- **Identity trust is TOFU** ([identity-trust.md](identity-trust.md)): the
  first accepted identity key per device address is pinned. A server that
  substitutes keys at first contact is detected only by **manual safety
  number verification** ([identity-verification.md](identity-verification.md)).
  A changed key fails closed (`IdentityChanged`) until the user accepts it.
- **Server authentication** ([server-authentication.md](server-authentication.md))
  binds a dedicated Ed25519 device key to a device address. It is not
  account authentication: since S1 every first registration needs the host
  application's `DeviceRegistrationAuthorizer`, which since S1.1 decides
  with the host's own authenticated principal for the request, and all
  "same-user device" authority (device recovery, offline recovery key and
  reset) rests on that host decision. Registrations stored before S1 were
  never host-authorized, and a malicious one may have planted an offline
  recovery key that outlives it: the operator audits them and runs the
  offline cleanup, which also revokes the affected users' recovery keys
  ([operating-the-server.md](operating-the-server.md#registrations-from-before-s1), S1.2). Message submission is signed by the sender (the server
  vouches for the envelope's sender). Requests are signed over a canonical binary description (domain
  `KSecureMessage-ServerAuth-v1`), fresh within ±5 minutes, single-use per
  nonce and device. It authenticates requests, not responses; TLS is the
  host's job.
- **Replay** of signed requests is prevented by atomic nonce claims within
  the freshness window, with a monotonic prune watermark so no interleaving
  of callers can prune a nonce that is still acceptable (S1); recovery and rotation statements carry their own
  nonces or single-use challenges. Restoring an old server database reopens
  replay and rollback ([operating-the-server.md](operating-the-server.md#backups-of-the-server-database)).
- **Device authentication recovery**: another registered device of the same
  user ([device-recovery.md](device-recovery.md)); routine rotation with the
  current key ([device-authentication-rotation.md](device-authentication-rotation.md));
  last-device recovery with an **offline recovery key** held by the user
  ([last-device-recovery.md](last-device-recovery.md)). None of them
  recover or change the messaging identity. Anyone holding the offline key
  can take over the server credentials of that user's devices.
- **Recovery key authority** ([recovery-key-lifecycle.md](recovery-key-lifecycle.md)):
  rotation and revocation need a registered device **and** the current
  offline key.
- **Delayed reset weakness** ([recovery-key-reset.md](recovery-key-reset.md)):
  a lost offline key is replaced after a host-chosen delay by any registered
  device of the user. A compromised device whose reset nobody cancels during
  the delay wins. There is no push notification, quorum or second factor.
- **Client storage** ([storage-encryption.md](storage-encryption.md)):
  record-level AES-256-GCM protects a copied database without the storage
  key. Since S1 an encrypted database cannot be pushed back through the
  plaintext migration by editing its format marker. It does not protect
  against database **and** key, a compromised running process, metadata
  analysis, rollback of the database file to an older encrypted copy, or
  plaintext remnants from before milestone 9 in SQLite pages.
- **Session initiation** ([session-lifecycle.md](session-lifecycle.md)):
  since S1 every new initiation is version 2; its transcript authenticates
  both addresses and every header field before anything is pinned or
  retired. Sessions from before S1 keep their version 1 associated data.
- **Application commit semantics** ([application-delivery.md](application-delivery.md),
  [message-discard.md](message-discard.md)): an ACK means the receiving
  application durably committed or discarded the message. Delivery is at
  least once; there are **no exactly-once application side effects**.
- **Abandon** ([outbound-message-lifecycle.md](outbound-message-lifecycle.md))
  is local; it is not a recall. Discard reasons are never sent.
- **Wall clock**: freshness windows, installation times, challenge expiry
  and reset delays depend on synchronized wall clocks on server and client.

## Review checklist

| Topic | Look at | Tests | Spec |
|---|---|---|---|
| X3DH integration (Kodium behind `ProtocolEngine`, bundle verification, OTPK handling) | `P/KodiumProtocolEngine.kt`, `P/ProtocolEngine.kt`, `P/ProtocolConstants.kt` | `KodiumProtocolEngineTest`, `KodiumProtocolEngineIntegrationTest` | [wire-format.md](wire-format.md) |
| Double Ratchet state persistence (atomic with crypto, session state format v3) | `P/SessionState.kt`, `C/SecureMessageClient.kt` (`storage.transaction` around encrypt/decrypt) | `MessageReliabilityAtomicityTest`, `FirstContactAtomicityTest`, `SqlDelightPersistenceTest` | [storage.md](storage.md) |
| Domain separation (every signature/hash has its own domain string) | `P/DeviceAuthentication.kt`, `P/DeviceRecovery.kt`, `P/DeviceAuthenticationRotation.kt`, `P/LastDeviceRecovery.kt`, `P/RecoveryKeyLifecycle.kt`, `P/RecoveryKeyReset.kt`, `P/SafetyNumber.kt`, `P/SessionInitiationId.kt`, `P/ApplicationMessageDigest.kt` | `*domainsAreDistinct*` in `RecoveryKeyLifecycleTest`, `RecoveryKeyResetTest`; frozen vectors in each protocol test | per-feature docs |
| Signature verification (registered key, never a request-supplied key; PoP) | `S/DeviceAuthenticator.kt`, `S/DeviceRecoveryService.kt`, `S/DeviceAuthenticationRotationService.kt`, `S/LastDeviceRecoveryService.kt`, `S/RecoveryKeyLifecycleService.kt`, `S/RecoveryKeyResetService.kt` | `DeviceAuthenticationServerTest`, `*ServerTest` | [server-authentication.md](server-authentication.md) |
| Associated data (storage AD, ratchet AD) | `E/EncryptedRecordFormat.kt`, `E/ClientRecordCipher.kt` | `StorageCipherTest`, `ClientRecordCipherTest` | [storage-encryption.md](storage-encryption.md) |
| Session initiation (v2 transcript, S1), collision, replacement, stale initiations | `C/SecureMessageClient.kt` (`receivePreKeyMessage`), `P/SessionInitiationId.kt`, `P/KodiumProtocolEngine.kt` | `SessionLifecycleTest`, `SessionReplacementAtomicityTest`, `SessionInitiationIdTest`, `SessionInitiationV2Test`, `SecurityReviewRegressionTest`, `MessageCollisionRecoveryTest` | [session-lifecycle.md](session-lifecycle.md) |
| TOFU transitions (pin after accept, never replace from messages) | `C/RemoteIdentityTrust.kt`, `C/SecureMessageClient.kt` (`acceptRemoteIdentityChange`) | `RemoteIdentityTrustTest`, `IdentityChangeAcceptanceTest` | [identity-trust.md](identity-trust.md) |
| Safety number construction | `P/SafetyNumber.kt` | `SafetyNumberTest` (frozen vectors), `IdentityVerificationTest` | [identity-verification.md](identity-verification.md) |
| ServerAuth canonicalization (exact body bytes, canonical paths) | `P/DeviceAuthentication.kt` (`ServerRequestAuthentication`, `ServerApiPaths`), `server/ktor/.../KSecureMessageRoutes.kt` | `ServerRequestAuthenticationTest`, `AuthenticatedRoutesTest` | [server-authentication.md](server-authentication.md) |
| Nonce and replay handling (prune watermark, S1) | `S/DeviceAuthenticator.kt`, `storage/server/sqldelight/.../SqlDelightServerStorage.kt`, `storage/server/inmemory/.../InMemoryServerStorage.kt` | `AuthenticationNonceRepositoryContractTest`, `NonceLifetimeServerTest`, `SqlDelightServerPersistenceTest` | [server-authentication.md](server-authentication.md) |
| Device auth recovery | `S/DeviceRecoveryService.kt`, `C/SecureMessageClient.kt` (`prepare/complete…Recovery`) | `DeviceRecoveryTest`, `DeviceRecoveryServerTest`, `DeviceAuthenticationRecoveryTest`, `DeviceRecoveryRepositoryContractTest` | [device-recovery.md](device-recovery.md) |
| Device auth rotation | `S/DeviceAuthenticationRotationService.kt`, `C/DeviceAuthenticationRotationPolicy.kt` | `DeviceAuthenticationRotationTest`, `DeviceAuthenticationRotationServerTest`, `DeviceAuthenticationRotationRepositoryContractTest` | [device-authentication-rotation.md](device-authentication-rotation.md) |
| Last-device recovery | `S/LastDeviceRecoveryService.kt`, `P/LastDeviceRecovery.kt` | `LastDeviceRecoveryTest` (both), `LastDeviceRecoveryServerTest`, `LastDeviceRecoveryRepositoryContractTest` | [last-device-recovery.md](last-device-recovery.md) |
| Recovery key rotation and revocation | `S/RecoveryKeyLifecycleService.kt`, `P/RecoveryKeyLifecycle.kt` | `RecoveryKeyLifecycleTest`, `RecoveryKeyLifecycleServerTest`, `RecoveryKeyLifecycleRepositoryContractTest` | [recovery-key-lifecycle.md](recovery-key-lifecycle.md) |
| Delayed reset | `S/RecoveryKeyResetService.kt`, `P/RecoveryKeyReset.kt`, `C/RecoveryKeyResetAwareness.kt` | `RecoveryKeyResetTest`, `RecoveryKeyResetServerTest`, `RecoveryKeyResetAwarenessTest`, `RecoveryKeyResetRepositoryContractTest` | [recovery-key-reset.md](recovery-key-reset.md) |
| Storage encryption (AES-GCM, fresh nonces, fail closed, no trial decryption) | `E/AesGcm.kt`, `E/EncryptedRecordFormat.kt`, `Q/SqlDelightClientStorage.kt` | `StorageCipherTest`, `SqlDelightEncryptionTest` | [storage-encryption.md](storage-encryption.md) |
| Platform key providers | `storage/keyprovider/android/...`, `storage/keyprovider/apple/...` | `StorageKeyProviderContractTest`, `AndroidStorageKeyProviderTest`, `DataProtection*Test` (keychain host) | [storage-key-providers.md](storage-key-providers.md) |
| Storage key rotation | `storage/rotation/core/.../StorageKeyRotationManager.kt`, `Q/SqlDelightStorageKeyRotationBackend.kt` | `StorageKeyRotationManagerTest`, `StorageKeyRotationTest` | [storage-key-rotation.md](storage-key-rotation.md) |
| SQL migrations (client v16, server v8) | `storage/client/sqldelight/src/commonMain/sqldelight/`, `storage/server/sqldelight/src/main/sqldelight/`, `Q/LegacyPlaintextMigration.kt` | `SqlDelightMigrationTest`, `SqlDelightServerMigrationTest` (frozen schema fixtures) | [storage.md](storage.md), [server-storage.md](server-storage.md) |
| Transaction boundaries (no network I/O inside transactions) | `C/SecureMessageClient.kt`, `Q/SqlDelightClientStorage.kt` | `*AtomicityTest`, `SqlDelightServerRollbackTest` | [storage.md](storage.md) |
| Registration authorization and signed submission (S1) | `S/DeviceRegistrationAuthorizer.kt`, `S/SecureMessageServer.kt` (`registerDevice`, `relay`), `server/ktor/.../KSecureMessageRoutes.kt` | `DeviceRegistrationAuthorizationTest`, `SecurityRemediationRoutesTest`, `DeviceAuthenticationServerTest` | [server-authentication.md](server-authentication.md) |
| Storage downgrade (S1) | `Q/SqlDelightClientStorage.kt` (`openLegacyPlaintext`), `Q/LegacyPlaintextMigration.kt` | `StorageDowngradeTest`, `SqlDelightMigrationTest` | [storage-encryption.md](storage-encryption.md#downgrade-protection) |
| Log injection (S1) | `server/ktor/.../LogSanitizer.kt` | `LogInjectionTest` | [operating-the-server.md](operating-the-server.md) |
| Secret logging / `toString` (redacted keys) | `P/LocalKeys.kt`, `P/LastDeviceRecovery.kt`, `E/StorageKeys.kt`, `C/RecoveryKeyLifecycle.kt` | — (manual review) | — |
| Constant-time comparisons | `C/SecureMessageClient.kt` (`constantTimeEquals`); signature checks inside Kodium | `ApplicationDeliveryTest` | [application-delivery.md](application-delivery.md) |
| Failure rollback | `ClientStorage.transaction` implementations | `ClientStorageContractTest`, `*AtomicityTest`, `SqlDelightServerRollbackTest` | [storage.md](storage.md) |
| ACK / finalization semantics | `C/SecureMessageClient.kt` (`decrypt`, `commitReceivedMessage`, `discardReceivedMessage`) | `ApplicationDeliveryTest`, `MessageDiscardTest`, `MessageReliabilityTest` | [application-delivery.md](application-delivery.md), [message-discard.md](message-discard.md) |
| Pending, discard and abandon handling | `C/SecureMessageClient.kt`, `C/ReliableMessages.kt` | `MessageAbandonTest`, `MessageDiscardTest`, `ClientStorageContractTest` | [outbound-message-lifecycle.md](outbound-message-lifecycle.md) |

## Known limitations and open points

- **Not audited.** Kodium's own implementation of X25519/Ed25519, X3DH and
  the Double Ratchet is a dependency and has its own review status.
- **JS/Wasm**: see [supported-platforms.md](supported-platforms.md). The
  Kotlin/JS runtime of Kodium is slow (seconds per signature); Kodium's
  randomness dependency does not work on Wasm under Node.js.
- Several public model classes expose `ByteArray` properties without copying
  (`EncryptedEnvelope.payload`, prekey classes, `SecureSession.state`,
  `LocalIdentity` and other key pairs, plaintext in `PendingMessage` and
  `ReceivedMessage`). Callers must not mutate them. Some of them hold secret
  material; applications must not log or persist them.
- `explicitApi()` is not enabled; the public surface is tracked by the ABI
  baseline (`checkKotlinAbi`) instead.
- SQLDelight-generated database classes (`…sqldelight.db`) are public in the
  JVM/klib ABI because SQLDelight cannot generate internal code; they are
  excluded from the API baseline and are not API.
- `@InternalKSecureMessageApi` declarations (codecs, sealed-record helpers,
  rotation machinery) are public for module wiring only.
- Server database is unencrypted and has no rollback protection.
- No rate limiting or abuse protection in the reference server.

## Reporting

See [Security reporting](security-reporting.md).
