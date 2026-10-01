# Changelog

Public release notes of KSecureMessage, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
the 0.x policy in [docs/releasing.md](https://github.com/rkreienbuehl/KSecureMessage/blob/main/docs/releasing.md)
(the public API may change between minor versions; frozen wire, storage and
protocol formats change only through explicit new format versions).
Engineering milestone history is in
[docs/project-history.md](https://github.com/rkreienbuehl/KSecureMessage/blob/main/docs/project-history.md).

## [0.1.0] - 2026-10-01

First public release. Coordinates: group `dev.kreienbuehl.ksecuremessage`,
artifact `ksecuremessage-<module path>` (for example
`ksecuremessage-client-core`), version `0.1.0`.

### Added

- **Kotlin Multiplatform secure messaging core** (`core:model`,
  `core:protocol`, `client:core`): JVM, Android, iOS, macOS, Linux x64,
  Windows x64 and JS targets; see
  [supported platforms](https://github.com/rkreienbuehl/KSecureMessage/blob/main/docs/supported-platforms.md)
  for which are tested and which are compile-only (Wasm is compile-only,
  its runtime is blocked upstream).
- **Session establishment** with an X3DH-style key agreement over signed
  and one-time prekeys, session initiation v2 whose transcript
  authenticates both device addresses, session replacement, simultaneous
  initiation resolution and replay protection for initiations.
- **Double Ratchet messaging** through Kodium's primitives, kept behind
  `ProtocolEngine`; Kodium is an implementation detail and not part of the
  public API.
- **Explicit binary wire format** (ciphertext format v1, secure payload and
  ACK frames v1) frozen by test vectors. Not compatible with Signal or
  libsignal.
- **Identity trust**: trust on first use per device address, fail-closed
  identity changes with explicit acceptance, safety numbers and manual
  verification.
- **Reliable logical messages**: pending outbound messages, encrypted ACKs,
  retries, inbound deduplication, an explicit application commit or discard
  boundary (an ACK means the receiving application durably finalized the
  message; delivery is at least once), and cursor-paginated pending inbound
  and outbound messages with explicit abandon.
- **Client storage**: in-memory (tests/examples) and SQLDelight storage
  with record-level AES-256-GCM encryption, explicit storage key rotation,
  and platform storage key providers for Android (Keystore) and Apple
  platforms (Keychain).
- **Server**: `SecureMessageServer` as a blind relay with prekey
  publication and atomic one-time prekey hand-out, in-memory and
  persistent SQLite (SQLDelight, JVM) server storage.
- **Device authentication towards the server**: dedicated Ed25519 device
  keys, signed requests with replay protection, device registration that
  requires the host application's `DeviceRegistrationAuthorizer`, signed
  message submission.
- **Device authentication key lifecycle**: recovery by another device of
  the same user, routine rotation with a key-age policy, last-device
  recovery with an offline recovery key, offline recovery key rotation,
  revocation and a delayed, cancellable reset, plus read-only health and
  reset awareness queries.
- **Ktor adapters**: HTTP API v1 client transport (`client:ktor`) and
  server routes (`server:ktor`).

### Security

- A targeted security review of the pre-release code produced findings that
  were fixed in S1–S1.3 and checked by independent targeted re-reviews; the
  final re-review passed with residual risks. This is not a comprehensive
  audit, and KSecureMessage is not formally verified.
- The review and remediation history, the per-finding status and the
  accepted residual risks (F7 storage downgrade, partially fixed; N8 and N9,
  LOW, pre-S1 cleanup side effects) are in
  [security-review-remediation.md](https://github.com/rkreienbuehl/KSecureMessage/blob/main/docs/security-review-remediation.md).
  The threat model and known limitations (TOFU on first contact, metadata
  visible to the server, no sealed sender, the server's wall clock as a
  security input, storage key compromise) are in
  [security-review.md](https://github.com/rkreienbuehl/KSecureMessage/blob/main/docs/security-review.md).
- Report vulnerabilities privately as described in
  [SECURITY.md](https://github.com/rkreienbuehl/KSecureMessage/blob/main/SECURITY.md).

### Operators of servers from pre-S1 development builds

If you ran a KSecureMessage server built before the S1 security remediation,
its stored device registrations were never authorized by the host
application, and a malicious one may have planted an offline recovery key.
Before exposing a 0.1.0 server on that database, audit the registrations and
run the tested offline cleanup exactly as described in
[operating-the-server.md, "Pre-S1 cleanup"](https://github.com/rkreienbuehl/KSecureMessage/blob/main/docs/operating-the-server.md#pre-s1-cleanup).

### Compatibility and migration

- This is the first public release; there is no earlier public version to
  upgrade from.
- Databases created by development snapshots are migrated by the numbered,
  tested migrations: client SQLDelight schema 1 → 16 (plus the encryption
  of milestone 8 plaintext databases by `SqlDelightClientStorage.open`,
  subject to the downgrade protection), server SQLDelight schema 1 → 8
  (migrate before `SqlDelightServerStorage.open`). Each step is tested
  against a frozen fixture of the previous schema. Other snapshot state and
  snapshot APIs carry no compatibility promise.
- Clients and servers from before S1 cannot talk to 0.1.0 (session
  initiation v2, signed message submission): upgrade peers and servers
  together. Details: "Upgrade behavior" in
  [security-review-remediation.md](https://github.com/rkreienbuehl/KSecureMessage/blob/main/docs/security-review-remediation.md#upgrade-behavior).
