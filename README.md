# KSecureMessage

KSecureMessage is an early-stage (pre-1.0) Kotlin Multiplatform library for Signal-style secure messaging. It uses the X3DH and Double Ratchet primitives of [Kodium](https://github.com/LivotovLabs/kodium) and adds the messaging lifecycle around them: sessions, identity trust and safety numbers, reliable delivery with explicit acknowledgements, encrypted client storage, device authentication towards the server and recovery of lost device keys.

It is not Signal, not compatible with Signal/libsignal, not formally verified and **has not had a comprehensive security audit** (targeted independent re-reviews of its first security review's findings are documented, see [Security](#security)). There is no sealed sender: the server sees routing metadata. Delivery is at least once, not exactly once.

**Documentation:** <https://rkreienbuehl.github.io/KSecureMessage/> (start with [Getting started](https://rkreienbuehl.github.io/KSecureMessage/getting-started/), API reference under [/api/](https://rkreienbuehl.github.io/KSecureMessage/api/)). Source: [docs/](docs/index.md).

## Status

`0.x`, current version `0.1.0` (the first public release). The public API is tracked by a checked-in ABI baseline and may still change between minor versions; wire, storage and protocol formats are frozen by test vectors. Release notes: [CHANGELOG.md](CHANGELOG.md). Milestone history: [docs/project-history.md](docs/project-history.md).

## Installation

Group `dev.kreienbuehl.ksecuremessage`, one artifact per module named `ksecuremessage-<module path>`:

```kotlin
dependencies {
    implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-client-core:0.1.0")
    implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-client-ktor:0.1.0")
    implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-storage-client-sqldelight:0.1.0")
    // plus one platform key provider: ksecuremessage-storage-keyprovider-android or -apple
}
```

Servers (JVM) use `ksecuremessage-server-core`, `ksecuremessage-server-ktor` and `ksecuremessage-storage-server-sqldelight`. All artifacts and the versioning policy: [docs/releasing.md](docs/releasing.md); dependency setup for both sides: [docs/getting-started.md](docs/getting-started.md).

## Quick start

```kotlin
val client = SecureMessageClient(address, storage, KodiumProtocolEngine(), KtorSecureMessageTransport(baseUrl))
client.initialize()          // every launch: local keys and prekeys
client.registerDevice()      // first launch: device authentication key
client.publishPreKeys()      // after initialize(): public prekeys

client.send(recipient, "Hello".encodeToByteArray())

for (envelope in client.receive()) {
    val result = client.decrypt(envelope)
    if (result is ReceiveResult.Delivery) {
        // apply result.message durably, then:
        client.commitReceivedMessage(result.message)   // sends the ACK
    }
}
```

Server (JVM, Ktor): the host owns the SQLite driver and decides which authenticated caller may register a device for which user.

```kotlin
val storage = SqlDelightServerStorage.open(JdbcSqliteDriver("jdbc:sqlite:server.db", Properties(), SqlDelightServerStorage.Schema))
val authorizer = DeviceRegistrationAuthorizer<MyPrincipal> { principal, request ->
    if (request.address.userId == principal.userId) DeviceRegistrationAuthorizationResult.Authorized
    else DeviceRegistrationAuthorizationResult.Denied
}
val server = SecureMessageServer(storage, Clock.System, authorizer)
routing { kSecureMessageRoutes(server, DeviceRegistrationContextExtractor { call -> myAuthenticatedPrincipal(call) }) }
```

The runnable version, with a SQLite-backed server and a host registration authorizer (its clients use in-memory storage for brevity; applications use `SqlDelightClientStorage` with a platform `StorageKeyProvider`), is [samples/jvm-e2e](samples/jvm-e2e); every call an application makes is in [docs/application-lifecycle.md](docs/application-lifecycle.md), and running the server in [docs/operating-the-server.md](docs/operating-the-server.md).

## Supported platforms

| Platform | Status |
|---|---|
| JVM, Android, macOS arm64, iOS simulator arm64, Linux x64, JS on Node.js | supported, tests executed |
| iOS arm64, iOS x64, macOS x64, Windows x64 (mingwX64), JS in a browser | compile-only |
| Wasm (wasmJs), Node.js and browser | compile-only, runtime blocked upstream |

Details: [docs/supported-platforms.md](docs/supported-platforms.md).

## Security

Read [docs/security-review.md](docs/security-review.md) (threat model and known limitations) before depending on KSecureMessage. The findings of the first security review, their fixes (S1–S1.3), the independent re-review results and the accepted residual risks (F7, N8, N9) are in [docs/security-review-remediation.md](docs/security-review-remediation.md). In short: identity trust is trust on first use until users compare safety numbers; the server sees metadata and its wall clock is a security input; client storage encryption does not protect against an attacker who has both the database and the storage key. KSecureMessage does not authenticate accounts: a server must be given a `DeviceRegistrationAuthorizer<C>` that decides, with the principal the host's own authentication established for the request (passed through a `DeviceRegistrationContextExtractor<C>`), which device may join which user. **If you ran a server from a build before S1** (any development snapshot before the security remediation), its stored registrations were never host-authorized and must be audited before exposing the upgraded server; a malicious one must be removed offline with the tested cleanup script, which also revokes the user's possibly planted offline recovery key ([docs/operating-the-server.md, "Pre-S1 cleanup"](docs/operating-the-server.md#pre-s1-cleanup)). Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/rkreienbuehl/KSecureMessage/security/advisories/new) as described in [SECURITY.md](SECURITY.md), never in a public issue.

## Building

The Gradle wrapper (Gradle 9.6.0) is checked in; always build with `./gradlew`.

```bash
./gradlew build                    # all targets available on this host, all tests, API check
./gradlew verifyTestExecution      # after build: the supported test matrix really ran
./gradlew verifyPublication        # local publication, artifact inspection, consumer fixture
./gradlew docsSite                 # documentation site with API reference (needs docs/requirements.txt)
```

Release process and CI: [docs/releasing.md](docs/releasing.md).

## Next implementation steps

1. A PostgreSQL server adapter if multi-node deployment is needed.
2. Sealed sender.

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
