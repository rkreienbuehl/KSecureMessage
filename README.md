# KSecureMessage

KSecureMessage is an early-stage (pre-1.0) Kotlin Multiplatform library for Signal-style secure messaging. It uses the X3DH and Double Ratchet primitives of [Kodium](https://github.com/LivotovLabs/kodium) and adds the messaging lifecycle around them: sessions, identity trust and safety numbers, reliable delivery with explicit acknowledgements, encrypted client storage, device authentication towards the server and recovery of lost device keys.

It is not Signal, not compatible with Signal/libsignal, not formally verified and **not independently audited**. There is no sealed sender: the server sees routing metadata. Delivery is at least once, not exactly once.

**Documentation:** <https://rkreienbuehl.github.io/KSecureMessage/> (start with [Getting started](https://rkreienbuehl.github.io/KSecureMessage/getting-started/), API reference under [/api/](https://rkreienbuehl.github.io/KSecureMessage/api/)). Source: [docs/](docs/index.md).

## Status

`0.x`, no public release yet (development version `0.1.0-SNAPSHOT`). The public API is tracked by a checked-in ABI baseline and may still change between minor versions; wire, storage and protocol formats are frozen by test vectors. Milestone history: [docs/project-history.md](docs/project-history.md).

## Installation

Group `dev.kreienbuehl.ksecuremessage`, one artifact per module named `ksecuremessage-<module path>`:

```kotlin
dependencies {
    implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-client-core:0.1.0-SNAPSHOT")
    implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-client-ktor:0.1.0-SNAPSHOT")
    implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-storage-client-sqldelight:0.1.0-SNAPSHOT")
}
```

All artifacts and the versioning policy: [docs/releasing.md](docs/releasing.md).

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

The runnable version is [samples/jvm-e2e](samples/jvm-e2e); every call an application makes is in [docs/application-lifecycle.md](docs/application-lifecycle.md).

## Supported platforms

| Platform | Status |
|---|---|
| JVM, Android, macOS arm64, iOS simulator arm64, Linux x64, JS on Node.js | supported, tests executed |
| iOS arm64, iOS x64, macOS x64, Windows x64 (mingwX64), JS in a browser | compile-only |
| Wasm (wasmJs), Node.js and browser | compile-only, runtime blocked upstream |

Details: [docs/supported-platforms.md](docs/supported-platforms.md).

## Security

Read [docs/security-review.md](docs/security-review.md) (threat model and known limitations) before depending on KSecureMessage. Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/rkreienbuehl/KSecureMessage/security/advisories/new) as described in [SECURITY.md](SECURITY.md), never in a public issue.

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
