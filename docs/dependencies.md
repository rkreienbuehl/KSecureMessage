# Dependencies and licenses

Runtime dependencies of the published artifacts, versions from
`gradle/libs.versions.toml` as resolved in R1. Licenses are taken from the
POM metadata in the local Gradle cache; "not verified" means no license
metadata was available locally and nothing is assumed. Check the upstream
project before redistributing.

KSecureMessage itself is licensed under the Apache License 2.0
([LICENSE](https://github.com/rkreienbuehl/KSecureMessage/blob/main/LICENSE), [NOTICE](https://github.com/rkreienbuehl/KSecureMessage/blob/main/NOTICE)).

## Direct dependencies

| Dependency | Version | Used by | Scope | License (POM) |
|---|---|---|---|---|
| `eu.livotov.labs:kodium` | 1.0.0 | `core:protocol` | implementation | Apache-2.0 |
| `dev.whyoleg.cryptography:cryptography-core`, `-random`, `-provider-optimal` | 0.6.0 | `storage:encryption` | implementation | The Apache Software License, Version 2.0 |
| `org.kotlincrypto.hash:sha2` | 0.8.0 | `core:protocol` | implementation | The Apache Software License, Version 2.0 |
| `org.jetbrains.kotlinx:kotlinx-serialization-core` / `-json` | 1.11.0 | `core:model` (api), `client:ktor`, `server:ktor` | api / implementation | Apache-2.0 |
| `org.jetbrains.kotlinx:kotlinx-coroutines-core` | 1.11.0 | client, server, storage modules | implementation | Apache-2.0 |
| `app.cash.sqldelight:runtime` | 2.4.0 | `storage:client:sqldelight`, `storage:server:sqldelight` | api (`SqlDriver`, `SqlSchema` at `open`) | Apache-2.0 |
| `app.cash.sqldelight:async-extensions` | 2.4.0 | `storage:client:sqldelight` | implementation | Apache-2.0 |
| `io.ktor:ktor-client-core`, `-client-content-negotiation`, `-client-engine-defaults`, `-serialization-kotlinx-json` | 3.6.0 | `client:ktor` | implementation (`HttpClient` in the transport constructor) | The Apache Software License, Version 2.0 |
| `io.ktor:ktor-server-core`, `-server-content-negotiation`, `-serialization-kotlinx-json` | 3.6.0 | `server:ktor` | implementation (`Route` receiver of `kSecureMessageRoutes`) | The Apache Software License, Version 2.0 |
| `org.jetbrains.kotlin:kotlin-stdlib` | 2.4.20 | all | api | Apache-2.0 |

## Transitive dependencies

| Group | Examples | License (POM) |
|---|---|---|
| `org.kotlincrypto.*` (via Kodium) | `crypto-rand` 0.6.0, `sha3`, `hmac-sha2`, `keccak`, `core`, `bitops`, `error` | The Apache Software License, Version 2.0 |
| `dev.whyoleg.cryptography` providers | `provider-jdk`, `provider-apple`, `provider-cryptokit`, `bigint`, `serialization-asn1`, `serialization-pem` | The Apache Software License, Version 2.0 |
| `io.ktor` | `ktor-http`, `ktor-io`, `ktor-utils`, `ktor-client-okhttp`, `ktor-server-sessions`, … | The Apache Software License, Version 2.0 |
| `com.squareup.okhttp3:okhttp` 5.5.0, `com.squareup.okio:okio` (JVM client engine) | | The Apache Software License, Version 2.0 |
| `org.jetbrains.kotlinx:atomicfu`, `kotlinx-io-core` | | Apache-2.0 |
| `org.jetbrains.kotlinx:kotlinx-datetime` | | Apache-2.0 |
| `org.jetbrains:annotations` 23.0.0 | | The Apache Software License, Version 2.0 |
| `org.slf4j:slf4j-api` 2.0.19 (Ktor server) | | MIT |
| `com.typesafe:config` 1.4.9 (Ktor server) | | not verified |
| `com.charleskorn.kaml:kaml` 0.79.0, `it.krzeminski:snakeyaml-engine-kmp` 3.1.1 (Ktor server) | | not verified |
| `net.thauvin.erik.urlencoder:urlencoder-lib` 1.6.0 (Ktor) | | not verified |
| `org.jetbrains.kotlinx:kotlinx-io-bytestring` 0.9.x | | not verified |

## Dependency boundaries

- **Kodium** is imported only by `core:protocol`
  (`KodiumProtocolEngine.kt`, `DeviceAuthentication.kt`) and never appears in
  a public signature.
- **cryptography-kotlin** is imported only by `storage:encryption`
  (`AesGcm.kt`, internal).
- **SQLDelight** types appear in public API only at the adapter boundary:
  `SqlDelightClientStorage.open(driver, keyProvider)`, `.Schema` and the
  server equivalents. Generated database classes are not API
  ([security-review.md](security-review.md#known-limitations-and-open-points)).
- **Ktor** types appear only in `client:ktor` (`HttpClient` constructor
  parameter) and `server:ktor` (`Route.kSecureMessageRoutes`).

`checkReleaseConventions` fails if a Kodium, cryptography-kotlin or
KotlinCrypto type appears in any API dump, or SQLDelight/Ktor types outside
those modules.

## Upgrades and additions in R1

No runtime dependency was upgraded. Build-time additions only:

| Addition | Version | Reason |
|---|---|---|
| `com.vanniktech.maven.publish` (base plugin) | 0.37.0 | Maven publications, POM metadata, signing and Central configuration for KMP and JVM modules |
| `org.jetbrains.dokka` | 2.2.0 | Documentation (javadoc) jars required by Maven Central |
| `io.ktor:ktor-server-cio` | 3.6.0 | Only in the sample `samples/jvm-e2e` (HTTP engine for the example server) |
