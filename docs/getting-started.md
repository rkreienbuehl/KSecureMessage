# Getting started

The shortest path from an empty project to one message sent, received,
committed and acknowledged. The Kotlin below is taken verbatim from
[`samples/jvm-e2e`](https://github.com/rkreienbuehl/KSecureMessage/blob/main/samples/jvm-e2e/app/src/main/kotlin/dev/kreienbuehl/ksecuremessage/sample/Main.kt),
which the release gate compiles and runs against the published artifacts.

!!! warning "Pre-1.0, not audited"
    KSecureMessage is `0.x` and has not had an independent security audit.
    Read the [security model](security-review.md) before you depend on it.

## Dependencies

Group `dev.kreienbuehl.ksecuremessage`, one artifact per module named
`ksecuremessage-<module path>`. No release has been published yet; the
current development version is `0.1.0-SNAPSHOT`.

=== "Client application"

    ```kotlin
    dependencies {
        implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-client-core:0.1.0-SNAPSHOT")
        implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-client-ktor:0.1.0-SNAPSHOT")
        implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-storage-client-sqldelight:0.1.0-SNAPSHOT")
        // one platform key provider:
        implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-storage-keyprovider-android:0.1.0-SNAPSHOT")
        implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-storage-keyprovider-apple:0.1.0-SNAPSHOT")
    }
    ```

=== "Server (JVM)"

    ```kotlin
    dependencies {
        implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-server-core:0.1.0-SNAPSHOT")
        implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-server-ktor:0.1.0-SNAPSHOT")
        implementation("dev.kreienbuehl.ksecuremessage:ksecuremessage-storage-server-sqldelight:0.1.0-SNAPSHOT")
    }
    ```

The full artifact list is in [releasing](releasing.md#published-artifacts).
Snapshots are served from the Maven Central snapshot repository
`https://central.sonatype.com/repository/maven-snapshots/`.

## Choose storage and a key provider

| Use | Client storage | Storage key |
|---|---|---|
| Production, Android | `SqlDelightClientStorage.open(driver, keyProvider)` | `AndroidStorageKeyProvider(context)` |
| Production, iOS/macOS | `SqlDelightClientStorage.open(driver, keyProvider)` | `AppleStorageKeyProvider()` |
| Other platforms | `SqlDelightClientStorage.open(driver, keyProvider)` | your own `StorageKeyProvider` backed by the platform's secret store |
| Tests and examples | `InMemoryClientStorage()` | none (not encrypted, not persistent) |

The application creates and owns the SQLDelight driver
(`SqlDelightClientStorage.Schema`). See [client storage](storage.md),
[storage encryption](storage-encryption.md) and
[storage key providers](storage-key-providers.md).

## Run a server

The server is a blind relay: it stores public prekeys and queues opaque
envelopes. The host owns the SQLite driver and its own user authentication:
the registration route asks the host for the caller's principal and the
`DeviceRegistrationAuthorizer` decides with it (the sample's bearer-token
table is DEMO ONLY).

```kotlin
--8<-- "samples/jvm-e2e/app/src/main/kotlin/dev/kreienbuehl/ksecuremessage/sample/Main.kt:server"
```

Clocks, backups and deployment notes: [operating the server](operating-the-server.md).

## Create clients

Each device has a `DeviceAddress` (user + device). The sample keeps storage
in memory to stay short; use `SqlDelightClientStorage` in an application.
The transport's `HttpClient` carries the application's own authentication.

```kotlin
--8<-- "samples/jvm-e2e/app/src/main/kotlin/dev/kreienbuehl/ksecuremessage/sample/Main.kt:clients"
```

## First launch: initialize, register, publish

`initialize()` creates the local identity, the device authentication key and
prekeys (on every launch it tops them up). `registerDevice()` registers the
device authentication key with the server, `publishPreKeys()` uploads the
public prekeys.

```kotlin
--8<-- "samples/jvm-e2e/app/src/main/kotlin/dev/kreienbuehl/ksecuremessage/sample/Main.kt:first-launch"
```

## Send

The message stays pending on the sender until the recipient acknowledges it.

```kotlin
--8<-- "samples/jvm-e2e/app/src/main/kotlin/dev/kreienbuehl/ksecuremessage/sample/Main.kt:send"
```

## Receive and commit

`receive()` drains the mailbox; `decrypt` returns a `Delivery` that is not yet
acknowledged. Apply the message durably first, then commit: the commit sends
the ACK.

```kotlin
--8<-- "samples/jvm-e2e/app/src/main/kotlin/dev/kreienbuehl/ksecuremessage/sample/Main.kt:receive"
```

```kotlin
--8<-- "samples/jvm-e2e/app/src/main/kotlin/dev/kreienbuehl/ksecuremessage/sample/Main.kt:commit"
```

## Next

- [Application lifecycle](application-lifecycle.md): retries, restarts,
  identity changes, recovery and every other call.
- [Application delivery](application-delivery.md): at-least-once delivery and
  the commit boundary.
- [API reference](api-reference.md).
