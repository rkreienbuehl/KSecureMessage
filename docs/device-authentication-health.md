# Device authentication health (milestone 25)

`SecureMessageClient.deviceAuthenticationHealth(policy)` answers one
question: what is the current factual state of this device's server
authentication credentials? It composes existing state only: the local
device authentication key slots (server authentication M12, device recovery
M14, routine rotation M16, last-device recovery M18) and, when those do not
decide, the signed registration status of M17. The library classifies; the
application decides what to show and what to do.

Client only. No server code, route, schema (client v15, server v7), wire
format, cryptographic domain, frozen vector or sealed record type changed.

## Model

```kotlin
sealed interface DeviceAuthenticationHealth {
    data class Healthy(status: DeviceAuthenticationRotationStatus, policy: DeviceAuthenticationRotationPolicy?)
    data class RotationDue(status: DeviceAuthenticationRotationStatus, policy: DeviceAuthenticationRotationPolicy)
    data object RotationPending
    data class RecoveryPending(kind: DeviceAuthenticationRecoveryKind)   // DEVICE_RECOVERY, LAST_DEVICE_RECOVERY
    data object ActiveKeyMissing
    data object Unregistered
    data class Inconsistent(reason: DeviceAuthenticationHealthInconsistency)
}
```

| State | Meaning | Server reads |
| --- | --- | --- |
| `Healthy` | Active key present, server has a registration, nothing pending; with a policy the key is younger than `maxKeyAge`. `policy == null`: the age was not evaluated. | 1 |
| `RotationDue` | As `Healthy`, but `age >= policy.maxKeyAge` by the client clock. Nothing rotated. | 1 |
| `RotationPending` | M16 pending rotation key, active K1 present. Not completed or resolved. | 0 |
| `RecoveryPending(kind)` | M14 (`DEVICE_RECOVERY`) or M18 (`LAST_DEVICE_RECOVERY`) pending replacement key, whether or not the active key is present. Not completed or resolved. | 0 |
| `ActiveKeyMissing` | Identity present, no active key, nothing pending, not pre-M12 storage. The key is never recreated (M12/M14 fail closed). | 0 |
| `Unregistered` | Active key present, the server answered `NOT_REGISTERED`. Nothing registered. | 1 |
| `Inconsistent(reason)` | The local slots contradict each other: `MULTIPLE_PENDING_TRANSITIONS` (more than one of the three pending slots filled; storage refuses this) or `ROTATION_PENDING_WITHOUT_ACTIVE_KEY` (M16 K2 pending, K1 gone; M16 never promotes K2 because K1 vanished). | 0 |

`Healthy` and `RotationDue` reuse `DeviceAuthenticationRotationStatus`
(`authEpoch`, `authKeyInstalledAt`, `evaluatedAt`, `age`); its
`pendingRotation`/`pendingRecovery` are always `false` there. No state
carries key material; pending states expose no pending key, seed or sealed
record. The names are factual: no severity, score or recommendation.

## Evaluation order

Under the client's `deviceAuthenticationMutex` (the lock of the M16/M18/M19/M23/M24
steps); no storage transaction is held across the request.

1. One read transaction: local identity (missing → `NotInitialized`), the
   active key, `awaitsUpgradeKey`, the three pending slots.
2. Several pending slots → `Inconsistent(MULTIPLE_PENDING_TRANSITIONS)`.
3. Pending device recovery → `RecoveryPending(DEVICE_RECOVERY)`; pending
   last-device recovery → `RecoveryPending(LAST_DEVICE_RECOVERY)`.
4. Pending rotation without the active key →
   `Inconsistent(ROTATION_PENDING_WITHOUT_ACTIVE_KEY)`; with it →
   `RotationPending`.
5. No active key: storage from before M12 that has not created its first key
   (`awaitsUpgradeKey`) → `NotInitialized` (call `initialize()`); otherwise
   `ActiveKeyMissing`.
6. Exactly one signed `GET …/registration` with the active key.
   `AuthenticationFailed(NOT_REGISTERED)` → `Unregistered`.
7. One more local read (no second request). If steps 2–5 now decide (a
   transition started while the request was open), that state is returned.
8. The client clock is read once: `RotationDue` if a policy is given and
   `policy.isDue(age)`, otherwise `Healthy`.

Pending transitions come first because they are directly actionable local
facts, and a pending transition takes precedence over the age: a pending
rotation of a 400-day-old key is `RotationPending`, not `RotationDue`. A
pending recovery with the active key present is `RecoveryPending` (a
prepared recovery is not a key loss); after a loss it is `RecoveryPending`,
not `ActiveKeyMissing`. The local-only states never ask the server, not even
to confirm that it still holds a registration for a missing key; so a
"registered but key missing" state is not observable and does not exist.

## Rotation policy and clocks

Same semantics as M17 (`DeviceAuthenticationRotationPolicy.isDue`, `keyAge`):

- `age = max(0, clientNow - authKeyInstalledAt)`: client clock minus the
  server installation time; a client clock behind it gives age zero.
- Due exactly when `age >= maxKeyAge`; `Duration.INFINITE` is never due.
- No default policy: `policy == null` never gives `RotationDue`.
- A client clock jumping forward can make a key due early. This is a
  wall-clock classification, not a secure monotonic timer.
- The injected client `Clock`, read once per evaluation (`evaluatedAt`).

## Errors versus `Inconsistent`

Operational failures stay exceptions exactly as the transport raises them:
unreachable server, `UnexpectedResponse` (for example `500`), and every
`AuthenticationFailed` except `NOT_REGISTERED`. `INVALID` in particular
means the server rejected the active key's signature (the registered key is
another one); it is thrown, not classified. A registration status the model
rejects (`authEpoch < 1`) fails in the transport. `Inconsistent` is only for
contradictory local state.

## What the server can prove

The registration status carries `authEpoch` and `authKeyInstalledAt`, not
the registered public key. The helper therefore cannot prove "server key ==
local active key"; the only evidence is that the server accepted the
request signed by the local key (the server verifies with the registered
key). Like M17, ServerAuth authenticates the request, not the response.

## Read-only guarantee

Never initializes, registers, rotates, recovers, resolves, cancels, creates
a key, writes storage, sends messages or publishes prekeys, and is never
called implicitly (not by `initialize`, `send`, `receive`, `decrypt`,
`publishPreKeys`, registration, rotation or recovery). Nothing is cached or
persisted: every call reads fresh local state and, when needed, fresh server
status. The only server-side effect is the ServerAuth nonce of the signed
read.

## Concurrency

The mutex serializes the evaluation with the M16 rotation and M18
last-device recovery steps of the same instance: a `prepareDeviceAuthenticationRotation`
started while the status read is open waits, so the result reflects one
complete order (`Healthy`, then `RotationPending` on the next call). The M14
device recovery functions do not take that mutex; a recovery prepared while
the read is open is found by the re-read of step 7 and reported as
`RecoveryPending`. Changes after the re-read, from another instance on the
same storage or another device on the server, are not seen: the result is a
snapshot that can be stale right after it returns.

## Usage

```kotlin
when (val health = client.deviceAuthenticationHealth(policy)) {
    is DeviceAuthenticationHealth.Healthy -> { /* nothing required by the library */ }
    is DeviceAuthenticationHealth.RotationDue -> { /* may offer rotateDeviceAuthenticationKey() */ }
    DeviceAuthenticationHealth.RotationPending -> { /* may complete or resolve the pending rotation */ }
    is DeviceAuthenticationHealth.RecoveryPending -> { /* health.kind: continue that recovery */ }
    DeviceAuthenticationHealth.ActiveKeyMissing -> { /* may start device or last-device recovery */ }
    DeviceAuthenticationHealth.Unregistered -> { /* may call registerDevice() */ }
    is DeviceAuthenticationHealth.Inconsistent -> { /* health.reason: a state error */ }
}
```

## Tests

`client:core` `DeviceAuthenticationHealthTest`: every state with its read
count (0 for local states, exactly 1 otherwise), the due boundary, `INFINITE`,
no policy, client clock behind and jumping forward, fresh reads after a
rotation, operational errors thrown (`500`, `EXPIRED`, `INVALID`),
`NotInitialized` without identity and for pre-M12 storage, injected
impossible slot combinations, no writes (transport and storage refuse every
write; prekeys, session, registration, recovery key state and mailbox
unchanged), nothing implicit, the mutex race with a rotation prepared during
the read, and the re-read with a recovery prepared during the read.

## Limitations

- A factual snapshot only: no history, no background monitoring, no push,
  no polling.
- Wall-clock rotation age.
- No proof that the registered key equals the local key (not exposed by the
  registration status).
- No automatic action; the application decides UI and policy.
- Server authentication only: no messaging identity health, no recovery key
  state (see `recoveryKeyResetAwareness()`, docs/recovery-key-reset.md), no
  sealed sender.
