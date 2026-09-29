# Application lifecycle

What an application built on `SecureMessageClient` has to call, and when.
Every call is explicit: the library has no background scheduler, no timer and
no implicit maintenance. The compiled, runnable version of the minimal path is
[`samples/jvm-e2e`](https://github.com/rkreienbuehl/KSecureMessage/blob/main/samples/jvm-e2e/app/src/main/kotlin/dev/kreienbuehl/ksecuremessage/sample/Main.kt)
(run by `./gradlew verifyPublication`).

Each item is marked:

- **Required**: needed for correct messaging.
- **Feature**: needed only if the application offers that feature.
- **Policy**: optional maintenance; the application decides when and how often.

## Setup

| When | Call | Kind | Notes |
|---|---|---|---|
| Every launch | construct `SecureMessageClient(localAddress, storage, KodiumProtocolEngine(), transport, preKeyConfiguration, clock)` | Required | Storage: `SqlDelightClientStorage.open(driver, keyProvider)` in production (see [operating-the-server.md](operating-the-server.md#client-storage)); `InMemoryClientStorage` only for tests and examples. Transport: `KtorSecureMessageTransport(baseUrl)` or your own `SecureMessageTransport`. |
| Every launch | `initialize()` | Required | Creates the identity, the device authentication key and prekeys on first launch; afterwards tops up one-time prekeys, rotates the signed prekey by age and deletes expired ones. Local only, safe to repeat. Fails closed (`InconsistentStorage`) if an initialized storage lost its device authentication key: see recovery below. |
| First launch (then harmless) | `registerDevice()` | Required | Registers the device authentication public key (trust on first registration). A different key for the address is a `DeviceRegistrationConflict`, never a reset. |
| First launch and after every `initialize()` that changed prekeys | `publishPreKeys()` | Required | Uploads identity key, signed prekey and one-time prekeys. Idempotent; call it again after a failure. Each first contact consumes one server-side one-time prekey; when none is left, X3DH runs without one. Call `initialize()` + `publishPreKeys()` regularly (policy) to replenish them. |

Operations before `initialize()` throw `SecureMessageClientException.NotInitialized`.

## Sending

| Call | Kind | Notes |
|---|---|---|
| `send(recipient, plaintext)` | Required | Creates a session on first contact (fetches the recipient's bundle), stores the message as pending outbound with the new ratchet state in one transaction, then hands it to the transport. Returns `SentMessage` (the `LogicalMessageId`). Throws `MessageNotSent` if the hand-off failed; the message stays pending. |
| `retryPendingMessages(recipient)` | Required (when to call is policy) | Re-encrypts pending messages for that recipient in order and resends them. Needed after a failed hand-off, a lost envelope, a lost ACK or a session collision. The library never retries on its own; choose the trigger (app start, reconnect, timer, user action). |
| `pendingMessages(afterSequence, limit, recipient)` / `pendingMessageCount(recipient)` | Policy | Cursor pagination (max 100 per page) over messages not yet acknowledged. |
| `abandonPendingMessage(message)` | Feature | The application gives up on one message: removes it locally, sends nothing. It is not a recall: an already delivered envelope can still arrive and its late ACK is ignored. |

A pending message ends only by the recipient's ACK or an explicit abandon;
transport success is not delivery.

## Receiving

| Call | Kind | Notes |
|---|---|---|
| `receive()` | Required | Drains this device's mailbox (signed request). Pass the envelopes to `decrypt` one at a time, **in the returned order**. |
| `decrypt(envelope)` | Required | Returns a `ReceiveResult`: `Delivery` (new application message, stored as pending inbound, **not yet acknowledged**), `Acknowledgement` (one of your messages was finalized by the recipient), `AlreadyCommitted` / `AlreadyDiscarded` (a retry; the ACK is sent again). A second `decrypt` of the same message before the commit returns the same `Delivery`. |
| `commitReceivedMessage(message)` | Required | Call **after** the application applied the message durably (for example, stored it in its own database). Moves it to processed in one transaction and sends the ACK. The ACK means "finalized by the receiving application". |
| `discardReceivedMessage(message, reason)` | Feature | Finalizes a message the application will never apply (`MessageDiscardReason`, a closed enum, never sent to the sender). Also sends the ACK. |
| `pendingReceivedMessages(afterSequence, limit, sender)` / `pendingReceivedMessageCount(sender)` | Required after a restart | Messages decrypted but not yet committed or discarded, for example because the app crashed in between. Process them like a new `Delivery`. Pending inbound messages never expire. |
| `pruneProcessedMessages(ProcessedInboundRetentionPolicy(maxAge))` | Policy | Removes old processed-message tombstones (committed and discarded). A pruned ID is no longer recognized as a duplicate, so choose `maxAge` longer than any sender could still retry. No default, never automatic. |

Delivery is at least once, not exactly once. Apply messages idempotently,
keyed by sender and `LogicalMessageId`, and commit only after the application
side effect is durable.

## Identity trust

| Call | Kind | Notes |
|---|---|---|
| (implicit) | Required | The first successful contact pins the peer's identity key (TOFU). |
| `SecureMessageClientException.IdentityChanged` | Required | Thrown when a peer presents a different identity key. Nothing changes. The application must show this to the user. |
| `acceptRemoteIdentityChange(exception.change)` | Feature | Replaces the pin with exactly the presented key, only after the user decided to. Never accept automatically. Pending outbound messages survive and can be retried. |
| `safetyNumber(remote)`, `compareSafetyNumber(remote, scanned)` | Feature | Manual verification (display 60 digits or a QR payload). Comparing changes nothing. |
| `markRemoteIdentityVerified(safetyNumber)` / `markRemoteIdentityUnverified(remote)`, `remoteIdentityTrust(remote)` | Feature | Local verification state per pin. A new or replaced pin is always unverified. |

## Device authentication (server credentials)

| Call | Kind | Notes |
|---|---|---|
| `deviceAuthenticationHealth(policy)` | Policy | Read-only summary: `Healthy`, `RotationDue`, `RotationPending`, `RecoveryPending`, `ActiveKeyMissing`, `Unregistered`, `Inconsistent`. Use it to decide which of the calls below to offer. |
| `rotateDeviceAuthenticationKeyIfNeeded(policy)` | Policy | Routine rotation when the key is older than `DeviceAuthenticationRotationPolicy.maxKeyAge`. No default policy; never automatic. Lower-level steps: `deviceAuthenticationRotationStatus`, `evaluateDeviceAuthenticationRotation`, `rotateDeviceAuthenticationKey`, `resolveDeviceAuthenticationRotation`, `cancelDeviceAuthenticationRotation`. |
| `prepareDeviceAuthenticationRecovery(authorizer)` → transfer → `authorizeDeviceRecovery(request)` on the other device → transfer → `completeDeviceAuthenticationRecovery(authorization)` | Feature | Recovery of a lost device authentication key authorized by another registered device of the same user. Transfer the request and authorization with `DeviceRecoveryCodec` (QR code, etc.). `resolveDeviceAuthenticationRecovery` / `cancelDeviceAuthenticationRecovery` after a lost response or to give up. Recovers server authentication only, never the messaging identity. |

## Offline recovery key (last-device recovery)

| Call | Kind | Notes |
|---|---|---|
| `createLastDeviceRecoveryKey()` → back up offline (`LastDeviceRecoveryKey.encode()`) → `registerLastDeviceRecoveryKey(key)` | Feature | The only way for a user's **last** device to recover its server credentials. The client never stores the key; the application must have the user keep it offline. |
| `recoverLastDevice(key)` (or `prepareLastDeviceRecovery` + `completeLastDeviceRecovery`), `resolveLastDeviceRecovery`, `cancelLastDeviceRecovery` | Feature | Replaces the lost device authentication key using the offline key. |
| `lastDeviceRecoveryKeyStatus()`, `rotateLastDeviceRecoveryKey(current, new)`, `revokeLastDeviceRecoveryKey(current)` | Feature | Key lifecycle; both need a registered device **and** the current offline key. Back up the new key before rotating. |
| `requestLastDeviceRecoveryKeyReset()`, `lastDeviceRecoveryKeyResetStatus()`, `completeLastDeviceRecoveryKeyReset(newKey)`, `cancelLastDeviceRecoveryKeyReset(reset)` | Feature | Delayed replacement of a **lost** offline key; only possible if the server host configured a `RecoveryKeyResetPolicy`. The holder of the current offline key can see and veto a reset without any device: `lastDeviceRecoveryKeyResetStatusByRecoveryKey(key)`, `cancelLastDeviceRecoveryKeyResetByRecoveryKey(key, reset)`. |
| `recoveryKeyResetAwareness()` | Policy | Read-only: is a reset pending or eligible? Poll it at a time the application chooses and show it to the user. A reset that nobody cancels replaces the key after the delay. |

## Advanced

`rotateSignedPreKey()` rotates the signed prekey immediately (`initialize()`
does it by age). `currentPreKeyBundle()`, `publicOneTimePreKeys()` and
`remoteIdentityKey(remote)` expose public key material for diagnostics and
custom transports. Declarations marked `@InternalKSecureMessageApi` are for
KSecureMessage's own modules; applications do not need them.

## Shutdown and restart

Nothing needs to be flushed: every state change is committed in a storage
transaction before a call returns. On shutdown, stop calling the client and
close the storage driver the application owns. After a restart, call
`initialize()`, then process `pendingReceivedMessages` and (by policy)
`retryPendingMessages`.

## Not provided

No background retry, polling, push notifications, automatic key rotation,
automatic pruning, sealed sender, groups, attachments or read receipts.
