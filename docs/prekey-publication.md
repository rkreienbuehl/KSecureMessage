# KSecureMessage prekey publication

This document describes how a client publishes its public prekeys, how the
server stores them and how it hands them out for first contacts. It also
defines the HTTP API v1.

Contracts: `storage/core/.../storage/ServerStorage.kt` (`PreKeyRepository`).
Server: `server/core/.../server/PreKeyService.kt`. Client:
`SecureMessageClient.publishPreKeys()`. HTTP: `server/ktor/.../KSecureMessageRoutes.kt`
and `client/ktor/.../KtorSecureMessageTransport.kt`.

## Trust boundary

The client owns all private key material. The server receives only public
material:

| Sent to the server | Never sent |
|--------------------|------------|
| identity public key | identity private key |
| current signed prekey: ID, public key, signature | signed prekey private keys |
| one-time prekeys: ID, public key | one-time prekey private keys |
| | shared secrets, `SecureSession` / ratchet state, plaintext |

The API has no field for anything in the right column.

The server is not a trusted cryptographic endpoint. It does not verify the
signed prekey signature, because it could not protect clients by doing so. The
initiator's `ProtocolEngine` verifies the signature and key sizes before X3DH,
whatever server the bundle came from.

## Lifecycle

```kotlin
client.initialize()        // local only: identity, signed prekey, one-time prekeys
client.registerDevice()    // once: registers the device authentication key (milestone 12)
client.publishPreKeys()    // upload the public halves, signed
client.rotateSignedPreKey()// local only
client.publishPreKeys()    // make the new signed prekey current on the server
```

`initialize()` and `rotateSignedPreKey()` never do network I/O. Publishing is
always an explicit call. Since milestone 7, `initialize()` may also rotate the
signed prekey by age, so call `publishPreKeys()` after it. Replaced signed
prekeys stay on the device for their grace period and are never uploaded
([signed-prekey-lifecycle.md](signed-prekey-lifecycle.md)).

`publishPreKeys()` reads the identity key, the current signed prekey and the
public halves of all local one-time prekeys in one `ClientStorage.transaction`.
It then uploads them after that transaction. More than
`PreKeyFormat.MAX_ONE_TIME_PRE_KEYS_PER_PUBLICATION` (1000) one-time prekeys
go out as several publications, each carrying the same identity key and
signed prekey.

## What the server stores

The server keeps state per `DeviceAddress` (user + device). Two devices of the
same user are fully independent.

- **Identity key**: set by the first publication.
- **Current signed prekey**: ID, public key and signature. Older signed
  prekeys are not kept.
- **Available one-time prekeys**: public key by ID.
- **Consumed one-time prekey IDs** (tombstones): IDs that were handed out
  once. They are never handed out again.

## Publication rules

The server treats a publication as untrusted input. `PreKeyService` checks the
format first (`PreKeyFormat.validate`):

- key sizes: 64 bytes, and 64 bytes for the signature
- no repeated one-time prekey ID within the publication
- at most 1000 one-time prekeys

IDs are non-negative by type. Then the repository applies these rules:

| Case | Result |
|------|--------|
| first publication for the address | stores identity key, signed prekey, one-time prekeys |
| different identity key than stored | `IdentityKeyConflict`, nothing changes |
| signed prekey ID higher than current | replaces the current one (rotation) |
| same signed prekey ID, same key and signature | no change |
| same signed prekey ID, other key or signature | `SignedPreKeyConflict`, nothing changes |
| signed prekey ID lower than current | `SignedPreKeyConflict` (stale retry after rotation), nothing changes |
| one-time prekey ID never seen | added |
| one-time prekey ID available, same key | no change (retry) |
| one-time prekey ID available, other key | `OneTimePreKeyConflict`, nothing changes |
| one-time prekey ID already consumed | skipped silently, even with other bytes |

A publication is atomic. The repository checks every rule before it changes
anything, so a rejected publication leaves no partial state. For example, one
conflicting one-time prekey among many also discards the signed prekey update.

### Retries

The same publication sent twice has the same effect as sent once. After a lost
response, the client simply publishes again. Nothing is duplicated, nothing
fails because it already exists, and the identity and signed prekey stay the
same. Idempotency comes from the rules above, not from exactly-once
networking. The client keeps no record of what it has published: it always
re-sends its whole local inventory.

## Bundle consumption

`consumePreKeyBundle(address)` does the following in one atomic step (one lock
hold in the in-memory repository):

1. Finds the device, or returns `null` (HTTP 404).
2. Selects the available one-time prekey with the **lowest ID**.
3. Removes it from the inventory and records its ID as consumed.
4. Returns identity key + current signed prekey + that one-time prekey.

Concurrent fetches never get the same one-time prekey. An empty inventory is
not an error: the bundle then has no one-time prekey, and X3DH runs without
one. Selection order is deterministic on purpose. The security property is
single use, not random order.

## Public vs private one-time prekey lifecycle

These are two separate events:

1. **Server**: hands out public one-time prekey #42 → removes it and tombstones #42.
2. **Recipient client**: accepts the `PreKeyMessage` that used #42 → deletes
   private #42 in the same transaction that stores the new session.

The recipient keeps private #42 until step 2. It needs it to decrypt the first
message. During that time the recipient's next `publishPreKeys()` still
uploads public #42. The tombstone makes the server skip it, so #42 is never
handed out a second time.

If the initiator never sends its first message, or the message is lost, the
recipient keeps private #42 indefinitely. No timeout or reconciliation exists
yet.

## HTTP API v1

Since milestone 12, prekey publication and mailbox drain are authenticated
with the device authentication key, and devices register that key first
(`PUT .../registration`). Headers, signed request format, status codes and
the endpoint policy are in [server-authentication.md](server-authentication.md).
This changed the behavior of API v1 on purpose; the paths stayed the same.

JSON bodies. Binary fields are **Base64 strings, RFC 4648 standard alphabet
with padding**. Decoded sizes are validated. Unknown JSON fields are rejected.
Path segments are URL-encoded user and device IDs.

| Method | Path | Body | Success |
|--------|------|------|---------|
| `PUT` | `/v1/devices/{user}/{device}/registration` | `{"publicKey": "<base64, 32 bytes>"}`, signed | `201 Created` / `204 No Content` |
| `PUT` | `/v1/devices/{user}/{device}/prekeys` | `PreKeyPublicationRequest`, signed | `204 No Content` |
| `GET` | `/v1/devices/{user}/{device}/prekey-bundle` | – | `200` `PreKeyBundleResponse` |
| `POST` | `/v1/messages` | `EncryptedEnvelope` | `202 Accepted` |
| `GET` | `/v1/devices/{user}/{device}/messages` | –, signed | `200` list of `EncryptedEnvelope` |

```json
// PreKeyPublicationRequest (the address comes from the path)
{
  "identityKey": "<base64, 64 bytes>",
  "signedPreKey": { "id": 5, "publicKey": "<base64, 64 bytes>", "signature": "<base64, 64 bytes>" },
  "oneTimePreKeys": [ { "id": 10, "publicKey": "<base64, 64 bytes>" } ]
}

// PreKeyBundleResponse; oneTimePreKey is null (or absent) when none is left
{
  "identityKey": "<base64>",
  "signedPreKey": { "id": 5, "publicKey": "<base64>", "signature": "<base64>" },
  "oneTimePreKey": { "id": 10, "publicKey": "<base64>" }
}

// Error body of 4xx responses
{ "error": "invalid_publication" }
```

| Status | `error` | Cause |
|--------|---------|-------|
| 400 | `invalid_publication` | malformed JSON, unknown field, bad Base64, negative ID, wrong size, repeated ID, too many keys |
| 404 | `device_not_found` | bundle fetch for a device that never published |
| 409 | `identity_key_conflict` | different identity key |
| 409 | `signed_pre_key_conflict` | same signed prekey ID with other bytes, or an older ID |
| 409 | `one_time_pre_key_conflict` | available one-time prekey ID with another key |
| 401 | `missing_authentication`, `invalid_authentication`, `expired_authentication`, `authentication_replay`, `device_not_registered` | authentication failed; checked before the body is parsed ([server-authentication.md](server-authentication.md)) |

`KtorSecureMessageTransport` maps these statuses to
`SecureMessageTransportException`: `DeviceNotFound`,
`PublicationRejected(reason)` and `UnexpectedResponse(status)`. The bundle it
returns carries the requested address; the response has none.

The DTOs exist twice, in `client:ktor` and `server:ktor`.
`server/ktor/src/test` runs the real client adapter against the routes to keep
them in sync. This HTTP API is a transport API and may evolve. It is separate
from the frozen binary ciphertext wire format (`docs/wire-format.md`), which
stays inside `EncryptedEnvelope.payload`.

## Known limitations

- **Host-authorized registration.** Since milestone 12 only the registered
  device can publish for its address, and since S1 an address is registered
  only with the host application's authorization
  ([server-authentication.md](server-authentication.md)).
  Bundle fetches stay public, so anyone can still drain a device's one-time
  prekeys by fetching bundles.
- **No device reset or re-registration.** A device that lost its identity
  cannot publish a new one for the same address (`409 identity_key_conflict`).
- **Server identity checks are not trust.** The server's identity-key check
  is repository consistency only. Clients pin remote identity keys themselves
  (TOFU, see [identity-trust.md](identity-trust.md)) and do not rely on the
  server for identity continuity.
- **Tombstones are never pruned.** Consumed IDs accumulate, one per handed-out
  one-time prekey.
- **Consumed tombstones hide conflicts.** A re-upload of a consumed ID is
  skipped without comparing bytes.
- **No background sync.** The client re-sends its whole inventory on each
  `publishPreKeys()`; it neither tracks what the server has nor refills
  automatically.
- **No persistent server storage.** Only `InMemoryServerStorage` exists; its
  mailboxes are not synchronized.
- **Envelopes** in the `/v1/messages` routes still use kotlinx.serialization's
  default `ByteArray` JSON encoding (array of numbers).
