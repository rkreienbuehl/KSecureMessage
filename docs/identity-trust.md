# Remote identity trust (TOFU)

This document describes how a KSecureMessage client decides whether to trust
the identity key of a remote device. The client uses trust on first use
(TOFU).

Code: `client/core/.../client/RemoteIdentityTrust.kt`, `SecureMessageClient.kt`.
Storage contract: `RemoteIdentityStore` in `storage/core/.../storage/ClientStorage.kt`.

## What TOFU does and does not do

**TOFU detects unexpected identity changes after first contact. It does not
authenticate the human identity of the remote party on first contact.**

The client remembers the first cryptographically valid identity key it sees
for a remote device and rejects a different key for that device later. If the
server hands out an attacker's keys before the first contact, the client pins
the attacker's key. TOFU cannot detect that. Only out-of-band verification
can, and it is not implemented yet: there are no safety numbers, fingerprints,
QR codes or verified/unverified states.

Why this is needed: signed prekey verification proves only that the signed
prekey belongs to the identity key *in the same bundle*. A malicious server
can return a bundle with its own identity key and a signed prekey it signed
itself, and that bundle verifies. The pin catches this after the first
contact. The server's own identity-key conflict check
([prekey-publication.md](prekey-publication.md)) keeps the repository
consistent. It is not a trust mechanism, and the client enforces continuity
even when the server is malicious.

## Rules

Trust is scoped to a `DeviceAddress` (user ID and device ID). Two devices of
the same user have separate pins and may have different identity keys.

| Situation | Result |
|---|---|
| No pin, first contact succeeds cryptographically | key is pinned together with the new session |
| Same key as pinned | accepted |
| Different key than pinned | `SecureMessageClientException.IdentityChanged(address)`, nothing changes |
| First contact fails (malformed bundle, bad signature, tampered or forged message, storage failure) | nothing is pinned |

A pin is never replaced or removed. There is no API to accept a changed
identity, reset trust or forget a device. Device reset and re-registration
are out of scope for now. A new *session* from the pinned identity is
accepted and replaces the old one; the identity check runs first, so a
different identity never reaches session replacement or collision handling
(see [session-lifecycle.md](session-lifecycle.md)).

`IdentityChanged` carries the address only. Its message is
`Remote identity changed for <address>`. It does not contain either key.

`SecureMessageClient.remoteIdentityKey(address)` returns the pinned key, or
`null`. It is public key material and is meant for later verification
features.

## Initiator

Alice starts a session with Bob (`encrypt`, `send` or `ensureSession`
without a stored session):

1. Fetch Bob's `PreKeyBundle`. This happens **outside** any storage
   transaction.
2. Open one `ClientStorage.transaction`:
   1. The bundle's address must be Bob's address, otherwise
      `ProtocolException.InvalidPreKeyBundle`.
   2. Compare `bundle.identityKey` with the pin for Bob. A different key
      throws `IdentityChanged` before anything is written.
   3. `ProtocolEngine.initiateSession` checks key sizes and the signed prekey
      signature, then runs X3DH. Any failure throws and nothing is written.
   4. If Bob had no pin, pin `bundle.identityKey`.
   5. Encrypt and store the session.
3. The transaction commits the pin and the session together or not at all.

The pin is written only after the bundle passed validation. A server cannot
use a malformed bundle or a bad signature to plant a pin.

## Responder

Bob receives an envelope from Alice:

1. Decode the wire message, outside the transaction.
2. Open one `ClientStorage.transaction`:
   1. If it is a `PreKeyMessage`, compare its `identityKey` with the pin for
      Alice's address. A different key throws `IdentityChanged` before any
      crypto or write. The existing session, the pin and all one-time prekeys
      stay unchanged.
   2. With an existing session, decrypt on it. Repeated `PreKeyMessage`s from
      the same initiator work as before; the engine also checks that the key
      matches the session.
   3. Without a session, `acceptSession` runs X3DH and decrypts the first
      message. Then the new session is stored and the consumed one-time
      prekey is removed.
   4. If Alice had no pin and the message was a `PreKeyMessage`, pin its
      identity key.
3. Session, one-time prekey removal and pin commit together or not at all.

The identity key in a `PreKeyMessage` is only a claim until decryption
succeeds. The X3DH secret and the associated data depend on it, so a message
with a swapped or forged key fails to decrypt. Then nothing is pinned, no
session is stored and the one-time prekey stays available.

`RatchetMessage`s carry no identity key. They rely on the identity binding
of the session (the associated data is
`initiatorIdentityKey || responderIdentityKey`) and on the pin made when the
session was set up. The wire format is unchanged.

## Atomicity and concurrency

Check, crypto work, pin and session writes run in one storage transaction.
Storage transactions are serialized (a `Mutex`, plus a SQLite transaction in
the SQLDelight adapter). Two contradictory first contacts for the same
address therefore cannot both pass the "no pin yet" check: the first one to
commit wins, and the other one fails with `IdentityChanged`. As a second
barrier, `RemoteIdentityStore.store` refuses to overwrite a different key and
the SQLDelight table has a primary key on the address.

Tests: `RemoteIdentityTrustTest` and `FirstContactAtomicityTest`
(`client:core`), the `ClientStorageContractTest` cases for remote identities,
`SqlDelightPersistenceTest`, and `HttpEndToEndTest` (`server:ktor`).

## Persistence

Pins are stored in `ClientStorage.remoteIdentities` and survive restarts with
a persistent adapter. `storage:client:sqldelight` keeps them in the
`remote_identity` table (added in schema version 2, see
[storage.md](storage.md)).

## Sessions from before pinning

A database written before milestone 5 can hold sessions without a pin. The
client does not invent a pin from the envelope's sender address, which is
unauthenticated routing data. Such sessions keep working. The first
`PreKeyMessage` that decrypts successfully on such a session pins its
identity key, because the engine has checked it against the session.

A session whose peer already sends `RatchetMessage`s stays unpinned. Such a
session is never replaced by a new initiation: without a pin there is no
identity to check the new initiation against
([session-lifecycle.md](session-lifecycle.md)). A stronger migration is possible later: the stored
session state contains both identity keys as associated data, so a narrow
`ProtocolEngine` method could return the remote one. It is not implemented.

## Limitations

- First contact is not authenticated (see above).
- No safety numbers or manual verification.
- No way to accept a legitimate identity change (reinstall, device reset).
  The only outcome is `IdentityChanged`.
- No authenticated server API.
- Pinned keys are stored unencrypted like all client state. They are public
  keys, but they identify contacts.
