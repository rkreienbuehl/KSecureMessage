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
can: safety numbers and the verified/unverified state are described in
[identity-verification.md](identity-verification.md).

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
| No pin, first contact succeeds cryptographically | key is pinned, `UNVERIFIED`, together with the new session |
| Same key as pinned | accepted |
| Different key than pinned | `SecureMessageClientException.IdentityChanged`, nothing changes |
| First contact fails (malformed bundle, bad signature, tampered or forged message, storage failure) | nothing is pinned |

A pin is never removed and never replaced by message or bundle processing.
Only `SecureMessageClient.acceptRemoteIdentityChange`, called by the
application after the user approved a specific change, replaces it
(compare-and-set on the old key; the old session is removed and its
initiation retired; the new pin is `UNVERIFIED`), see
[identity-verification.md](identity-verification.md#identity-changes).
There is no API to reset trust or forget a device. A new *session* from the pinned identity is
accepted and replaces the old one; the identity check runs first, so a
different identity never reaches session replacement or collision handling
(see [session-lifecycle.md](session-lifecycle.md)).

`IdentityChanged` carries a `RemoteIdentityChange`: the address, the pinned
key and the presented key, as structured public-key fields for the
application. Its message is `Remote identity changed for <address>` and does
not contain either key.

`SecureMessageClient.remoteIdentityKey(address)` returns the pinned key, or
`null`; `remoteIdentityTrust(address)` adds its verification state.

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

**Sender address (S1, finding F4).** The pin is stored under the envelope's
sender address, so that address must be authenticated too, before the pin
is written:

- the server queues an envelope only if its sender is the device that signed
  the submission (docs/server-authentication.md, "Message submission"), so a
  malicious client cannot claim `alice/phone` with its own identity key;
- a new first contact is always a session initiation version 2, whose
  associated data binds sender and recipient address, so a relay that
  rewrites either address makes the first message fail to decrypt
  ([session-lifecycle.md](session-lifecycle.md#session-initiation-version-2-s1));
- a version 1 `PreKeyMessage` never writes a first pin.

Order: pin check (refusal only) → authenticate the initiation with the
address-bound transcript → write the pin in the same transaction as the
session. A malicious server can still fabricate a first contact with a key
of its choice, as it can hand out a bundle with a key of its choice; that is
the TOFU trust in the server that safety numbers
([identity-verification.md](identity-verification.md)) detect.

`RatchetMessage`s carry no identity key. They rely on the identity binding
of the session (the associated data is the version 2 transcript with both
identity keys and addresses, or `initiatorIdentityKey || responderIdentityKey`
for sessions from before S1) and on the pin made when the session was set
up.

## Atomicity and concurrency

Check, crypto work, pin and session writes run in one storage transaction.
Storage transactions are serialized (a `Mutex`, plus a SQLite transaction in
the SQLDelight adapter). Two contradictory first contacts for the same
address therefore cannot both pass the "no pin yet" check: the first one to
commit wins, and the other one fails with `IdentityChanged`. As a second
barrier, `RemoteIdentityStore.store` refuses to overwrite a different key and
the SQLDelight table has a primary key on the address.

Accepting identity changes is serialized the same way and is a
compare-and-set on the pinned key, so of two competing acceptances only one
succeeds.

Tests: `RemoteIdentityTrustTest`, `FirstContactAtomicityTest`,
`IdentityVerificationTest` and `IdentityChangeAcceptanceTest`
(`client:core`), the `ClientStorageContractTest` cases for remote identities,
`SqlDelightPersistenceTest`, and `HttpEndToEndTest` (`server:ktor`).

## Persistence

Pins are stored in `ClientStorage.remoteIdentities` and survive restarts with
a persistent adapter. `storage:client:sqldelight` keeps them in the
`remote_identity` table (added in schema version 2, see
[storage.md](storage.md); the `verification` column since schema version 10).

## Sessions from before pinning

A database written before milestone 5 can hold sessions without a pin. The
client does not invent a pin from the envelope's sender address. Such
sessions keep working.

**S1, finding F9.** Before S1 the first `PreKeyMessage` that decrypted on such
a session pinned the message's identity key. The engine only checked that
the key was the *first* half of the session's associated data, which is the
initiator's key. In a session this device had initiated, that is the
**local** identity key: a relay could wrap the peer's genuine ratchet
message in a `PreKeyMessage` naming the victim's own key, it decrypted, and
the victim pinned its own identity key as the peer's (later `IdentityChanged`
denial of service, wrong safety number).

Since S1:

- a `PreKeyMessage` on an existing session is accepted only if this device
  is the session's **responder** (the responder slot is the local key and
  the initiator slot is not) and the message names the initiator key;
  otherwise `InvalidMessage` and nothing changes;
- a legacy session is pinned only with
  `ProtocolEngine.sessionRemoteIdentityKey(session, localIdentityKey)`: the
  one of the session's two identity keys that is not the local one, and only
  if exactly one slot is the local key and it equals the message's key.
  Otherwise (both or neither slot is local) nothing is pinned; no pin is
  ever guessed;
- ratchet messages never pin.

What happens to an unpinned session, as implemented (S1.1, finding D4; S1
docs said a locally initiated one "stays unpinned until an authenticated new
initiation replaces it", which the S1 code did not do):

- **Replacement by a version 2 initiation** is accepted only if the
  initiation names exactly `sessionRemoteIdentityKey(session, localKey)`,
  the identity the session was established with as remote (the same check
  that pins it from a repetition). The new session is then pinned to that
  key. Any other key, or a session where that key cannot be determined
  (both or neither slot local), is refused with `InvalidMessage` and
  nothing changes: there is no identity to hold another key against. Such a
  session is never replaced by the protocol; it keeps working as it is, and
  only the application can remove it (for example by resetting the local
  session store). Before S1.1 every replacement of an unpinned session was
  refused, which after S1 left no way out for a session this device had
  initiated (its peer can no longer send the version 1 repetition that pins
  it).
- **An unanswered version 1 initiation of this device** (pending, never
  replied to) is replaced by any authenticated version 2 initiation, pinned
  or not (S1.1, finding N3, [session-lifecycle.md](session-lifecycle.md)):
  nothing was ever established on it, so accepting is ordinary first
  contact, and the new key is pinned on acceptance. A pin that exists is
  still checked first (`IdentityChanged`).

Tests: `SecurityReviewRegressionTest`, `SessionLifecycleTest`
(`sessionWithoutPinIsNeverReplacedByAnotherIdentity`, `n3…`) in
`client:core`; `SessionInitiationV2Test` (`core:protocol`).

## Limitations

- First contact is not authenticated (see above). Manual verification
  ([identity-verification.md](identity-verification.md)) closes the gap only
  if the user compares safety numbers.
- An identity change is accepted only explicitly, per device; there is no
  automatic reset.
- Pinned keys are stored unencrypted (not sealed) even in the SQLDelight
  adapter. They are public keys, but they identify contacts.
