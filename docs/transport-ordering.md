# Transport ordering

This document describes the one delivery-order guarantee KSecureMessage needs,
why it is needed, and where it is enforced. It is a follow-up to milestone 6
([session-lifecycle.md](session-lifecycle.md)). Wire v1 and the HTTP API v1
are unchanged.

Code: `SecureMessageClient.send` / `decrypt` (`client:core`),
`MailboxRepository` (`storage:core`), `InMemoryServerStorage` (`storage:inmemory`),
`SecureMessageServer.relay` / `receive` (`server:core`).
Tests: `SessionReorderingTest` (`client:core`), `MailboxRepositoryContractTest`
(`storage:testing`, run by `InMemoryMailboxRepositoryTest`),
`KSecureMessageRoutesTest.eachSendersEnvelopesArriveInSendOrderOverHttp`.

## The contract

> For each ordered pair (sender device S, recipient device R), a
> `PreKeyMessage` from S must be processed by R before every envelope that S
> handed to the transport for R after it.

The server cannot see message types, so it enforces the stronger and simpler
**per (sender `DeviceAddress`, recipient `DeviceAddress`) FIFO**. Three links
are needed, and each one is enforced or specified at a concrete place:

| Link | Guarantee | Where |
|---|---|---|
| Sender | Envelopes reach the transport in the order they were encrypted | `SecureMessageClient.send` holds a per-client `Mutex` around `encrypt` and `transport.send` |
| Server | Per (sender, recipient): drained in the order the `enqueue` calls returned; each envelope in exactly one drain | `MailboxRepository` contract; `InMemoryServerStorage` serializes enqueue and drain with a `Mutex`. HTTP: `POST /v1/messages` answers 202 after the enqueue returned |
| Receiver | One sender's envelopes are decrypted one at a time, in drain order | The application's receive loop (documented on `SecureMessageClient.decrypt` and `SecureMessageTransport.receive`) |

Things that are **not** required, and not promised by `MailboxRepository`:

- Order between different senders to the same recipient.
- Order between one sender's envelopes to different recipients.
- Order among the `RatchetMessage`s of one session. That is message-level
  reordering inside one Double Ratchet. Kodium's skipped-message keys handle
  it, and KSecureMessage does not add anything on top.
- Order among repeated `PreKeyMessage`s of one initiation. They all decrypt on
  the session they created (session-lifecycle step 2).

So a mailbox may be sharded by sender, and a recipient's envelopes from
different senders may interleave in any way.

## The problem

Session-level ordering is different from ratchet-level ordering. The problem
is a `PreKeyMessage` of one initiation arriving after a message from a *later*
session of the same sender.

### Simultaneous initiation

W's initiation `w` is smaller than L's initiation `l`, so `w` wins
(session-lifecycle, "Simultaneous initiation").

```
W (pending w)                        L (pending l)
   |---- P_W (PreKeyMessage, w) ------->|
   |<--- P_L (PreKeyMessage, l) --------|   enqueued first
   |                                    |  receives P_W: l > w, accepts w, retires l
   |<--- R   (RatchetMessage on w) -----|   enqueued second
```

- **Contract order `P_L`, `R`:** W is still pending on `w`, so `P_L` loses the
  collision (step 7, `SessionCollision`, `l` retired). `R` then decrypts on
  `w`. Both sides are on `w`.
- **Reordered `R`, `P_L`:** `R` decrypts on `w`, and W's session is no longer
  awaiting a reply. `P_L` now looks like a replacement of an established
  session (step 8). W accepts `l` and retires `w`. W is on `l` and L is on
  `w`. Each side has retired the other's session and rejects its traffic for
  good. `replyOvertakingTheLosingPreKeyMessageSplitsTheSessions` records this.

Inside the library, this order came from a race. `send` used to encrypt and
then hand off without ordering. If L's `send(P_L)` was slow in
`transport.send` while L accepted `P_W` and sent `R`, then `R` reached the
server first. `slowSendOfTheLosingPreKeyMessageIsNotOvertakenByTheReply`
failed before the send mutex was added. The in-memory mailbox was also not
synchronized: concurrent producers lost envelopes
(`concurrentProducersLoseNothingAndKeepEachStreamsOrder` failed with 2185 of
3200 envelopes).

### State loss

S sends `P(x)` and then loses its session state. It starts again and sends
`P(x')`. If `P(x')` is delivered first, R accepts `x'`, and the late `P(x)`
then replaces it with an initiation S no longer has. The contract order
`P(x)`, `P(x')` converges on `x'`.

## Why the client cannot fix this on wire v1

When W receives the late `P_L`, it cannot tell it apart from a legitimate new
initiation `l'` that L started after losing its state. In both cases the
initiation is fresh, never retired, and comes from the pinned identity. Both
were created while L had no session. Wire v1 carries nothing authenticated that
says "created before or after L accepted `w`". So:

- **Deferring the message** does not help. There is no signal about which
  session the message belongs to, so nothing to defer on.
- **Candidate sessions** (keeping `w` and `l` for a while) do not help. Only
  later traffic from L could decide, and that traffic has the same ordering
  problem.
- **Rejecting larger IDs once confirmed** ("reject `x > origin` once the own
  initiation was confirmed") would reject about half of all legitimate
  replacements. The replacing peer would then be stuck waiting for a reply for
  good.

A wire v2 field could fix the collision case, for example ratchet messages
that authenticate "I retired `l`". It could not fix the state-loss case,
because the sender no longer knows its old initiation. An ordering guarantee is
therefore needed either way. It is enforced at the transport rather than
changing the wire format.

## Why the contract is enough

Assume the three links hold. A divergence needs R to accept `P(x)` from S at a
time when S has already moved away from `x`. S moves away in one of two ways.

1. **S accepted R's initiation `y` while pending on `x`, with `y < x`.** S
   sent `P(x)` before that, and every envelope S sends to R afterwards comes
   after `P(x)`. So R processes `P(x)` before any message S sent on `y`. R's
   session is then still its own pending `y`, and `x > y`, so step 7 applies:
   `x` loses and is retired. Both sides end on `y`.
2. **S lost its state, or removed its session.** `P(x)` is processed before
   `P(x')`. R accepts `x`, and `P(x')` then replaces it through step 8. Both
   sides end on `x'`.

It is also necessary: swapping only `P_L` and `R` in the example above
produces the split.

## Behavior by kind of traffic

| Traffic | Behavior |
|---|---|
| Current session | Decrypts. Message-level reordering is left to Kodium. |
| Repeated `PreKeyMessage` of the current initiation | Decrypts on the current session (step 2). |
| Losing initiation, before the reply (contract order) | The first message gets `SessionCollision`, later ones `StaleSessionInitiation`. The winning session is unchanged. |
| Losing initiation, delivered again later | `StaleSessionInitiation`, no crypto, nothing changes. There is no rollback. |
| Old session's `PreKeyMessage` after a replacement | `StaleSessionInitiation`. |
| Old session's `RatchetMessage` after a replacement | Fails on the new session with a `ProtocolException` and changes nothing. There is no grace window for old sessions, and the client never switches back. |
| Different identity key | `IdentityChanged` before any of the above (M5). |

No messages are buffered or deferred, and no candidate or previous sessions
are kept. There is no new client state, so nothing to bound or migrate.

## Restarts

All decisions depend only on persisted state: the session and its origin, the
retired initiations, and the pins. Restarting either side at any point in the
exchange (both pending; L switched but not replied; W after the collision but
before the reply) gives the same result
(`restartsDuringTheSwitchKeepTheSameOutcome`). The send mutex exists only in
memory. That is enough: an envelope whose `send` was interrupted by a restart
was either enqueued before the restart or never, and the client does not resend
it.

## Obligations of an application

- Use `SecureMessageClient.send`. If you use `encrypt` with your own
  transport, hand envelopes for one recipient over in encryption order.
- Do not resend an envelope after a later envelope for the same recipient was
  handed over. Losing an envelope is safe; sending it late is not.
- Process a drained batch in order, one `decrypt` at a time. Do not run two
  receive loops for one device concurrently.
- A server or mailbox implementation must satisfy `MailboxRepository`'s
  contract. Run `MailboxRepositoryContractTest` against it.

## Remaining limitations

- A malicious or faulty relay that breaks per-pair FIFO can still split two
  sessions. That is denial of service, like dropping messages, which a relay
  can always do. It exposes no plaintext and no keys.
- Withheld initiations: an old initiation that never reached the device is
  accepted as new ([session-lifecycle.md](session-lifecycle.md#limitations)).
- The receive-side order depends on the application's receive loop. The
  library has no receive loop of its own.
- `send` serializes all sends of one client, including sends to different
  recipients.
- Messages lost to a collision are not resent. That needs delivery
  acknowledgements, which are out of scope.
