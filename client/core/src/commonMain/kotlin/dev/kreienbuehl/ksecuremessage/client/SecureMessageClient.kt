package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.CiphertextMessage
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.protocol.SecurePayload
import dev.kreienbuehl.ksecuremessage.protocol.SecurePayloadCodec
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionAcceptanceResult
import dev.kreienbuehl.ksecuremessage.protocol.SessionInfo
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Clock
import kotlin.uuid.Uuid

/**
 * Sends and receives messages for [localAddress]. Envelope payloads are
 * [CiphertextMessageCodec]-encoded ciphertext messages; their plaintext is a
 * [SecurePayloadCodec] reliability frame.
 *
 * Messages are reliable across collisions, lost envelopes and lost
 * acknowledgements (docs/message-reliability.md). [send] gives each
 * application message a [LogicalMessageId] and keeps it pending, plaintext
 * included, until the recipient acknowledges it. [decrypt] returns each
 * logical message of a sender at most once and answers it with an encrypted
 * acknowledgement. [retryPendingMessages] encrypts pending messages again,
 * under the current session and with the same logical ID. Both peers must
 * use this frame (milestone 8); raw plaintext from older peers is rejected.
 *
 * The client owns its local protocol state in [storage]: identity key,
 * signed prekeys, one-time prekeys and sessions. Call [initialize] once per
 * start before anything else; it creates missing state and keeps existing
 * state. Other operations never create an identity on their own. Before the
 * first [initialize] on a storage they throw
 * [SecureMessageClientException.NotInitialized]. Storage is read on every
 * operation; the client caches nothing.
 *
 * Every operation stores the new session state in the same
 * [ClientStorage.transaction] as the crypto work. A failed encrypt or decrypt
 * leaves the stored state as it was. Network calls happen outside
 * transactions.
 *
 * [initialize] and [rotateSignedPreKey] change local state only. Call
 * [publishPreKeys] afterwards to upload the public material.
 *
 * Signed prekeys expire (docs/signed-prekey-lifecycle.md). A replaced signed
 * prekey stays usable for new sessions for
 * [PreKeyConfiguration.signedPreKeyGracePeriod]; after that, initiations that
 * name it fail with [SecureMessageClientException.ExpiredSignedPreKey] and
 * [initialize] deletes it. Established sessions are not affected. [initialize]
 * also rotates the current signed prekey once it is
 * [PreKeyConfiguration.signedPreKeyRotationAge] old, so long-running
 * applications call [initialize] periodically, followed by [publishPreKeys].
 * Time comes from [clock].
 *
 * Remote identity keys are trusted on first use (docs/identity-trust.md).
 * The first identity key that sets up a session with a remote device, as
 * initiator or responder, is pinned in the same transaction that stores the
 * session. A different key for that device later fails with
 * [SecureMessageClientException.IdentityChanged] and changes nothing. This
 * detects identity changes after first contact; it does not prove who the
 * remote party is on first contact.
 *
 * A sender with the pinned identity may set up a new session while one
 * exists (lost session state, simultaneous initiation); see
 * docs/session-lifecycle.md. The new session replaces the old one atomically.
 * Initiations that were replaced or lost a collision are retired and
 * rejected for good ([SecureMessageClientException.StaleSessionInitiation]).
 * When both sides initiate at once, both keep the initiation with the smaller
 * [SessionInitiationId]; the losing one's messages fail with
 * [SecureMessageClientException.SessionCollision] and are not delivered.
 *
 * Sessions converge only if, per (sender, recipient) pair, a PreKeyMessage is
 * processed before every envelope the sender handed to the transport after
 * it (docs/transport-ordering.md). [send] hands envelopes over in encryption
 * order; the server keeps them in that order per pair; the application must
 * [decrypt] one sender's envelopes one at a time, in the order
 * [SecureMessageTransport.receive] returned them.
 *
 * Not handled yet: identity changes cannot be accepted, pending messages are
 * not retried automatically, and prekeys are not published automatically.
 */
class SecureMessageClient(
    val localAddress: DeviceAddress,
    private val storage: ClientStorage,
    private val protocol: ProtocolEngine,
    private val transport: SecureMessageTransport,
    preKeyConfiguration: PreKeyConfiguration = PreKeyConfiguration(),
    clock: Clock = Clock.System,
) {
    private val preKeyManager = PreKeyManager(protocol, preKeyConfiguration, clock)

    /**
     * Keeps every hand-off to the transport (messages, retries,
     * acknowledgements) in encryption order.
     */
    private val sendMutex = Mutex()

    /**
     * Makes sure the local identity, a current signed prekey and
     * [PreKeyConfiguration.oneTimePreKeyTarget] one-time prekeys exist, and
     * runs signed prekey maintenance: rotation of a current key that reached
     * [PreKeyConfiguration.signedPreKeyRotationAge], deletion of replaced keys
     * whose grace period is over, and removal of retired session initiations
     * that only those keys could accept. All in one transaction. An existing
     * identity is never replaced. Safe to call repeatedly. No network I/O: call
     * [publishPreKeys] afterwards, a rotation changes the published signed
     * prekey.
     */
    suspend fun initialize() {
        storage.transaction { with(preKeyManager) { ensureInitialized() } }
    }

    /**
     * The public prekey data to publish: identity key and current signed
     * prekey. [PreKeyBundle.oneTimePreKey] is always `null`. Which one-time
     * prekey a fetcher gets is up to the server, see [publicOneTimePreKeys].
     */
    suspend fun currentPreKeyBundle(): PreKeyBundle = storage.transaction {
        val identity = requireIdentity()
        val signedPreKey = preKeys.currentSignedPreKey() ?: throw SecureMessageClientException.NotInitialized()
        PreKeyBundle(
            address = localAddress,
            identityKey = identity.publicKey,
            signedPreKey = signedPreKey.toPublic(),
            oneTimePreKey = null,
        )
    }

    /**
     * Public halves of all unused local one-time prekeys, for upload to a
     * server. Nothing is reserved or marked as published: a key is only
     * removed when a session is accepted with it.
     */
    suspend fun publicOneTimePreKeys(): List<PublicOneTimePreKey> = storage.transaction {
        requireIdentity()
        preKeys.publicOneTimePreKeys()
    }

    /**
     * Replaces the current signed prekey with a new one and returns its
     * public half. The old private key stays stored for
     * [PreKeyConfiguration.signedPreKeyGracePeriod], so first-contact messages
     * that still use it can be decrypted. Local only: call [publishPreKeys]
     * afterwards.
     */
    suspend fun rotateSignedPreKey(): PublicSignedPreKey =
        storage.transaction { with(preKeyManager) { rotateSignedPreKey() } }.toPublic()

    /**
     * Uploads the public prekey material: identity key, current signed prekey
     * and the public halves of all local one-time prekeys. Private keys never
     * leave the device.
     *
     * The keys are read in one transaction; the upload happens after it. More
     * one-time prekeys than [PreKeyFormat.MAX_ONE_TIME_PRE_KEYS_PER_PUBLICATION]
     * are sent in several publications. Publishing again, also after a failed
     * or lost request, is safe: the server ignores keys it already has and
     * never hands out a one-time prekey twice.
     */
    suspend fun publishPreKeys() {
        val publications = storage.transaction {
            val identity = requireIdentity()
            val signedPreKey = preKeys.currentSignedPreKey() ?: throw SecureMessageClientException.NotInitialized()
            preKeys.publicOneTimePreKeys()
                .chunked(PreKeyFormat.MAX_ONE_TIME_PRE_KEYS_PER_PUBLICATION)
                .ifEmpty { listOf(emptyList()) }
                .map { batch ->
                    PreKeyPublication(localAddress, identity.publicKey, signedPreKey.toPublic(), batch)
                }
        }
        // Outside the transaction: it must not wait for the network.
        for (publication in publications) transport.publishPreKeys(publication)
    }

    /**
     * The identity key pinned for [remote], or `null` if there was no
     * successful first contact with it yet (or only before identity keys
     * were pinned). Public key material.
     */
    suspend fun remoteIdentityKey(remote: DeviceAddress): ByteArray? = storage.transaction {
        requireIdentity()
        remoteIdentities.identityKey(remote)
    }

    suspend fun ensureSession(remote: DeviceAddress): SecureSession {
        val bundle = fetchBundleIfNoSession(remote)
        return storage.transaction {
            sessions.load(remote) ?: initiateSession(remote, bundle).also { sessions.store(it) }
        }
    }

    /**
     * Sends [plaintext] to [remote] as a new logical message and returns its
     * [LogicalMessageId] and the envelope of this first attempt. Starts a
     * session if there is none. Bodies larger than
     * [SecurePayloadCodec.MAX_BODY_SIZE] are rejected with
     * [ProtocolException.MessageTooLarge].
     *
     * The message is stored as pending (with its plaintext, see
     * docs/message-reliability.md) in the same transaction as the ratchet
     * step that encrypts it; the envelope is handed to the transport after
     * the commit. It stays pending until [remote] acknowledges it; a
     * successful hand-off does not remove it. Use [retryPendingMessages] to
     * send pending messages again.
     *
     * Failures: an exception other than
     * [SecureMessageClientException.MessageNotSent] means nothing was stored.
     * [SecureMessageClientException.MessageNotSent] means the message is
     * pending but the transport did not take the envelope; its cause is the
     * transport's exception.
     *
     * Sends of this client run one at a time, so envelopes reach the
     * transport in encryption order (docs/transport-ordering.md).
     */
    suspend fun send(remote: DeviceAddress, plaintext: ByteArray): SentMessage {
        val id = LogicalMessageId.random()
        val frame = SecurePayloadCodec.encode(SecurePayload.ApplicationMessage(id, plaintext))
        // Held across the network call, never inside a storage transaction.
        return sendMutex.withLock {
            val bundle = fetchBundleIfNoSession(remote)
            val envelope = try {
                storage.transaction {
                    pendingOutbound.store(remote, id, frame)
                    encryptOn(remote, bundle, frame)
                }
            } finally {
                frame.fill(0)
            }
            handOff(id, envelope)
            SentMessage(id, envelope)
        }
    }

    /**
     * Sends every message pending for [remote] again, oldest first, and
     * returns the IDs whose new envelope the transport took. Each attempt is
     * a fresh encryption under the current session with a new envelope ID;
     * the logical ID stays. Messages stay pending until [remote]
     * acknowledges them, so calling this again sends them again; the
     * recipient delivers each logical message only once.
     *
     * The client never keeps a session it knows lost a collision, so a retry
     * always uses the session this device currently has. Call it after
     * processing received envelopes, for example after a
     * [SecureMessageClientException.SessionCollision] or once the application
     * suspects a lost acknowledgement. There is no automatic retry.
     *
     * Stops at the first envelope the transport does not take, with
     * [SecureMessageClientException.MessageNotSent]: sending later messages
     * first would change their order. Encryption failures are thrown as they
     * are and leave that message pending and its session unchanged.
     */
    suspend fun retryPendingMessages(remote: DeviceAddress): List<LogicalMessageId> = sendMutex.withLock {
        val ids = storage.transaction {
            requireIdentity()
            pendingOutbound.list(remote).map { it.id }
        }
        val sent = mutableListOf<LogicalMessageId>()
        for (id in ids) {
            val bundle = fetchBundleIfNoSession(remote)
            val envelope = storage.transaction {
                // Acknowledged since the list was read: nothing to resend.
                val pending = pendingOutbound.get(remote, id) ?: return@transaction null
                try {
                    encryptOn(remote, bundle, pending.frame)
                } finally {
                    pending.frame.fill(0)
                }
            } ?: continue
            handOff(id, envelope)
            sent += id
        }
        sent
    }

    /** The messages to [remote] that are not acknowledged yet, oldest first. Contains their plaintext. */
    suspend fun pendingMessages(remote: DeviceAddress): List<PendingMessage> {
        val pending = storage.transaction {
            requireIdentity()
            pendingOutbound.list(remote)
        }
        return pending.map {
            val payload = SecurePayloadCodec.decode(it.frame) as SecurePayload.ApplicationMessage
            it.frame.fill(0)
            PendingMessage(it.recipient, it.id, payload.body)
        }
    }

    /**
     * Decrypts and processes [envelope] (docs/message-reliability.md).
     *
     * - A new application message is marked processed in the same
     *   transaction as its ratchet step and returned as
     *   [ReceiveResult.Message]; this client then sends an encrypted
     *   acknowledgement to the sender.
     * - A message whose logical ID was already processed is returned as
     *   [ReceiveResult.Duplicate] without its plaintext and acknowledged
     *   again.
     * - An acknowledgement removes the matching pending message sent to this
     *   sender ([ReceiveResult.Acknowledgement]). It is never acknowledged.
     *
     * A failed acknowledgement does not fail this call: the result says
     * `ackSent = false` and the sender's next retry triggers a new one.
     *
     * Delivery is at most once per (sender, logical ID): once this returns a
     * [ReceiveResult.Message], the same message is never returned again, even
     * if the application crashes before it handled it.
     *
     * Failures change nothing, except that a
     * [SecureMessageClientException.SessionCollision] retires the losing
     * initiation; its message is not acknowledged, so its sender keeps it
     * pending and can send it again on the winning session. A decrypted
     * plaintext that is not a reliability frame (for example from a peer
     * before milestone 8) fails with
     * [ProtocolException.MalformedSecurePayload] or
     * [ProtocolException.UnsupportedSecurePayloadVersion].
     *
     * Envelopes from one sender must be decrypted one at a time, in the order
     * the transport delivered them (docs/transport-ordering.md).
     */
    suspend fun decrypt(envelope: EncryptedEnvelope): ReceiveResult {
        val message = decodeEnvelope(envelope)
        val sender = envelope.sender
        val processed = storage.transaction {
            when (val received = receive(sender, message)) {
                Received.CollisionLost -> null
                is Received.Plaintext -> process(sender, received.plaintext)
            }
        }
        // Thrown after the commit, so the retired initiation is kept. The
        // plaintext was discarded unread: no acknowledgement.
        processed ?: throw SecureMessageClientException.SessionCollision(sender)
        return when (processed) {
            is Processed.New -> ReceiveResult.Message(sender, processed.id, processed.body, acknowledge(sender, processed.id))
            is Processed.Duplicate -> ReceiveResult.Duplicate(sender, processed.id, acknowledge(sender, processed.id))
            is Processed.Acknowledged -> ReceiveResult.Acknowledgement(sender, processed.id, processed.cleared)
        }
    }

    /**
     * Applies a decrypted reliability frame inside the receive transaction.
     * A malformed frame throws, which rolls back the ratchet step too.
     */
    private suspend fun ClientStorage.process(sender: DeviceAddress, plaintext: ByteArray): Processed {
        val payload = try {
            SecurePayloadCodec.decode(plaintext)
        } finally {
            plaintext.fill(0)
        }
        return when (payload) {
            is SecurePayload.ApplicationMessage ->
                if (processedInbound.isProcessed(sender, payload.id)) {
                    payload.body.fill(0)
                    Processed.Duplicate(payload.id)
                } else {
                    processedInbound.markProcessed(sender, payload.id)
                    Processed.New(payload.id, payload.body)
                }
            // Scoped to the sender: only the device a message went to can clear it.
            is SecurePayload.Acknowledgement -> Processed.Acknowledged(payload.id, pendingOutbound.remove(sender, payload.id))
        }
    }

    /**
     * Sends an acknowledgement of [id] to [remote] on the existing session.
     * Never starts a session and is never stored as pending. Returns `false`
     * instead of throwing if encryption or the hand-off fails.
     */
    private suspend fun acknowledge(remote: DeviceAddress, id: LogicalMessageId): Boolean {
        val frame = SecurePayloadCodec.encode(SecurePayload.Acknowledgement(id))
        return try {
            sendMutex.withLock {
                // No bundle: without a session the encryption fails.
                val envelope = storage.transaction { encryptOn(remote, bundle = null, frame) }
                transport.send(envelope)
            }
            true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
    }

    /** Hands [envelope] to the transport; a failure leaves message [id] pending. */
    private suspend fun handOff(id: LogicalMessageId, envelope: EncryptedEnvelope) {
        try {
            transport.send(envelope)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw SecureMessageClientException.MessageNotSent(id, e)
        }
    }

    // Session layer: raw plaintext, no reliability frame, no acknowledgements.
    // Used by the reliability layer above and by tests of session behavior.

    /**
     * Encrypts raw [plaintext] for [remote], starting a session if there is
     * none. The caller must hand envelopes for one recipient to the transport
     * in the order they were encrypted (docs/transport-ordering.md).
     */
    internal suspend fun encryptRaw(
        remote: DeviceAddress,
        plaintext: ByteArray,
        id: MessageId = newEnvelopeId(),
    ): EncryptedEnvelope {
        val bundle = fetchBundleIfNoSession(remote)
        return storage.transaction { encryptOn(remote, bundle, plaintext, id) }
    }

    /** [encryptRaw] plus hand-off, in encryption order. */
    internal suspend fun sendRaw(remote: DeviceAddress, plaintext: ByteArray): EncryptedEnvelope =
        sendMutex.withLock { encryptRaw(remote, plaintext).also { transport.send(it) } }

    /**
     * Decrypts [envelope] and returns the raw plaintext. Failures change
     * nothing, except that a [SecureMessageClientException.SessionCollision]
     * retires the losing initiation.
     */
    internal suspend fun decryptRaw(envelope: EncryptedEnvelope): ByteArray {
        val message = decodeEnvelope(envelope)
        val received = storage.transaction { receive(envelope.sender, message) }
        // Thrown after the commit, so the retired initiation is kept.
        return when (received) {
            is Received.Plaintext -> received.plaintext
            Received.CollisionLost -> throw SecureMessageClientException.SessionCollision(envelope.sender)
        }
    }

    private fun decodeEnvelope(envelope: EncryptedEnvelope): CiphertextMessage {
        if (envelope.protocolVersion != ENVELOPE_VERSION) {
            throw ProtocolException.InvalidMessage("Unsupported envelope version")
        }
        if (envelope.recipient != localAddress) {
            throw ProtocolException.InvalidMessage("Envelope is addressed to another device")
        }
        // Decode first: a PreKeyMessage is valid without an existing session.
        return CiphertextMessageCodec.decode(envelope.payload)
    }

    /**
     * Encrypts [plaintext] on the session with [remote], or on a new one from
     * [bundle], and stores the advanced session. Runs inside a transaction.
     */
    private suspend fun ClientStorage.encryptOn(
        remote: DeviceAddress,
        bundle: PreKeyBundle?,
        plaintext: ByteArray,
        id: MessageId = newEnvelopeId(),
    ): EncryptedEnvelope {
        val session = sessions.load(remote) ?: initiateSession(remote, bundle)
        val result = protocol.encrypt(session, plaintext)
        val payload = CiphertextMessageCodec.encode(result.message)
        sessions.store(result.updatedSession)
        return EncryptedEnvelope(
            id = id,
            sender = localAddress,
            recipient = remote,
            protocolVersion = ENVELOPE_VERSION,
            payload = payload,
        )
    }

    /** Session handling for one incoming message. Runs inside a transaction. */
    private suspend fun ClientStorage.receive(sender: DeviceAddress, message: CiphertextMessage): Received {
        val identity = requireIdentity()
        return when (message) {
            is PreKeyMessage -> receivePreKeyMessage(identity, sender, message)
            is RatchetMessage -> {
                val session = sessions.load(sender) ?: throw ProtocolException.InvalidSessionState("No session with the sender")
                Received.Plaintext(decryptOn(session, message))
            }
        }
    }

    /**
     * Session setup, repetition, replacement and collision handling for an
     * incoming [PreKeyMessage], see docs/session-lifecycle.md.
     */
    private suspend fun ClientStorage.receivePreKeyMessage(
        identity: LocalIdentity,
        sender: DeviceAddress,
        message: PreKeyMessage,
    ): Received {
        // Identity continuity first: check the pin before any crypto or write;
        // pin only after decryption succeeded, so a forged first contact pins
        // nothing.
        val pinned = checkRemoteIdentity(sender, message.identityKey)
        // Computed from unauthenticated header fields. It is only trusted as
        // a session's origin after acceptSession decrypted with them.
        val initiation = SessionInitiationId.of(message, identity.publicKey)
        val session = sessions.load(sender)
        val current = session?.let { protocol.sessionInfo(it) }
        val currentInitiation = current?.initiationId

        val plaintext = when {
            // The initiator repeats its PreKeyMessage until it sees a reply.
            session != null && currentInitiation == initiation -> decryptOn(session, message)
            sessionInitiations.isRetired(sender, initiation) ->
                throw SecureMessageClientException.StaleSessionInitiation(sender)
            session == null || current == null -> acceptSession(identity, sender, message, replaced = null)
            // A session from before pinning is never replaced: without a pin
            // there is no identity to hold the new initiation against. Its
            // own repeated PreKeyMessages still decrypt (and pin it).
            !pinned -> decryptOn(session, message)
            // Established before milestone 6, so its initiation is unknown and
            // may even be this one (a replay). Only an initiation with a
            // one-time prekey that is still stored is certainly a different
            // one: accepting the old session consumed its one-time prekey.
            // Anything else is decrypted as a repetition on the old session.
            currentInitiation == null ->
                if (hasOneTimePreKeyFor(message)) {
                    acceptSession(identity, sender, message, replaced = null)
                } else {
                    decryptOn(session, message)
                }
            // Simultaneous initiation: the smaller ID wins on both sides.
            current.awaitingReply && initiation > currentInitiation -> {
                rejectLosingInitiation(identity, sender, message, initiation)
                return Received.CollisionLost
            }
            else -> acceptSession(identity, sender, message, replaced = current)
        }
        // A session from before pinning gets its pin here: the engine checked
        // the key against the session and decrypted.
        if (!pinned) pinRemoteIdentity(sender, message.identityKey)
        return Received.Plaintext(plaintext)
    }

    private suspend fun ClientStorage.decryptOn(session: SecureSession, message: CiphertextMessage): ByteArray {
        val result = protocol.decrypt(session, message)
        sessions.store(result.updatedSession)
        return result.plaintext
    }

    private suspend fun ClientStorage.hasOneTimePreKeyFor(message: PreKeyMessage): Boolean =
        message.oneTimePreKeyId?.let { preKeys.oneTimePreKey(it) } != null

    /**
     * Fetches [remote]'s bundle when there is no session yet. Runs outside
     * any transaction: a transaction must not wait for the network.
     */
    private suspend fun fetchBundleIfNoSession(remote: DeviceAddress): PreKeyBundle? {
        val hasSession = storage.transaction {
            requireIdentity()
            sessions.load(remote) != null
        }
        return if (hasSession) null else transport.fetchPreKeyBundle(remote)
    }

    private suspend fun ClientStorage.initiateSession(remote: DeviceAddress, bundle: PreKeyBundle?): SecureSession {
        // No bundle means a session existed a moment ago and was removed since.
        bundle ?: throw ProtocolException.InvalidSessionState("Session was removed concurrently")
        // The session and the pin are stored under remote, so the bundle must
        // be for it.
        if (bundle.address != remote) throw ProtocolException.InvalidPreKeyBundle("Prekey bundle is for another device")
        val pinned = checkRemoteIdentity(remote, bundle.identityKey)
        // Verifies the bundle (key sizes, signed prekey signature) first, so an
        // invalid bundle is never pinned. The caller stores the session in the
        // same transaction.
        val session = protocol.initiateSession(requireIdentity(), bundle)
        if (!pinned) pinRemoteIdentity(remote, bundle.identityKey)
        return session
    }

    /**
     * Sets up the session [message] starts and makes it the current one,
     * retiring the initiation of the [replaced] session. Nothing is written
     * unless the message decrypts.
     */
    private suspend fun ClientStorage.acceptSession(
        identity: LocalIdentity,
        sender: DeviceAddress,
        message: PreKeyMessage,
        replaced: SessionInfo?,
    ): ByteArray {
        val result = acceptWithLocalPreKeys(identity, sender, message)
        // One transaction: the session, the retired initiation and the
        // one-time prekey removal commit together or not at all. The retired
        // entry names the local signed prekey the replaced session was accepted
        // with (null if this device initiated it or it predates milestone 7),
        // so it can be pruned once that key is deleted.
        sessions.store(result.session)
        replaced?.initiationId?.let { sessionInitiations.retire(sender, it, replaced.acceptedSignedPreKeyId) }
        result.consumedOneTimePreKeyId?.let { preKeys.removeOneTimePreKey(it) }
        return result.plaintext
    }

    /**
     * Authenticates an initiation that lost a collision, then retires it.
     * The current session and the one-time prekey stay; the plaintext is
     * discarded. Retiring only after decryption keeps forged messages from
     * adding entries.
     */
    private suspend fun ClientStorage.rejectLosingInitiation(
        identity: LocalIdentity,
        sender: DeviceAddress,
        message: PreKeyMessage,
        initiation: SessionInitiationId,
    ) {
        val result = acceptWithLocalPreKeys(identity, sender, message)
        result.plaintext.fill(0)
        result.session.state.fill(0)
        // Accepted with the signed prekey the message names, so the entry can
        // be pruned once that key is deleted.
        sessionInitiations.retire(sender, initiation, message.signedPreKeyId)
    }

    private suspend fun ClientStorage.acceptWithLocalPreKeys(
        identity: LocalIdentity,
        sender: DeviceAddress,
        message: PreKeyMessage,
    ): SessionAcceptanceResult {
        val signedPreKey = with(preKeyManager) { signedPreKeyForAcceptance(sender, message.signedPreKeyId) }
        val oneTimePreKey = message.oneTimePreKeyId?.let { id ->
            // Missing usually means it was already consumed by another session.
            preKeys.oneTimePreKey(id) ?: throw ProtocolException.InvalidMessage("Unknown one-time prekey")
        }
        return protocol.acceptSession(identity, sender, signedPreKey, oneTimePreKey, message)
    }

    /** Result of a decrypt transaction. A collision is reported after the commit. */
    private sealed interface Received {
        class Plaintext(val plaintext: ByteArray) : Received

        data object CollisionLost : Received
    }

    /** What a received reliability frame did. Acknowledgements are sent after the commit. */
    private sealed interface Processed {
        class New(val id: LogicalMessageId, val body: ByteArray) : Processed

        class Duplicate(val id: LogicalMessageId) : Processed

        class Acknowledged(val id: LogicalMessageId, val cleared: Boolean) : Processed
    }

    private companion object {
        /** Version of the envelope metadata, see [EncryptedEnvelope.protocolVersion]. */
        const val ENVELOPE_VERSION = 1

        fun newEnvelopeId() = MessageId(Uuid.random().toString())
    }
}
