package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.CiphertextMessage
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
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
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionAcceptanceResult
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import kotlin.uuid.Uuid

/**
 * Sends and receives messages for [localAddress]. Envelope payloads are
 * [CiphertextMessageCodec]-encoded ciphertext messages.
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
 * Not handled yet: identity changes cannot be accepted, messages lost to a
 * collision are not resent, and prekeys are not published automatically.
 */
class SecureMessageClient(
    val localAddress: DeviceAddress,
    private val storage: ClientStorage,
    private val protocol: ProtocolEngine,
    private val transport: SecureMessageTransport,
    preKeyConfiguration: PreKeyConfiguration = PreKeyConfiguration(),
) {
    private val preKeyManager = PreKeyManager(protocol, preKeyConfiguration)

    /**
     * Makes sure the local identity, a current signed prekey and
     * [PreKeyConfiguration.oneTimePreKeyTarget] one-time prekeys exist. Only
     * missing state is created, in one transaction. An existing identity is
     * never replaced. No network I/O: see [publishPreKeys].
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
     * public half. The old private key stays stored, so first-contact
     * messages that still use it can be decrypted.
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

    /** Encrypts [plaintext] for [remote], starting a session if there is none. */
    suspend fun encrypt(
        remote: DeviceAddress,
        plaintext: ByteArray,
        id: MessageId = MessageId(Uuid.random().toString()),
    ): EncryptedEnvelope {
        val bundle = fetchBundleIfNoSession(remote)
        return storage.transaction {
            val session = sessions.load(remote) ?: initiateSession(remote, bundle)
            val result = protocol.encrypt(session, plaintext)
            val payload = CiphertextMessageCodec.encode(result.message)
            sessions.store(result.updatedSession)
            EncryptedEnvelope(
                id = id,
                sender = localAddress,
                recipient = remote,
                protocolVersion = ENVELOPE_VERSION,
                payload = payload,
            )
        }
    }

    /** [encrypt]s [plaintext] and hands the envelope to the transport. */
    suspend fun send(remote: DeviceAddress, plaintext: ByteArray): EncryptedEnvelope =
        encrypt(remote, plaintext).also { transport.send(it) }

    /**
     * Decrypts [envelope]. Failures change nothing, except that a
     * [SecureMessageClientException.SessionCollision] retires the losing
     * initiation.
     */
    suspend fun decrypt(envelope: EncryptedEnvelope): ByteArray {
        if (envelope.protocolVersion != ENVELOPE_VERSION) {
            throw ProtocolException.InvalidMessage("Unsupported envelope version")
        }
        if (envelope.recipient != localAddress) {
            throw ProtocolException.InvalidMessage("Envelope is addressed to another device")
        }
        // Decode first: a PreKeyMessage is valid without an existing session.
        val message = CiphertextMessageCodec.decode(envelope.payload)
        val sender = envelope.sender

        val received = storage.transaction {
            val identity = requireIdentity()
            when (message) {
                is PreKeyMessage -> receivePreKeyMessage(identity, sender, message)
                is RatchetMessage -> {
                    val session = sessions.load(sender) ?: throw ProtocolException.InvalidSessionState("No session with the sender")
                    Received.Plaintext(decryptOn(session, message))
                }
            }
        }
        // Thrown after the commit, so the retired initiation is kept.
        return when (received) {
            is Received.Plaintext -> received.plaintext
            Received.CollisionLost -> throw SecureMessageClientException.SessionCollision(sender)
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
            else -> acceptSession(identity, sender, message, replaced = currentInitiation)
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
     * retiring the [replaced] initiation. Nothing is written unless the
     * message decrypts.
     */
    private suspend fun ClientStorage.acceptSession(
        identity: LocalIdentity,
        sender: DeviceAddress,
        message: PreKeyMessage,
        replaced: SessionInitiationId?,
    ): ByteArray {
        val result = acceptWithLocalPreKeys(identity, sender, message)
        // One transaction: the session, the retired initiation and the
        // one-time prekey removal commit together or not at all.
        sessions.store(result.session)
        replaced?.let { sessionInitiations.retire(sender, it) }
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
        sessionInitiations.retire(sender, initiation)
    }

    private suspend fun ClientStorage.acceptWithLocalPreKeys(
        identity: LocalIdentity,
        sender: DeviceAddress,
        message: PreKeyMessage,
    ): SessionAcceptanceResult {
        val signedPreKey = preKeys.signedPreKey(message.signedPreKeyId)
            ?: throw ProtocolException.InvalidMessage("Unknown signed prekey")
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

    private companion object {
        /** Version of the envelope metadata, see [EncryptedEnvelope.protocolVersion]. */
        const val ENVELOPE_VERSION = 1
    }
}
