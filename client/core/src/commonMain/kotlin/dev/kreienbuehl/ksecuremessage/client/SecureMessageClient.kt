package dev.kreienbuehl.ksecuremessage.client

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
 * Not handled yet: the remote identity key in a first-contact
 * [PreKeyMessage] is accepted without a trust check, a new session from a
 * sender that already has one (reinstall, simultaneous initiation) fails, and
 * prekeys are not published automatically.
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

        return storage.transaction {
            val identity = requireIdentity()
            val session = sessions.load(sender)
            if (session != null) {
                // Also covers repeated PreKeyMessages from the initiator.
                val result = protocol.decrypt(session, message)
                sessions.store(result.updatedSession)
                result.plaintext
            } else {
                when (message) {
                    is PreKeyMessage -> acceptSession(identity, sender, message)
                    is RatchetMessage -> throw ProtocolException.InvalidSessionState("No session with the sender")
                }
            }
        }
    }

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
        return protocol.initiateSession(requireIdentity(), bundle)
    }

    private suspend fun ClientStorage.acceptSession(
        identity: LocalIdentity,
        sender: DeviceAddress,
        message: PreKeyMessage,
    ): ByteArray {
        val signedPreKey = preKeys.signedPreKey(message.signedPreKeyId)
            ?: throw ProtocolException.InvalidMessage("Unknown signed prekey")
        val oneTimePreKey = message.oneTimePreKeyId?.let { id ->
            // Missing usually means it was already consumed by another session.
            preKeys.oneTimePreKey(id) ?: throw ProtocolException.InvalidMessage("Unknown one-time prekey")
        }
        val result = protocol.acceptSession(identity, sender, signedPreKey, oneTimePreKey, message)
        // One transaction: the session and the one-time prekey removal commit
        // together or not at all.
        sessions.store(result.session)
        result.consumedOneTimePreKeyId?.let { preKeys.removeOneTimePreKey(it) }
        return result.plaintext
    }

    private companion object {
        /** Version of the envelope metadata, see [EncryptedEnvelope.protocolVersion]. */
        const val ENVELOPE_VERSION = 1
    }
}
