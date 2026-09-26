package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotation
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore
import dev.kreienbuehl.ksecuremessage.storage.PendingOutboundStore
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
import dev.kreienbuehl.ksecuremessage.storage.ProcessedInboundStore
import dev.kreienbuehl.ksecuremessage.storage.RemoteIdentityStore
import dev.kreienbuehl.ksecuremessage.storage.SessionInitiationStore
import dev.kreienbuehl.ksecuremessage.storage.SessionStore
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.server.inmemory.InMemoryServerStorage
import kotlinx.coroutines.CompletableDeferred
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Instant

internal val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
internal val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))
internal val CAROL = DeviceAddress(UserId("carol"), DeviceId("tablet"))

/** Stands in for the relay server: bundles plus one mailbox per device. */
internal class FakeNetwork : SecureMessageTransport {
    val bundles = mutableMapOf<DeviceAddress, PreKeyBundle>()
    private val mailboxes = mutableMapOf<DeviceAddress, MutableList<EncryptedEnvelope>>()

    val publications = mutableListOf<PreKeyPublication>()
    val registrations = mutableListOf<DeviceRegistration>()

    /** Only records, without checking authentication. */
    override suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner) {
        registrations += registration
    }

    val recoveries = mutableListOf<DeviceRecoveryAuthorization>()

    /** Only records, without checking anything. */
    override suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization) {
        recoveries += authorization
    }

    val rotations = mutableListOf<DeviceAuthenticationRotationAuthorization>()

    /** Returned by [authenticationEpoch] without checking authentication. */
    var authenticationEpoch = 1L

    override suspend fun authenticationEpoch(address: DeviceAddress, signer: ServerRequestSigner): Long = authenticationEpoch

    /** Only records, without checking anything. */
    override suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization) {
        rotations += authorization
    }

    /** Only records: these tests set [bundles] by hand, see [publish]. */
    override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) {
        publications += publication
    }

    override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle = bundles.getValue(address)

    private val holds = mutableMapOf<DeviceAddress, HeldSend>()

    override suspend fun send(envelope: EncryptedEnvelope) {
        holds.remove(envelope.sender)?.let { held ->
            held.reached.complete(envelope)
            held.release.await()
        }
        mailboxes.getOrPut(envelope.recipient) { mutableListOf() }.add(envelope)
    }

    override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope> = receive(address)

    /** Drains [address]'s mailbox directly, as the tests' stand-in for the device's authenticated drain. */
    fun receive(address: DeviceAddress): List<EncryptedEnvelope> = mailboxes.remove(address)?.toList().orEmpty()

    /**
     * Makes the next [send] from [sender] suspend before it is enqueued, like
     * a slow request, until [HeldSend.release] completes.
     */
    fun holdNextSend(sender: DeviceAddress): HeldSend = HeldSend().also { holds[sender] = it }

    class HeldSend {
        /** Completes with the held envelope once the send is waiting. */
        val reached = CompletableDeferred<EncryptedEnvelope>()
        val release = CompletableDeferred<Unit>()
    }

    /** Stands in for publication: the relay hands out the lowest one-time prekey, or none. */
    suspend fun publish(client: SecureMessageClient, withOneTimePreKey: Boolean = true) {
        bundles[client.localAddress] = client.currentPreKeyBundle().copy(
            oneTimePreKey = if (withOneTimePreKey) client.publicOneTimePreKeys().first() else null,
        )
    }
}

/**
 * Stands in for the relay server with the real server-side prekey and
 * registration semantics of [InMemoryServerStorage]: publication is
 * idempotent, every fetch consumes one one-time prekey, and registration,
 * publication and drain check the device's request signature against the
 * registered key and claim the nonce (without a time window; the real
 * checks are in server:core). The in-process "body" of a request is empty,
 * except for registration, where it is the public key.
 * [beforeNetworkCall] runs on every call.
 */
internal class ServerBackedNetwork(
    private val beforeNetworkCall: () -> Unit = {},
) : SecureMessageTransport {
    val server = InMemoryServerStorage()

    override suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner) {
        beforeNetworkCall()
        val key = registration.publicKey
        authenticate(registration.address, "PUT", ServerApiPaths.REGISTRATION, key, signer) { key }
        try {
            server.devices.register(registration)
        } catch (e: DeviceRegistrationException.Conflict) {
            throw SecureMessageTransportException.DeviceRegistrationConflict()
        }
    }

    /**
     * The checks of server:core's device recovery, without the time window:
     * same user, not self, both registered, authorizer signature with the
     * registered key, proof of possession, then the atomic replacement.
     * [afterRecovery] runs after the server committed, before the response.
     */
    var afterRecovery: () -> Unit = {}

    override suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization) {
        beforeNetworkCall()
        val request = authorization.request
        fun reject(failure: SecureMessageTransportException.RecoveryFailure): Nothing =
            throw SecureMessageTransportException.DeviceRecoveryRejected(failure)
        if (request.authorizer == request.target) reject(SecureMessageTransportException.RecoveryFailure.SELF_AUTHORIZATION)
        if (request.authorizer.userId != request.target.userId) reject(SecureMessageTransportException.RecoveryFailure.CROSS_USER)
        val authorizer = server.devices.registrationState(request.authorizer)
            ?: reject(SecureMessageTransportException.RecoveryFailure.AUTHORIZER_NOT_REGISTERED)
        val target = server.devices.registrationState(request.target)
            ?: reject(SecureMessageTransportException.RecoveryFailure.TARGET_NOT_REGISTERED)
        if (!DeviceRecovery.verifyAuthorization(authorizer.registration.publicKey, authorization) ||
            !DeviceRecovery.verifyProofOfPossession(request)
        ) {
            reject(SecureMessageTransportException.RecoveryFailure.INVALID_PROOF)
        }
        val result = server.devices.replaceForRecovery(
            RecoveryReplacement(
                target, authorizer, request.replacementPublicKey, DeviceRecovery.recoveryId(request),
                request.nonce, request.timestamp, Instant.DISTANT_PAST,
            ),
        )
        when (result) {
            RecoveryReplacementResult.REPLACED, RecoveryReplacementResult.ALREADY_APPLIED -> Unit
            RecoveryReplacementResult.CONFLICT -> reject(SecureMessageTransportException.RecoveryFailure.CONFLICT)
            RecoveryReplacementResult.REPLAY -> reject(SecureMessageTransportException.RecoveryFailure.REPLAY)
            RecoveryReplacementResult.TARGET_NOT_REGISTERED -> reject(SecureMessageTransportException.RecoveryFailure.TARGET_NOT_REGISTERED)
            RecoveryReplacementResult.EPOCH_EXHAUSTED -> reject(SecureMessageTransportException.RecoveryFailure.EPOCH_EXHAUSTED)
        }
        afterRecovery()
    }

    override suspend fun authenticationEpoch(address: DeviceAddress, signer: ServerRequestSigner): Long {
        beforeNetworkCall()
        authenticate(address, "GET", ServerApiPaths.REGISTRATION, ByteArray(0), signer)
        return checkNotNull(server.devices.registrationState(address)).authEpoch
    }

    /** Rotation requests that reached the server, in order. */
    val rotationAttempts = mutableListOf<DeviceAuthenticationRotationAuthorization>()

    /**
     * Runs after the server committed a rotation (or recognized a retry),
     * before the response: throwing here stands for a lost response.
     */
    var afterRotation: () -> Unit = {}

    /**
     * The checks of server:core's routine rotation, without the time window:
     * registered, exact retry, current key and epoch, authorization with the
     * registered key, proof of possession, then the atomic replacement.
     */
    override suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization) {
        beforeNetworkCall()
        rotationAttempts += authorization
        val statement = authorization.statement
        fun reject(failure: SecureMessageTransportException.RotationFailure): Nothing =
            throw SecureMessageTransportException.DeviceAuthenticationRotationRejected(failure)
        val state = server.devices.registrationState(statement.address)
            ?: reject(SecureMessageTransportException.RotationFailure.NOT_REGISTERED)
        val rotationId = DeviceAuthenticationRotation.rotationId(statement)
        val registered = state.registration.publicKey
        if (state.rotationId == rotationId && registered.contentEquals(statement.replacementPublicKey)) {
            if (!DeviceAuthenticationRotation.verifyAuthorization(statement.currentPublicKey, authorization) ||
                !DeviceAuthenticationRotation.verifyProofOfPossession(authorization)
            ) {
                reject(SecureMessageTransportException.RotationFailure.INVALID_PROOF)
            }
            afterRotation()
            return
        }
        if (!registered.contentEquals(statement.currentPublicKey) || state.authEpoch != statement.expectedAuthEpoch) {
            reject(SecureMessageTransportException.RotationFailure.CONFLICT)
        }
        if (!DeviceAuthenticationRotation.verifyAuthorization(registered, authorization) ||
            !DeviceAuthenticationRotation.verifyProofOfPossession(authorization)
        ) {
            reject(SecureMessageTransportException.RotationFailure.INVALID_PROOF)
        }
        val result = server.devices.replaceForRotation(
            RotationReplacement(state, statement.replacementPublicKey, rotationId, statement.nonce, statement.timestamp, Instant.DISTANT_PAST),
        )
        when (result) {
            RotationReplacementResult.REPLACED, RotationReplacementResult.ALREADY_APPLIED -> Unit
            RotationReplacementResult.CONFLICT -> reject(SecureMessageTransportException.RotationFailure.CONFLICT)
            RotationReplacementResult.REPLAY -> reject(SecureMessageTransportException.RotationFailure.REPLAY)
            RotationReplacementResult.NOT_REGISTERED -> reject(SecureMessageTransportException.RotationFailure.NOT_REGISTERED)
            RotationReplacementResult.EPOCH_EXHAUSTED -> reject(SecureMessageTransportException.RotationFailure.EPOCH_EXHAUSTED)
        }
        afterRotation()
    }

    override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) {
        beforeNetworkCall()
        authenticate(publication.address, "PUT", ServerApiPaths.PRE_KEYS, ByteArray(0), signer)
        server.preKeys.publish(publication)
    }

    private suspend fun authenticate(
        address: DeviceAddress,
        method: String,
        endpoint: String,
        body: ByteArray,
        signer: ServerRequestSigner,
        verificationKey: suspend () -> ByteArray? = { server.devices.registration(address)?.publicKey },
    ) {
        val request = ServerRequest(address, method, ServerApiPaths.device(address, endpoint), body)
        val authentication = signer.sign(request)
        val key = verificationKey() ?: throw SecureMessageTransportException.AuthenticationFailed(
            SecureMessageTransportException.AuthenticationFailure.NOT_REGISTERED,
        )
        if (!ServerRequestAuthentication.verify(key, request, authentication)) {
            throw SecureMessageTransportException.AuthenticationFailed(SecureMessageTransportException.AuthenticationFailure.INVALID)
        }
        if (!server.authenticationNonces.claim(address, authentication.nonce.bytes, authentication.timestamp, Instant.DISTANT_PAST)) {
            throw SecureMessageTransportException.AuthenticationFailed(SecureMessageTransportException.AuthenticationFailure.REPLAY)
        }
    }

    override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle {
        beforeNetworkCall()
        return server.preKeys.consumePreKeyBundle(address) ?: throw SecureMessageTransportException.DeviceNotFound(address)
    }

    override suspend fun send(envelope: EncryptedEnvelope) {
        beforeNetworkCall()
        server.mailboxes.enqueue(envelope)
    }

    override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope> {
        beforeNetworkCall()
        authenticate(address, "GET", ServerApiPaths.MESSAGES, ByteArray(0), signer)
        return server.mailboxes.drain(address)
    }

    /** Drains [address]'s mailbox directly, bypassing authentication, for tests. */
    suspend fun receive(address: DeviceAddress): List<EncryptedEnvelope> = server.mailboxes.drain(address)
}

/** Delegates to [delegate] and tracks whether a transaction is running. */
internal class TransactionTrackingStorage(private val delegate: ClientStorage) : ClientStorage by delegate {
    var depth = 0
        private set

    override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T {
        depth++
        try {
            return delegate.transaction(block)
        } finally {
            depth--
        }
    }
}

internal fun EncryptedEnvelope.tampered() =
    copy(payload = payload.copyOf().also { it[it.lastIndex] = (it[it.lastIndex].toInt() xor 1).toByte() })

/** A clock the test sets by hand. Starts at a fixed instant, never moves on its own. */
internal class ManualClock(var now: Instant = Instant.parse("2026-01-01T00:00:00Z")) : Clock {
    override fun now(): Instant = now

    fun advanceBy(duration: Duration) {
        now += duration
    }
}

internal class StorageFailure : Exception("Injected storage failure")

/** Delegates to [delegate], but can make writes inside a transaction fail. */
internal class FailingClientStorage(private val delegate: ClientStorage) : ClientStorage {
    var failSessionStore = false
    var failOneTimePreKeyRemoval = false
    var failRemoteIdentityStore = false
    var failRemoteIdentityReplace = false
    var failVerificationUpdate = false
    var failSessionRemoval = false
    var failRetire = false
    var failRetiredPrune = false
    var failSignedPreKeyStore = false
    var failDeviceAuthenticationKeyStore = false
    var failPendingRecoveryKeyStore = false
    var failRecoveryKeyPromotion = false
    var failPendingRotationKeyStore = false
    var failRotationKeyPromotion = false
    var failSignedPreKeyRemoval = false
    var failLegacyStamp = false
    var failPendingStore = false
    var failPendingRemoval = false
    var failMarkProcessed = false

    /** If set, that many more session writes succeed; the ones after fail. */
    var sessionStoresBeforeFailure: Int? = null

    override val identity get() = delegate.identity
    override val deviceAuthentication get() = delegate.deviceAuthentication
    override val remoteIdentities get() = delegate.remoteIdentities
    override val sessions get() = delegate.sessions
    override val sessionInitiations get() = delegate.sessionInitiations
    override val preKeys get() = delegate.preKeys
    override val pendingOutbound get() = delegate.pendingOutbound
    override val processedInbound get() = delegate.processedInbound

    override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T =
        delegate.transaction { FailingView(this).block() }

    private inner class FailingView(private val tx: ClientStorage) : ClientStorage {
        override val identity get() = tx.identity

        override val deviceAuthentication: DeviceAuthenticationKeyStore = object : DeviceAuthenticationKeyStore by tx.deviceAuthentication {
            override suspend fun store(keyPair: DeviceAuthenticationKeyPair) {
                if (failDeviceAuthenticationKeyStore) throw StorageFailure()
                tx.deviceAuthentication.store(keyPair)
            }

            override suspend fun storePendingRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) {
                if (failPendingRecoveryKeyStore) throw StorageFailure()
                tx.deviceAuthentication.storePendingRecoveryKeyPair(keyPair)
            }

            override suspend fun promotePendingRecoveryKeyPair() {
                if (failRecoveryKeyPromotion) throw StorageFailure()
                tx.deviceAuthentication.promotePendingRecoveryKeyPair()
            }

            override suspend fun storePendingRotationKeyPair(keyPair: DeviceAuthenticationKeyPair) {
                if (failPendingRotationKeyStore) throw StorageFailure()
                tx.deviceAuthentication.storePendingRotationKeyPair(keyPair)
            }

            override suspend fun promotePendingRotationKeyPair() {
                if (failRotationKeyPromotion) throw StorageFailure()
                tx.deviceAuthentication.promotePendingRotationKeyPair()
            }
        }

        override val remoteIdentities: RemoteIdentityStore = object : RemoteIdentityStore by tx.remoteIdentities {
            override suspend fun store(address: DeviceAddress, identityKey: ByteArray) {
                if (failRemoteIdentityStore) throw StorageFailure()
                tx.remoteIdentities.store(address, identityKey)
            }

            override suspend fun replace(address: DeviceAddress, expectedIdentityKey: ByteArray, newIdentityKey: ByteArray) {
                if (failRemoteIdentityReplace) throw StorageFailure()
                tx.remoteIdentities.replace(address, expectedIdentityKey, newIdentityKey)
            }

            override suspend fun setVerification(address: DeviceAddress, identityKey: ByteArray, verification: VerificationState) {
                if (failVerificationUpdate) throw StorageFailure()
                tx.remoteIdentities.setVerification(address, identityKey, verification)
            }
        }

        override val sessions: SessionStore = object : SessionStore by tx.sessions {
            override suspend fun store(session: SecureSession) {
                if (failSessionStore) throw StorageFailure()
                sessionStoresBeforeFailure?.let {
                    if (it == 0) throw StorageFailure()
                    sessionStoresBeforeFailure = it - 1
                }
                tx.sessions.store(session)
            }

            override suspend fun remove(address: DeviceAddress) {
                if (failSessionRemoval) throw StorageFailure()
                tx.sessions.remove(address)
            }
        }

        override val sessionInitiations: SessionInitiationStore = object : SessionInitiationStore by tx.sessionInitiations {
            override suspend fun retire(remote: DeviceAddress, id: SessionInitiationId, signedPreKeyId: SignedPreKeyId?) {
                if (failRetire) throw StorageFailure()
                tx.sessionInitiations.retire(remote, id, signedPreKeyId)
            }

            override suspend fun removeRetiredFor(signedPreKeyId: SignedPreKeyId) {
                if (failRetiredPrune) throw StorageFailure()
                tx.sessionInitiations.removeRetiredFor(signedPreKeyId)
            }
        }

        override val preKeys: PreKeyStore = object : PreKeyStore by tx.preKeys {
            override suspend fun removeOneTimePreKey(id: OneTimePreKeyId) {
                if (failOneTimePreKeyRemoval) throw StorageFailure()
                tx.preKeys.removeOneTimePreKey(id)
            }

            override suspend fun storeCurrentSignedPreKey(preKey: SignedPreKeyPair, createdAt: Instant) {
                if (failSignedPreKeyStore) throw StorageFailure()
                tx.preKeys.storeCurrentSignedPreKey(preKey, createdAt)
            }

            override suspend fun stampLegacySignedPreKeys(at: Instant) {
                if (failLegacyStamp) throw StorageFailure()
                tx.preKeys.stampLegacySignedPreKeys(at)
            }

            override suspend fun removeSignedPreKey(id: SignedPreKeyId) {
                if (failSignedPreKeyRemoval) throw StorageFailure()
                tx.preKeys.removeSignedPreKey(id)
            }
        }

        override val pendingOutbound: PendingOutboundStore = object : PendingOutboundStore by tx.pendingOutbound {
            override suspend fun store(recipient: DeviceAddress, id: LogicalMessageId, frame: ByteArray): Long {
                if (failPendingStore) throw StorageFailure()
                return tx.pendingOutbound.store(recipient, id, frame)
            }

            override suspend fun remove(recipient: DeviceAddress, id: LogicalMessageId): Boolean {
                if (failPendingRemoval) throw StorageFailure()
                return tx.pendingOutbound.remove(recipient, id)
            }
        }

        override val processedInbound: ProcessedInboundStore = object : ProcessedInboundStore by tx.processedInbound {
            override suspend fun markProcessed(sender: DeviceAddress, id: LogicalMessageId) {
                if (failMarkProcessed) throw StorageFailure()
                tx.processedInbound.markProcessed(sender, id)
            }
        }

        override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = block()
    }
}
