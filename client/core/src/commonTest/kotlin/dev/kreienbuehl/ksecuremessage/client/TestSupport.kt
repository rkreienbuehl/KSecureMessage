package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocation
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotation
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceAuthenticationRegistrationStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.MessageDiscardReason
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
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore
import dev.kreienbuehl.ksecuremessage.storage.PendingInboundStore
import dev.kreienbuehl.ksecuremessage.storage.PendingOutboundStore
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
import dev.kreienbuehl.ksecuremessage.storage.ProcessedInboundStore
import dev.kreienbuehl.ksecuremessage.storage.RemoteIdentityStore
import dev.kreienbuehl.ksecuremessage.storage.SessionInitiationStore
import dev.kreienbuehl.ksecuremessage.storage.SessionStore
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeIssue
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeRequest
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryKeyException
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.server.inmemory.InMemoryServerStorage
import kotlinx.coroutines.CompletableDeferred
import kotlin.random.Random
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

    /** Returned by [registrationStatus] without checking authentication. */
    var registrationStatus = DeviceAuthenticationRegistrationStatus(1, Instant.parse("2026-01-01T00:00:00Z"))

    override suspend fun registrationStatus(address: DeviceAddress, signer: ServerRequestSigner): DeviceAuthenticationRegistrationStatus =
        registrationStatus

    /** Only records, without checking anything. */
    override suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization) {
        rotations += authorization
    }

    override suspend fun registerLastDeviceRecoveryKey(
        address: DeviceAddress,
        registration: LastDeviceRecoveryKeyRegistration,
        signer: ServerRequestSigner,
    ) = error("Not used with FakeNetwork")

    override suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge = error("Not used with FakeNetwork")

    override suspend fun recoverLastDevice(authorization: LastDeviceRecoveryAuthorization) = error("Not used with FakeNetwork")

    override suspend fun lastDeviceRecoveryKeyStatus(
        address: DeviceAddress,
        signer: ServerRequestSigner,
    ): LastDeviceRecoveryKeyStatus = error("Not used with FakeNetwork")

    override suspend fun rotateLastDeviceRecoveryKey(
        authorization: RecoveryKeyRotationAuthorization,
        signer: ServerRequestSigner,
    ) = error("Not used with FakeNetwork")

    override suspend fun revokeLastDeviceRecoveryKey(
        authorization: RecoveryKeyRevocationAuthorization,
        signer: ServerRequestSigner,
    ) = error("Not used with FakeNetwork")

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
    /** The server's clock: the key installation time of registrations, recoveries and rotations. */
    private val clock: Clock = Clock.System,
    private val beforeNetworkCall: () -> Unit = {},
) : SecureMessageTransport {
    val server = InMemoryServerStorage()

    /** The server's time, in milliseconds like server:core. */
    private fun now() = Instant.fromEpochMilliseconds(clock.now().toEpochMilliseconds())

    override suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner) {
        beforeNetworkCall()
        val key = registration.publicKey
        authenticate(registration.address, "PUT", ServerApiPaths.REGISTRATION, key, signer) { key }
        try {
            server.devices.register(registration, now())
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
                request.nonce, request.timestamp, Instant.DISTANT_PAST, now(),
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

    /** Registration status requests that reached the server. */
    var registrationStatusRequests = 0

    override suspend fun registrationStatus(address: DeviceAddress, signer: ServerRequestSigner): DeviceAuthenticationRegistrationStatus {
        beforeNetworkCall()
        registrationStatusRequests++
        authenticate(address, "GET", ServerApiPaths.REGISTRATION, ByteArray(0), signer)
        val state = checkNotNull(server.devices.registrationState(address))
        return DeviceAuthenticationRegistrationStatus(state.authEpoch, state.authKeyInstalledAt)
    }

    /** Rotation requests that reached the server, in order. */
    val rotationAttempts = mutableListOf<DeviceAuthenticationRotationAuthorization>()

    /**
     * Runs after the server committed a rotation (or recognized a retry),
     * before the response: throwing here stands for a lost response.
     */
    var afterRotation: () -> Unit = {}

    /**
     * Runs after the server committed a rotation, before the response, and
     * may suspend: another client can act while this one waits for it.
     */
    var whileRotationResponsePending: suspend () -> Unit = {}

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
            RotationReplacement(state, statement.replacementPublicKey, rotationId, statement.nonce, statement.timestamp, Instant.DISTANT_PAST, now()),
        )
        when (result) {
            RotationReplacementResult.REPLACED, RotationReplacementResult.ALREADY_APPLIED -> Unit
            RotationReplacementResult.CONFLICT -> reject(SecureMessageTransportException.RotationFailure.CONFLICT)
            RotationReplacementResult.REPLAY -> reject(SecureMessageTransportException.RotationFailure.REPLAY)
            RotationReplacementResult.NOT_REGISTERED -> reject(SecureMessageTransportException.RotationFailure.NOT_REGISTERED)
            RotationReplacementResult.EPOCH_EXHAUSTED -> reject(SecureMessageTransportException.RotationFailure.EPOCH_EXHAUSTED)
        }
        afterRotation()
        whileRotationResponsePending()
    }

    /** Key registration: authenticated by the device, same user, valid proof of possession, never replaced. */
    override suspend fun registerLastDeviceRecoveryKey(
        address: DeviceAddress,
        registration: LastDeviceRecoveryKeyRegistration,
        signer: ServerRequestSigner,
    ) {
        beforeNetworkCall()
        authenticate(address, "PUT", ServerApiPaths.LAST_DEVICE_RECOVERY_KEY, ByteArray(0), signer)
        if (registration.userId != address.userId || !LastDeviceRecovery.verifyKeyRegistration(registration)) {
            throw SecureMessageTransportException.LastDeviceRecoveryKeyRejected(SecureMessageTransportException.RecoveryKeyFailure.INVALID)
        }
        registerRecoveryKey(registration)
    }

    /** Recovery key registration after a revocation at the maximum epoch fails closed. */
    private suspend fun registerRecoveryKey(registration: LastDeviceRecoveryKeyRegistration) {
        try {
            server.lastDeviceRecovery.registerRecoveryKey(registration.userId, registration.publicKey, now())
        } catch (e: LastDeviceRecoveryKeyException.Conflict) {
            throw SecureMessageTransportException.LastDeviceRecoveryKeyRejected(SecureMessageTransportException.RecoveryKeyFailure.CONFLICT)
        } catch (e: LastDeviceRecoveryKeyException.EpochExhausted) {
            throw SecureMessageTransportException.LastDeviceRecoveryKeyRejected(SecureMessageTransportException.RecoveryKeyFailure.EPOCH_EXHAUSTED)
        }
    }

    /** Status requests that reached the server. */
    var recoveryKeyStatusRequests = 0

    override suspend fun lastDeviceRecoveryKeyStatus(address: DeviceAddress, signer: ServerRequestSigner): LastDeviceRecoveryKeyStatus {
        beforeNetworkCall()
        recoveryKeyStatusRequests++
        authenticate(address, "GET", ServerApiPaths.LAST_DEVICE_RECOVERY_KEY, ByteArray(0), signer)
        val state = server.lastDeviceRecovery.recoveryKeyState(address.userId) ?: return LastDeviceRecoveryKeyStatus.Unconfigured
        return when (state.status) {
            RecoveryKeyStatus.ACTIVE -> LastDeviceRecoveryKeyStatus.Active(state.epoch, checkNotNull(state.installedAt), checkNotNull(state.publicKey))
            RecoveryKeyStatus.REVOKED -> LastDeviceRecoveryKeyStatus.Revoked(state.epoch, state.transitionedAt)
        }
    }

    /** Recovery key rotations and revocations that reached the server, in order. */
    val recoveryKeyTransitionAttempts = mutableListOf<Any>()

    /** Runs after the server committed a recovery key rotation or revocation, before the response: throwing stands for a lost response. */
    var afterRecoveryKeyTransition: () -> Unit = {}

    /** Runs when a recovery key rotation or revocation arrives, before the server reads any state: another transition can win meanwhile. */
    var beforeRecoveryKeyTransition: suspend () -> Unit = {}

    /** The checks of server:core's recovery key rotation (without a time window), then the atomic storage transition. */
    override suspend fun rotateLastDeviceRecoveryKey(authorization: RecoveryKeyRotationAuthorization, signer: ServerRequestSigner) {
        beforeNetworkCall()
        val statement = authorization.statement
        authenticate(statement.authorizer, "PUT", ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_ROTATION, ByteArray(0), signer)
        beforeRecoveryKeyTransition()
        recoveryKeyTransitionAttempts += authorization
        fun reject(failure: SecureMessageTransportException.RecoveryKeyTransitionFailure): Nothing =
            throw SecureMessageTransportException.RecoveryKeyRotationRejected(failure)
        val authorizer = checkNotNull(server.devices.registrationState(statement.authorizer))
        val state = server.lastDeviceRecovery.recoveryKeyState(statement.userId)
            ?: reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.NOT_CONFIGURED)
        val id = RecoveryKeyRotation.rotationId(statement)
        val proofs = RecoveryKeyRotation.verifyCurrentKeySignature(statement.currentPublicKey, authorization) &&
            RecoveryKeyRotation.verifyNewKeyProofOfPossession(authorization)
        if (state.rotationId == id && state.publicKey.contentEquals(statement.newPublicKey)) {
            if (!proofs) reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.INVALID_PROOF)
            afterRecoveryKeyTransition()
            return
        }
        if (state.status != RecoveryKeyStatus.ACTIVE) reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.NOT_CONFIGURED)
        if (state.epoch != statement.expectedEpoch || !state.publicKey.contentEquals(statement.currentPublicKey)) {
            reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.CONFLICT)
        }
        if (!proofs) reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.INVALID_PROOF)
        val result = server.lastDeviceRecovery.rotateRecoveryKey(
            RecoveryKeyRotationTransition(
                statement.userId, statement.currentPublicKey, statement.expectedEpoch, statement.newPublicKey, authorizer, id,
                statement.nonce, statement.timestamp, Instant.DISTANT_PAST, now(),
            ),
        )
        when (result) {
            RecoveryKeyRotationResult.ROTATED, RecoveryKeyRotationResult.ALREADY_APPLIED -> Unit
            RecoveryKeyRotationResult.NOT_CONFIGURED -> reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.NOT_CONFIGURED)
            RecoveryKeyRotationResult.CONFLICT -> reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.CONFLICT)
            RecoveryKeyRotationResult.REPLAY -> reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.REPLAY)
            RecoveryKeyRotationResult.EPOCH_EXHAUSTED -> reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.EPOCH_EXHAUSTED)
        }
        afterRecoveryKeyTransition()
    }

    /** The checks of server:core's recovery key revocation (without a time window), then the atomic storage transition. */
    override suspend fun revokeLastDeviceRecoveryKey(authorization: RecoveryKeyRevocationAuthorization, signer: ServerRequestSigner) {
        beforeNetworkCall()
        val statement = authorization.statement
        authenticate(statement.authorizer, "PUT", ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_REVOCATION, ByteArray(0), signer)
        beforeRecoveryKeyTransition()
        recoveryKeyTransitionAttempts += authorization
        fun reject(failure: SecureMessageTransportException.RecoveryKeyTransitionFailure): Nothing =
            throw SecureMessageTransportException.RecoveryKeyRevocationRejected(failure)
        val authorizer = checkNotNull(server.devices.registrationState(statement.authorizer))
        val state = server.lastDeviceRecovery.recoveryKeyState(statement.userId)
            ?: reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.NOT_CONFIGURED)
        val id = RecoveryKeyRevocation.revocationId(statement)
        val proof = RecoveryKeyRevocation.verifySignature(statement.currentPublicKey, authorization)
        if (state.status == RecoveryKeyStatus.REVOKED && state.revocationId == id) {
            if (!proof) reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.INVALID_PROOF)
            afterRecoveryKeyTransition()
            return
        }
        if (state.status != RecoveryKeyStatus.ACTIVE) reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.NOT_CONFIGURED)
        if (state.epoch != statement.expectedEpoch || !state.publicKey.contentEquals(statement.currentPublicKey)) {
            reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.CONFLICT)
        }
        if (!proof) reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.INVALID_PROOF)
        val result = server.lastDeviceRecovery.revokeRecoveryKey(
            RecoveryKeyRevocationTransition(
                statement.userId, statement.currentPublicKey, statement.expectedEpoch, authorizer, id,
                statement.nonce, statement.timestamp, Instant.DISTANT_PAST, now(),
            ),
        )
        when (result) {
            RecoveryKeyRevocationResult.REVOKED, RecoveryKeyRevocationResult.ALREADY_APPLIED -> Unit
            RecoveryKeyRevocationResult.NOT_CONFIGURED -> reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.NOT_CONFIGURED)
            RecoveryKeyRevocationResult.CONFLICT -> reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.CONFLICT)
            RecoveryKeyRevocationResult.REPLAY -> reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.REPLAY)
            RecoveryKeyRevocationResult.EPOCH_EXHAUSTED -> reject(SecureMessageTransportException.RecoveryKeyTransitionFailure.EPOCH_EXHAUSTED)
        }
        afterRecoveryKeyTransition()
    }

    /** Runs after a challenge was issued, before the response: another transition or the clock can move meanwhile. */
    var afterLastDeviceRecoveryChallenge: suspend () -> Unit = {}

    /** Challenges requested, in order. */
    val lastDeviceRecoveryChallenges = mutableListOf<LastDeviceRecoveryChallenge>()

    override suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge {
        beforeNetworkCall()
        val now = now()
        val request = LastDeviceRecoveryChallengeRequest(
            target, LastDeviceRecoveryChallengeId(Random.nextBytes(16)), Random.nextBytes(32), now, now + LastDeviceRecovery.CHALLENGE_LIFETIME,
        )
        val challenge = when (val issue = server.lastDeviceRecovery.issueChallenge(request)) {
            is LastDeviceRecoveryChallengeIssue.Issued -> issue.challenge.challenge
            LastDeviceRecoveryChallengeIssue.NotConfigured -> rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.NOT_CONFIGURED)
            LastDeviceRecoveryChallengeIssue.NotRegistered ->
                rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.TARGET_NOT_REGISTERED)
        }
        lastDeviceRecoveryChallenges += challenge
        afterLastDeviceRecoveryChallenge()
        return challenge
    }

    /** Last-device recovery requests that reached the server, in order. */
    val lastDeviceRecoveryAttempts = mutableListOf<LastDeviceRecoveryAuthorization>()

    /**
     * Runs after the server committed a last-device recovery (or recognized
     * a retry), before the response: throwing here stands for a lost response.
     */
    var afterLastDeviceRecovery: () -> Unit = {}

    private fun rejectLastDevice(failure: SecureMessageTransportException.LastDeviceRecoveryFailure): Nothing =
        throw SecureMessageTransportException.LastDeviceRecoveryRejected(failure)

    /**
     * The checks of server:core's last-device recovery: the user's registered
     * recovery key, registered target, exact retry, both proofs, then the
     * atomic challenge consumption and replacement (which checks the
     * challenge and its expiry against the server clock).
     */
    override suspend fun recoverLastDevice(authorization: LastDeviceRecoveryAuthorization) {
        beforeNetworkCall()
        lastDeviceRecoveryAttempts += authorization
        val statement = authorization.statement
        val target = statement.target
        val recoveryKey = server.lastDeviceRecovery.recoveryKey(target.userId)
            ?: rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.NOT_CONFIGURED)
        if (!recoveryKey.contentEquals(statement.recoveryPublicKey)) {
            rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.INVALID_PROOF)
        }
        val state = server.devices.registrationState(target)
            ?: rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.TARGET_NOT_REGISTERED)
        if (!LastDeviceRecovery.verifyRecoverySignature(recoveryKey, authorization) || !LastDeviceRecovery.verifyProofOfPossession(authorization)) {
            rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.INVALID_PROOF)
        }
        val id = LastDeviceRecovery.recoveryId(statement)
        val result = server.devices.replaceForLastDeviceRecovery(
            LastDeviceRecoveryReplacement(state, recoveryKey, statement.challenge.id, statement.challenge.nonce, statement.replacementPublicKey, id, now()),
        )
        when (result) {
            LastDeviceRecoveryReplacementResult.REPLACED, LastDeviceRecoveryReplacementResult.ALREADY_APPLIED -> Unit
            LastDeviceRecoveryReplacementResult.NOT_REGISTERED ->
                rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.TARGET_NOT_REGISTERED)
            LastDeviceRecoveryReplacementResult.NOT_CONFIGURED -> rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.NOT_CONFIGURED)
            LastDeviceRecoveryReplacementResult.CHALLENGE_INVALID ->
                rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.CHALLENGE_INVALID)
            LastDeviceRecoveryReplacementResult.EXPIRED -> rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.EXPIRED)
            LastDeviceRecoveryReplacementResult.CONFLICT -> rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.CONFLICT)
            LastDeviceRecoveryReplacementResult.EPOCH_EXHAUSTED ->
                rejectLastDevice(SecureMessageTransportException.LastDeviceRecoveryFailure.EPOCH_EXHAUSTED)
        }
        afterLastDeviceRecovery()
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
    var failPendingLastDeviceRecoveryKeyStore = false
    var failLastDeviceRecoveryKeyPromotion = false
    var failSignedPreKeyRemoval = false
    var failLegacyStamp = false
    var failPendingStore = false
    var failPendingRemoval = false
    var failMarkProcessed = false
    var failPendingInboundStore = false
    var failPendingInboundRemoval = false

    /** If set, that many more session writes succeed; the ones after fail. */
    var sessionStoresBeforeFailure: Int? = null

    override val identity get() = delegate.identity
    override val deviceAuthentication get() = delegate.deviceAuthentication
    override val remoteIdentities get() = delegate.remoteIdentities
    override val sessions get() = delegate.sessions
    override val sessionInitiations get() = delegate.sessionInitiations
    override val preKeys get() = delegate.preKeys
    override val pendingOutbound get() = delegate.pendingOutbound
    override val pendingInbound get() = delegate.pendingInbound
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

            override suspend fun storePendingLastDeviceRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) {
                if (failPendingLastDeviceRecoveryKeyStore) throw StorageFailure()
                tx.deviceAuthentication.storePendingLastDeviceRecoveryKeyPair(keyPair)
            }

            override suspend fun promotePendingLastDeviceRecoveryKeyPair() {
                if (failLastDeviceRecoveryKeyPromotion) throw StorageFailure()
                tx.deviceAuthentication.promotePendingLastDeviceRecoveryKeyPair()
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

        override val pendingInbound: PendingInboundStore = object : PendingInboundStore by tx.pendingInbound {
            override suspend fun store(sender: DeviceAddress, id: LogicalMessageId, frame: ByteArray, receivedAt: Instant): Long {
                if (failPendingInboundStore) throw StorageFailure()
                return tx.pendingInbound.store(sender, id, frame, receivedAt)
            }

            override suspend fun remove(sender: DeviceAddress, id: LogicalMessageId): Boolean {
                if (failPendingInboundRemoval) throw StorageFailure()
                return tx.pendingInbound.remove(sender, id)
            }
        }

        override val processedInbound: ProcessedInboundStore = object : ProcessedInboundStore by tx.processedInbound {
            override suspend fun markCommitted(sender: DeviceAddress, id: LogicalMessageId, digest: ByteArray, committedAt: Instant) {
                if (failMarkProcessed) throw StorageFailure()
                tx.processedInbound.markCommitted(sender, id, digest, committedAt)
            }

            override suspend fun markDiscarded(
                sender: DeviceAddress,
                id: LogicalMessageId,
                digest: ByteArray,
                discardedAt: Instant,
                reason: MessageDiscardReason,
            ) {
                if (failMarkProcessed) throw StorageFailure()
                tx.processedInbound.markDiscarded(sender, id, digest, discardedAt, reason)
            }
        }

        override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = block()
    }
}
