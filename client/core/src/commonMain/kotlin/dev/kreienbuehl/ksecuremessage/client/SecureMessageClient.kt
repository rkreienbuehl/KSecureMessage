package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.CiphertextMessage
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.InboundFinalization
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.MessageDiscardReason
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.protocol.ApplicationMessageDigest
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotation
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryCodec
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryRequest
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.protocol.PublicIdentityKey
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyReset
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocation
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotation
import dev.kreienbuehl.ksecuremessage.protocol.SafetyNumber
import dev.kreienbuehl.ksecuremessage.protocol.SafetyNumberCodec
import dev.kreienbuehl.ksecuremessage.protocol.SafetyNumberComparison
import dev.kreienbuehl.ksecuremessage.protocol.SecurePayload
import dev.kreienbuehl.ksecuremessage.protocol.SecurePayloadCodec
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.SessionAcceptanceResult
import dev.kreienbuehl.ksecuremessage.protocol.SessionInfo
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.PendingInboundMessage
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Clock
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Instant
import kotlin.uuid.Uuid

/**
 * Sends and receives messages for [localAddress]. Envelope payloads are
 * [CiphertextMessageCodec]-encoded ciphertext messages; their plaintext is a
 * [SecurePayloadCodec] reliability frame.
 *
 * Messages are reliable across collisions, lost envelopes and lost
 * acknowledgements (docs/message-reliability.md). [send] gives each
 * application message a [LogicalMessageId] and keeps it pending, plaintext
 * included, until the recipient acknowledges it. [retryPendingMessages]
 * encrypts pending messages again, under the current session and with the
 * same logical ID. Both peers must use this frame (milestone 8); raw
 * plaintext from older peers is rejected.
 *
 * Received messages are delivered at least once, until the application
 * finalizes them (docs/application-delivery.md, docs/message-discard.md).
 * [decrypt] stores a new message as pending and returns it as
 * [ReceiveResult.Delivery]; [pendingReceivedMessages] pages through every
 * pending message again, also after a restart. Once the application has
 * applied a message durably, it calls [commitReceivedMessage]; for a message
 * it can never apply, it calls [discardReceivedMessage]. Either records a
 * terminal tombstone and only then sends the encrypted acknowledgement. An
 * acknowledgement therefore means that the receiving application durably
 * finalized the message and will not have it redelivered; the sender cannot
 * tell a commit from a discard. This is not exactly-once processing: an
 * application that crashes between its own commit and [commitReceivedMessage]
 * sees the message again, so it should apply messages idempotently, keyed by
 * sender and logical ID. Finalized IDs are kept for duplicate suppression
 * until [pruneProcessedMessages] removes them.
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
 * The server only accepts device-scoped requests from the registered device
 * (docs/server-authentication.md). [initialize] creates the device
 * authentication key, a signing key separate from the messaging identity;
 * [registerDevice] registers its public half with the server, explicitly
 * and once. [publishPreKeys] and [receive] then sign their requests with it;
 * the application never handles signatures. Fetching bundles and sending
 * envelopes need no authentication.
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
 * A device whose device authentication key is lost can be recovered by
 * another registered device of the same user (docs/device-recovery.md):
 * [prepareDeviceAuthenticationRecovery] on the lost device,
 * [authorizeDeviceRecovery] on the other one,
 * [completeDeviceAuthenticationRecovery] on the lost device again. This
 * replaces the server authentication key only, never the messaging identity.
 *
 * A device that still holds its key can replace it itself with a routine
 * rotation (docs/device-authentication-rotation.md):
 * [rotateDeviceAuthenticationKey], or [prepareDeviceAuthenticationRotation]
 * and [completeDeviceAuthenticationRotation]. The current key authorizes the
 * new one; no other device takes part. Nothing rotates automatically.
 * [deviceAuthenticationHealth] classifies the state of these credentials
 * read-only (docs/device-authentication-health.md).
 *
 * Identities can be verified manually and changes accepted explicitly
 * (docs/identity-verification.md): [safetyNumber] gives a value both devices
 * derive alike for the user to compare, [markRemoteIdentityVerified] records
 * the user's confirmation for exactly the pinned key, and
 * [acceptRemoteIdentityChange] installs a new identity the user approved,
 * resetting the session and the verification. Nothing here happens
 * automatically.
 *
 * Not handled yet: pending messages are not retried automatically, and
 * prekeys are not published automatically.
 */
class SecureMessageClient(
    val localAddress: DeviceAddress,
    private val storage: ClientStorage,
    private val protocol: ProtocolEngine,
    private val transport: SecureMessageTransport,
    preKeyConfiguration: PreKeyConfiguration = PreKeyConfiguration(),
    private val clock: Clock = Clock.System,
) {
    private val preKeyManager = PreKeyManager(protocol, preKeyConfiguration, clock)

    /**
     * Keeps every hand-off to the transport (messages, retries,
     * acknowledgements) in encryption order.
     */
    private val sendMutex = Mutex()

    /**
     * Serializes this instance's routine rotation and last-device recovery
     * steps, so that concurrent calls never race two submissions of one
     * pending key (docs/device-authentication-rotation.md,
     * docs/last-device-recovery.md). Independent of [sendMutex].
     * Public rotation functions take it once and call the `…Locked`
     * variants, because it is not reentrant.
     */
    private val deviceAuthenticationMutex = Mutex()

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
     *
     * Also makes sure the device authentication key exists: it is created
     * with the identity, or once for storage from before milestone 12. If an
     * initialized storage lost the key, this throws
     * [SecureMessageClientException.InconsistentStorage] instead of creating
     * a new one, which the server would never accept. Never registers the
     * device: call [registerDevice].
     */
    suspend fun initialize() {
        storage.transaction {
            with(preKeyManager) { ensureInitialized() }
            // Committed IDs from before milestone 20 get a full retention period from now on.
            processedInbound.stampLegacyCommitTimes(preKeyManager.now())
        }
    }

    /**
     * Registers this device's authentication public key with the server
     * (docs/server-authentication.md), in a request signed with that key.
     * Needed once before [publishPreKeys] and [receive]; calling it again is
     * safe. Throws [SecureMessageTransportException.DeviceRegistrationConflict]
     * if the server has another key for [localAddress]; there is no reset.
     * The server trusts the first registration for an address.
     */
    suspend fun registerDevice() {
        withRequestSigner { keyPair, signer ->
            transport.registerDevice(DeviceRegistration(localAddress, keyPair.publicKey), signer)
        }
    }

    /**
     * Starts or resumes a device authentication recovery of this device
     * (docs/device-recovery.md): for a device whose registered device
     * authentication key is lost, [authorizer], another registered device of
     * the same user, can authorize a replacement key.
     *
     * Creates the replacement key pair once and keeps it as pending recovery
     * key, sealed at rest; later calls reuse it until the recovery completes
     * or is cancelled. The active key (if any) is not touched. Returns a
     * request signed with the replacement key (proof of possession), stamped
     * with the current time and a fresh nonce. The application transfers it
     * to [authorizer] (for example with [DeviceRecoveryCodec]), which calls
     * [authorizeDeviceRecovery]; this device then calls
     * [completeDeviceAuthenticationRecovery] within
     * [DeviceRecovery.VALIDITY_WINDOW] of the request time. No network I/O.
     *
     * Recovers server authentication only. The messaging identity, prekeys,
     * sessions and identity pins are not changed. Needs the local identity
     * ([SecureMessageClientException.NotInitialized]); throws
     * [SecureMessageClientException.InvalidDeviceRecovery] if [authorizer] is
     * this device or belongs to another user, and
     * [SecureMessageClientException.DeviceAuthenticationRotationInProgress]
     * while a routine rotation is pending and
     * [SecureMessageClientException.LastDeviceRecoveryInProgress] while a
     * last-device recovery is pending.
     */
    suspend fun prepareDeviceAuthenticationRecovery(authorizer: DeviceAddress): DeviceRecoveryRequest {
        if (authorizer == localAddress) throw SecureMessageClientException.InvalidDeviceRecovery("A device cannot authorize its own recovery")
        if (authorizer.userId != localAddress.userId) {
            throw SecureMessageClientException.InvalidDeviceRecovery("The authorizing device belongs to another user")
        }
        val keyPair = storage.transaction {
            requireIdentity()
            deviceAuthentication.pendingRotationKeyPair()?.let {
                it.privateKey.fill(0)
                throw SecureMessageClientException.DeviceAuthenticationRotationInProgress()
            }
            deviceAuthentication.pendingLastDeviceRecoveryKeyPair()?.let {
                it.privateKey.fill(0)
                throw SecureMessageClientException.LastDeviceRecoveryInProgress()
            }
            deviceAuthentication.pendingRecoveryKeyPair()
                ?: protocol.createDeviceAuthenticationKey().also { deviceAuthentication.storePendingRecoveryKeyPair(it) }
        }
        try {
            return DeviceRecovery.prepare(keyPair, localAddress, authorizer, clock.now())
        } finally {
            keyPair.privateKey.fill(0)
        }
    }

    /**
     * Authorizes [request], another device's recovery request, with this
     * device's active device authentication key (docs/device-recovery.md).
     * The application shows the user which device ([DeviceRecoveryRequest.target])
     * is being recovered before calling this, and transfers the result back
     * to it. No network I/O.
     *
     * Throws [SecureMessageClientException.InvalidDeviceRecovery] unless the
     * request names this device as authorizer, targets another device of
     * the same user, is within [DeviceRecovery.VALIDITY_WINDOW] of the local
     * time and carries a valid proof of possession of its replacement key.
     */
    suspend fun authorizeDeviceRecovery(request: DeviceRecoveryRequest): DeviceRecoveryAuthorization {
        fun invalid(message: String): Nothing = throw SecureMessageClientException.InvalidDeviceRecovery(message)
        if (request.authorizer != localAddress) invalid("The request asks another device for authorization")
        if (request.target == localAddress) invalid("A device cannot authorize its own recovery")
        if (request.target.userId != localAddress.userId) invalid("The device to recover belongs to another user")
        val now = clock.now()
        if (request.timestamp < now - DeviceRecovery.VALIDITY_WINDOW || request.timestamp > now + DeviceRecovery.VALIDITY_WINDOW) {
            invalid("The request is outside the validity window")
        }
        if (!DeviceRecovery.verifyProofOfPossession(request)) invalid("The request's proof of possession is invalid")
        val keyPair = storage.transaction { requireDeviceAuthenticationKey() }
        try {
            return DeviceRecovery.authorize(keyPair, request)
        } finally {
            keyPair.privateKey.fill(0)
        }
    }

    /**
     * Submits [authorization] for this device's pending recovery and, once
     * the server replaced the registered key, makes the pending key the
     * active device authentication key (docs/device-recovery.md). From then
     * on every request is signed with it; the old key no longer works.
     *
     * Safe to call again after a failure or a lost response: the server
     * recognizes a retry of an applied recovery, and if it rejects the retry
     * as conflicting, expired or replayed, this asks the server whether the
     * pending key is already registered ([resolveDeviceAuthenticationRecovery])
     * before failing. Other failures leave the pending key for another
     * attempt. Throws [SecureMessageClientException.NoPendingDeviceRecovery],
     * [SecureMessageClientException.InvalidDeviceRecovery] if [authorization]
     * is not for this device's pending key, and
     * [SecureMessageTransportException.DeviceRecoveryRejected].
     */
    suspend fun completeDeviceAuthenticationRecovery(authorization: DeviceRecoveryAuthorization) {
        val request = authorization.request
        if (request.target != localAddress) throw SecureMessageClientException.InvalidDeviceRecovery("The authorization is for another device")
        val pending = storage.transaction { deviceAuthentication.pendingRecoveryKeyPair() }
            ?: throw SecureMessageClientException.NoPendingDeviceRecovery()
        val publicKey = pending.publicKey
        pending.privateKey.fill(0)
        if (!publicKey.contentEquals(request.replacementPublicKey)) {
            throw SecureMessageClientException.InvalidDeviceRecovery("The authorization is for another replacement key")
        }
        try {
            transport.recoverDevice(authorization)
        } catch (e: SecureMessageTransportException.DeviceRecoveryRejected) {
            // A lost response, or an earlier attempt that won: the key may be registered already.
            if (e.reason in RESOLVABLE_RECOVERY_FAILURES && resolveDeviceAuthenticationRecovery()) return
            throw e
        }
        promotePendingRecoveryKey(publicKey)
    }

    /**
     * Asks the server whether this device's pending recovery key is its
     * registered key, with a registration request signed by that key (a
     * registration of exactly the registered key changes nothing). If it
     * is, makes it the active key and returns `true`; if the server holds
     * another key, returns `false` and keeps the pending key. For a recovery
     * whose response was lost and whose authorization expired. Throws
     * [SecureMessageClientException.NoPendingDeviceRecovery].
     */
    suspend fun resolveDeviceAuthenticationRecovery(): Boolean {
        val pending = storage.transaction { deviceAuthentication.pendingRecoveryKeyPair() }
            ?: throw SecureMessageClientException.NoPendingDeviceRecovery()
        val publicKey = pending.publicKey
        if (!probeRegistration(pending)) return false
        promotePendingRecoveryKey(publicKey)
        return true
    }

    /**
     * Deletes the pending recovery key. Only for a recovery that will not be
     * completed: if the server already accepted it, the device has to be
     * recovered again.
     */
    suspend fun cancelDeviceAuthenticationRecovery() {
        storage.transaction { deviceAuthentication.removePendingRecoveryKeyPair() }
    }

    /**
     * Asks the server whether [keyPair]'s public key is this device's
     * registered key, with a registration request signed by it: registering
     * exactly the registered key changes nothing. `false` if the server holds
     * another key. Wipes [keyPair]'s private key.
     */
    private suspend fun probeRegistration(keyPair: DeviceAuthenticationKeyPair): Boolean = try {
        withRequestSigner(keyPair) { pending, signer ->
            transport.registerDevice(DeviceRegistration(localAddress, pending.publicKey), signer)
        }
        true
    } catch (e: SecureMessageTransportException.DeviceRegistrationConflict) {
        false
    }

    /**
     * Starts or resumes a routine rotation of this device's authentication
     * key (docs/device-authentication-rotation.md), for a device that still
     * holds its registered key K1. Creates the replacement key pair K2 once
     * and keeps it as pending rotation key, sealed at rest; later calls reuse
     * it until the rotation completes or is cancelled. K1 stays the active
     * key and keeps signing every request. No network I/O: call
     * [completeDeviceAuthenticationRotation].
     *
     * Rotates server authentication only. The messaging identity, prekeys,
     * sessions, identity pins and their verification are not changed. Needs
     * the local identity and K1 ([SecureMessageClientException.NotInitialized]
     * if either is missing); throws
     * [SecureMessageClientException.DeviceAuthenticationRecoveryInProgress]
     * while a device recovery is pending and
     * [SecureMessageClientException.LastDeviceRecoveryInProgress] while a
     * last-device recovery is pending. A device that lost K1 uses device
     * recovery instead (docs/device-recovery.md, docs/last-device-recovery.md).
     */
    suspend fun prepareDeviceAuthenticationRotation() {
        deviceAuthenticationMutex.withLock { prepareRotationLocked() }
    }

    private suspend fun prepareRotationLocked() {
        storage.transaction {
            requireDeviceAuthenticationKey().privateKey.fill(0)
            deviceAuthentication.pendingRecoveryKeyPair()?.let {
                it.privateKey.fill(0)
                throw SecureMessageClientException.DeviceAuthenticationRecoveryInProgress()
            }
            deviceAuthentication.pendingLastDeviceRecoveryKeyPair()?.let {
                it.privateKey.fill(0)
                throw SecureMessageClientException.LastDeviceRecoveryInProgress()
            }
            val pending = deviceAuthentication.pendingRotationKeyPair()
                ?: protocol.createDeviceAuthenticationKey().also { deviceAuthentication.storePendingRotationKeyPair(it) }
            pending.privateKey.fill(0)
        }
    }

    /**
     * Submits the pending rotation and, once the server replaced the
     * registered key, makes the pending key K2 the active device
     * authentication key (docs/device-authentication-rotation.md). From then
     * on every request is signed with K2; K1 no longer works.
     *
     * Reads the current authentication epoch from the server with a request
     * signed by K1, then sends the rotation statement for (K1, epoch) → K2,
     * signed by K1 (authorization) and K2 (proof of possession), with the
     * current time and a fresh nonce.
     *
     * Safe to call again after a failure, a lost response or a crash before
     * the local promotion: if the server rejects K1 or the rotation as
     * conflicting, expired or replayed, this asks the server whether K2 is
     * registered already ([resolveDeviceAuthenticationRotation]) before
     * failing. Other failures leave both keys as they are for another
     * attempt. Throws
     * [SecureMessageClientException.NoPendingDeviceAuthenticationRotation],
     * [SecureMessageTransportException.AuthenticationFailed] and
     * [SecureMessageTransportException.DeviceAuthenticationRotationRejected].
     */
    suspend fun completeDeviceAuthenticationRotation() {
        deviceAuthenticationMutex.withLock { completeRotationLocked() }
    }

    private suspend fun completeRotationLocked() {
        val (active, pending) = storage.transaction {
            val active = requireDeviceAuthenticationKey()
            val pending = deviceAuthentication.pendingRotationKeyPair()
            if (pending == null) {
                active.privateKey.fill(0)
                throw SecureMessageClientException.NoPendingDeviceAuthenticationRotation()
            }
            active to pending
        }
        val replacementKey = pending.publicKey
        try {
            val signer = ServerRequestSigner { request ->
                require(request.address == localAddress) { "Request is not for this device" }
                ServerRequestAuthentication.sign(active, request, clock.now())
            }
            val epoch = try {
                transport.registrationStatus(localAddress, signer).authEpoch
            } catch (e: SecureMessageTransportException.AuthenticationFailed) {
                // K1 is no longer the registered key: an earlier attempt may have installed K2.
                if (e.failure == SecureMessageTransportException.AuthenticationFailure.INVALID && resolveRotationLocked()) return
                throw e
            }
            val authorization = DeviceAuthenticationRotation.create(active, pending, localAddress, epoch, clock.now())
            try {
                transport.rotateDeviceAuthenticationKey(authorization)
            } catch (e: SecureMessageTransportException.DeviceAuthenticationRotationRejected) {
                // A lost response, or an earlier attempt that won: K2 may be registered already.
                if (e.reason in RESOLVABLE_ROTATION_FAILURES && resolveRotationLocked()) return
                throw e
            }
        } finally {
            active.privateKey.fill(0)
            pending.privateKey.fill(0)
        }
        promotePendingRotationKey(replacementKey)
    }

    /**
     * [prepareDeviceAuthenticationRotation] followed by
     * [completeDeviceAuthenticationRotation]. Resumes a pending rotation
     * with its existing key.
     */
    suspend fun rotateDeviceAuthenticationKey() {
        deviceAuthenticationMutex.withLock {
            prepareRotationLocked()
            completeRotationLocked()
        }
    }

    /**
     * This device's server authentication status
     * (docs/device-authentication-rotation.md): the authentication epoch and
     * the server time the registered key was installed at, read from the
     * server with a request signed by the active key (never cached, never
     * stored locally), the key's age by this client's clock (clamped at
     * zero), and whether a rotation or recovery key is pending locally
     * ([DeviceAuthenticationRotationStatus.pendingRecovery] covers device
     * recovery and last-device recovery).
     * Changes nothing. Throws [SecureMessageClientException.NotInitialized]
     * without an active key and
     * [SecureMessageTransportException.AuthenticationFailed] if the active
     * key is not the registered one.
     */
    suspend fun deviceAuthenticationRotationStatus(): DeviceAuthenticationRotationStatus {
        val transitions = storage.transaction { localAuthenticationTransitions() }
        val active = storage.transaction { requireDeviceAuthenticationKey() }
        val registration = withRequestSigner(active) { _, signer -> transport.registrationStatus(localAddress, signer) }
        return DeviceAuthenticationRotationStatus(
            authEpoch = registration.authEpoch,
            authKeyInstalledAt = registration.authKeyInstalledAt,
            evaluatedAt = clock.now(),
            pendingRotation = transitions.rotation,
            pendingRecovery = transitions.recovery,
        )
    }

    /**
     * Evaluates [policy] against the server's key installation time
     * ([deviceAuthenticationRotationStatus]): [DeviceAuthenticationRotationDecision.Due]
     * once the key's age is at least [DeviceAuthenticationRotationPolicy.maxKeyAge].
     * A pending recovery or rotation is reported without asking the server.
     * Never rotates and never creates a key.
     */
    suspend fun evaluateDeviceAuthenticationRotation(policy: DeviceAuthenticationRotationPolicy): DeviceAuthenticationRotationDecision {
        val transitions = storage.transaction { requireIdentity(); localAuthenticationTransitions() }
        if (transitions.recovery) return DeviceAuthenticationRotationDecision.RecoveryPending
        if (transitions.rotation) return DeviceAuthenticationRotationDecision.RotationPending
        val status = deviceAuthenticationRotationStatus()
        return if (policy.isDue(status.age)) {
            DeviceAuthenticationRotationDecision.Due(status)
        } else {
            DeviceAuthenticationRotationDecision.NotNeeded(status)
        }
    }

    /**
     * Rotates the device authentication key if [policy] says it is due, with
     * the routine rotation of [rotateDeviceAuthenticationKey]
     * (docs/device-authentication-rotation.md). Only runs when the
     * application calls it: nothing in the library calls it implicitly.
     *
     * - A pending device recovery or last-device recovery: returns
     *   [DeviceAuthenticationRotationResult.RecoveryInProgress], starts nothing.
     * - A pending routine rotation: completes it with its existing key
     *   (including the lost-response resolution of
     *   [completeDeviceAuthenticationRotation]) and returns
     *   [DeviceAuthenticationRotationResult.ResumedPendingRotation]; never a
     *   second pending key.
     * - Otherwise reads the status from the server: not due returns
     *   [DeviceAuthenticationRotationResult.NotNeeded], due rotates and
     *   returns [DeviceAuthenticationRotationResult.Rotated].
     *
     * Concurrent calls on one instance run one after the other: the second
     * sees the new key's age and returns NotNeeded. Throws what
     * [completeDeviceAuthenticationRotation] throws.
     */
    suspend fun rotateDeviceAuthenticationKeyIfNeeded(policy: DeviceAuthenticationRotationPolicy): DeviceAuthenticationRotationResult =
        deviceAuthenticationMutex.withLock {
            val transitions = storage.transaction { requireIdentity(); localAuthenticationTransitions() }
            if (transitions.recovery) return@withLock DeviceAuthenticationRotationResult.RecoveryInProgress
            if (transitions.rotation) {
                completeRotationLocked()
                return@withLock DeviceAuthenticationRotationResult.ResumedPendingRotation
            }
            val status = deviceAuthenticationRotationStatus()
            if (!policy.isDue(status.age)) return@withLock DeviceAuthenticationRotationResult.NotNeeded(status)
            prepareRotationLocked()
            completeRotationLocked()
            DeviceAuthenticationRotationResult.Rotated(status)
        }

    private class AuthenticationTransitions(val rotation: Boolean, val recovery: Boolean)

    /**
     * Which device authentication transitions are pending locally; `recovery`
     * covers device recovery and last-device recovery. Wipes the loaded
     * private keys.
     */
    private suspend fun ClientStorage.localAuthenticationTransitions(): AuthenticationTransitions {
        val rotation = deviceAuthentication.pendingRotationKeyPair()?.also { it.privateKey.fill(0) } != null
        val recovery = deviceAuthentication.pendingRecoveryKeyPair()?.also { it.privateKey.fill(0) } != null
        val lastDevice = deviceAuthentication.pendingLastDeviceRecoveryKeyPair()?.also { it.privateKey.fill(0) } != null
        return AuthenticationTransitions(rotation, recovery || lastDevice)
    }

    /**
     * The state of this device's server authentication credentials
     * (docs/device-authentication-health.md), for the application to show or
     * act on. Read-only: never initializes, registers, rotates, recovers,
     * resolves, cancels, creates a key, writes storage or caches anything,
     * and is never called implicitly.
     *
     * Local state decides first, without asking the server, in this order:
     * several pending transitions → [DeviceAuthenticationHealth.Inconsistent];
     * a pending device or last-device recovery →
     * [DeviceAuthenticationHealth.RecoveryPending]; a pending rotation →
     * [DeviceAuthenticationHealth.RotationPending] (or Inconsistent without
     * the active key); no active key → [DeviceAuthenticationHealth.ActiveKeyMissing].
     * Otherwise reads the registration status once with a request signed by
     * the active key: not registered → [DeviceAuthenticationHealth.Unregistered];
     * else [DeviceAuthenticationHealth.RotationDue] if [policy] says the key's
     * age (client clock, read once, minus the server installation time,
     * clamped at zero) reached its maximum, and [DeviceAuthenticationHealth.Healthy]
     * otherwise or without a [policy]. There is no default policy.
     *
     * The local state is read again (no second request) after the server
     * answered; a transition that appeared meanwhile is reported instead.
     * Throws [SecureMessageClientException.NotInitialized] without a local
     * identity or on storage that has not created its first key yet
     * (milestone 12 upgrade), and every transport failure, including
     * [SecureMessageTransportException.AuthenticationFailed] other than
     * `NOT_REGISTERED`, as it is.
     */
    suspend fun deviceAuthenticationHealth(policy: DeviceAuthenticationRotationPolicy? = null): DeviceAuthenticationHealth =
        deviceAuthenticationMutex.withLock {
            val local = storage.transaction { localAuthenticationState() }
            local.classify()?.let {
                local.active?.privateKey?.fill(0)
                return@withLock it
            }
            val active = checkNotNull(local.active)
            val registration = try {
                withRequestSigner(active) { _, signer -> transport.registrationStatus(localAddress, signer) }
            } catch (e: SecureMessageTransportException.AuthenticationFailed) {
                if (e.failure != SecureMessageTransportException.AuthenticationFailure.NOT_REGISTERED) throw e
                null
            }
            // A transition that does not take this mutex (device recovery) may have started during the request.
            val after = storage.transaction { localAuthenticationState() }
            after.active?.privateKey?.fill(0)
            after.classify()?.let { return@withLock it }
            if (registration == null) return@withLock DeviceAuthenticationHealth.Unregistered
            val status = DeviceAuthenticationRotationStatus(
                authEpoch = registration.authEpoch,
                authKeyInstalledAt = registration.authKeyInstalledAt,
                evaluatedAt = clock.now(),
                pendingRotation = false,
                pendingRecovery = false,
            )
            if (policy != null && policy.isDue(status.age)) {
                DeviceAuthenticationHealth.RotationDue(status, policy)
            } else {
                DeviceAuthenticationHealth.Healthy(status, policy)
            }
        }

    private class LocalAuthenticationState(
        val active: DeviceAuthenticationKeyPair?,
        val awaitsUpgradeKey: Boolean,
        val rotation: Boolean,
        val recovery: Boolean,
        val lastDeviceRecovery: Boolean,
    ) {
        /** The health local state alone decides, or `null` if the server has to be asked. */
        fun classify(): DeviceAuthenticationHealth? = when {
            listOf(rotation, recovery, lastDeviceRecovery).count { it } > 1 ->
                DeviceAuthenticationHealth.Inconsistent(DeviceAuthenticationHealthInconsistency.MULTIPLE_PENDING_TRANSITIONS)
            recovery -> DeviceAuthenticationHealth.RecoveryPending(DeviceAuthenticationRecoveryKind.DEVICE_RECOVERY)
            lastDeviceRecovery -> DeviceAuthenticationHealth.RecoveryPending(DeviceAuthenticationRecoveryKind.LAST_DEVICE_RECOVERY)
            rotation && active == null ->
                DeviceAuthenticationHealth.Inconsistent(DeviceAuthenticationHealthInconsistency.ROTATION_PENDING_WITHOUT_ACTIVE_KEY)
            rotation -> DeviceAuthenticationHealth.RotationPending
            active == null -> if (awaitsUpgradeKey) throw SecureMessageClientException.NotInitialized() else DeviceAuthenticationHealth.ActiveKeyMissing
            else -> null
        }
    }

    /**
     * The active key pair (the caller wipes it) and which pending slots are
     * filled; wipes the pending private keys. Needs the local identity.
     */
    private suspend fun ClientStorage.localAuthenticationState(): LocalAuthenticationState {
        requireIdentity()
        return LocalAuthenticationState(
            active = deviceAuthentication.keyPair(),
            awaitsUpgradeKey = deviceAuthentication.awaitsUpgradeKey(),
            rotation = deviceAuthentication.pendingRotationKeyPair()?.also { it.privateKey.fill(0) } != null,
            recovery = deviceAuthentication.pendingRecoveryKeyPair()?.also { it.privateKey.fill(0) } != null,
            lastDeviceRecovery = deviceAuthentication.pendingLastDeviceRecoveryKeyPair()?.also { it.privateKey.fill(0) } != null,
        )
    }

    /**
     * Asks the server whether this device's pending rotation key is its
     * registered key, with a registration request signed by that key. If it
     * is, makes it the active key and returns `true`; if the server holds
     * another key, returns `false` and keeps both keys. For a rotation whose
     * response was lost, or that the server applied before the local
     * promotion failed. Throws
     * [SecureMessageClientException.NoPendingDeviceAuthenticationRotation].
     */
    suspend fun resolveDeviceAuthenticationRotation(): Boolean =
        deviceAuthenticationMutex.withLock { resolveRotationLocked() }

    private suspend fun resolveRotationLocked(): Boolean {
        val pending = storage.transaction { deviceAuthentication.pendingRotationKeyPair() }
            ?: throw SecureMessageClientException.NoPendingDeviceAuthenticationRotation()
        val publicKey = pending.publicKey
        if (!probeRegistration(pending)) return false
        promotePendingRotationKey(publicKey)
        return true
    }

    /**
     * Deletes the pending rotation key; the active key and a pending recovery
     * key are not touched. Only for a rotation that will not be completed:
     * call [resolveDeviceAuthenticationRotation] first, because if the server
     * already accepted it, only the deleted key authenticates this device and
     * it has to be recovered (docs/device-recovery.md).
     */
    suspend fun cancelDeviceAuthenticationRotation() {
        deviceAuthenticationMutex.withLock {
            storage.transaction { deviceAuthentication.removePendingRotationKeyPair() }
        }
    }

    /**
     * Promotes the pending rotation key only if it is still the one the
     * server accepted. If another client instance on the same storage
     * promoted exactly this key already, there is nothing left to do.
     */
    private suspend fun promotePendingRotationKey(publicKey: ByteArray) = storage.transaction {
        val pending = deviceAuthentication.pendingRotationKeyPair()
        if (pending == null) {
            val active = deviceAuthentication.keyPair()?.also { it.privateKey.fill(0) }
            if (active != null && active.publicKey.contentEquals(publicKey)) return@transaction
            throw SecureMessageClientException.NoPendingDeviceAuthenticationRotation()
        }
        pending.privateKey.fill(0)
        if (!pending.publicKey.contentEquals(publicKey)) {
            throw SecureMessageClientException.InvalidDeviceAuthenticationRotation("The pending rotation key changed")
        }
        deviceAuthentication.promotePendingRotationKeyPair()
    }

    /**
     * Creates a new offline last-device recovery key for this user
     * (docs/last-device-recovery.md). Returns it to the application and
     * stores nothing: the application backs it up offline (for example
     * [LastDeviceRecoveryKey.encode] printed or in a password manager) and
     * registers it with [registerLastDeviceRecoveryKey]. Whoever holds it can
     * replace the server authentication key of every registered device of
     * the user. No network I/O.
     */
    suspend fun createLastDeviceRecoveryKey(): LastDeviceRecoveryKey = protocol.createLastDeviceRecoveryKey()

    /**
     * Registers [key]'s public key as this user's last-device recovery key,
     * in a request signed with this device's active device authentication
     * key and with the recovery key's proof of possession. Only the public
     * key is sent. Registering the same key again is harmless; the server
     * never replaces a registered recovery key
     * ([SecureMessageTransportException.LastDeviceRecoveryKeyRejected] with
     * `CONFLICT`). Never called implicitly. Throws
     * [SecureMessageClientException.NotInitialized] without an active key.
     */
    suspend fun registerLastDeviceRecoveryKey(key: LastDeviceRecoveryKey) {
        val registration = LastDeviceRecovery.registerKey(key, localAddress.userId)
        withRequestSigner { _, signer -> transport.registerLastDeviceRecoveryKey(localAddress, registration, signer) }
    }

    /**
     * The server's state of this user's offline recovery key
     * (docs/recovery-key-lifecycle.md): unconfigured, active (epoch,
     * installation time, public key) or revoked (epoch, revocation time).
     * A signed request with this device's active device authentication key;
     * never cached. Compare [LastDeviceRecoveryKeyStatus.Active.isKey] with
     * a backed-up key's [LastDeviceRecoveryKey.publicKey] to check that the
     * backup is still the active key.
     */
    suspend fun lastDeviceRecoveryKeyStatus(): LastDeviceRecoveryKeyStatus = deviceAuthenticationMutex.withLock {
        withRequestSigner { _, signer -> transport.lastDeviceRecoveryKeyStatus(localAddress, signer) }
    }

    /**
     * Replaces this user's offline recovery key [currentKey] with [newKey]
     * (docs/recovery-key-lifecycle.md). Two authorities: this device's
     * signed request, and [currentKey]'s signature; [newKey] proves
     * possession. Neither key is stored.
     *
     * **Back up [newKey] before calling this.** Create it with
     * [createLastDeviceRecoveryKey], have the user store
     * [LastDeviceRecoveryKey.encode] offline and confirm it, and only then
     * rotate: once the server accepted the rotation, [currentKey] no longer
     * recovers anything, and a lost [newKey] cannot be replaced by a device
     * alone.
     *
     * Reads the status first. If [newKey] is already active (an earlier
     * call's response was lost, or the application restarted), returns
     * [LastDeviceRecoveryKeyRotationResult.ALREADY_ACTIVE] without sending
     * anything; call it again with the same keys to resolve an unknown
     * outcome. Throws [SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured]
     * if no key is active, [SecureMessageClientException.LastDeviceRecoveryKeyMismatch]
     * if neither key is the active one, and
     * [SecureMessageTransportException.RecoveryKeyRotationRejected] if the
     * server refused (for example `CONFLICT` if another transition won).
     * Never called implicitly.
     */
    suspend fun rotateLastDeviceRecoveryKey(
        currentKey: LastDeviceRecoveryKey,
        newKey: LastDeviceRecoveryKey,
    ): LastDeviceRecoveryKeyRotationResult {
        require(currentKey != newKey) { "The new recovery key must differ from the current one" }
        return deviceAuthenticationMutex.withLock {
            withRequestSigner { _, signer ->
                val status = transport.lastDeviceRecoveryKeyStatus(localAddress, signer)
                val active = status as? LastDeviceRecoveryKeyStatus.Active ?: throw SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured()
                if (active.isKey(newKey.publicKey)) return@withRequestSigner LastDeviceRecoveryKeyRotationResult.ALREADY_ACTIVE
                if (!active.isKey(currentKey.publicKey)) throw SecureMessageClientException.LastDeviceRecoveryKeyMismatch()
                val authorization = RecoveryKeyRotation.authorize(currentKey, newKey, localAddress, active.epoch, clock.now())
                try {
                    transport.rotateLastDeviceRecoveryKey(authorization, signer)
                } catch (e: SecureMessageTransportException.RecoveryKeyRotationRejected) {
                    // Another submission of this rotation may have won; then the new key is active.
                    val now = runCatching { transport.lastDeviceRecoveryKeyStatus(localAddress, signer) }.getOrNull()
                    if (e.reason == SecureMessageTransportException.RecoveryKeyTransitionFailure.CONFLICT &&
                        now is LastDeviceRecoveryKeyStatus.Active && now.isKey(newKey.publicKey)
                    ) {
                        return@withRequestSigner LastDeviceRecoveryKeyRotationResult.ROTATED
                    }
                    throw e
                }
                LastDeviceRecoveryKeyRotationResult.ROTATED
            }
        }
    }

    /**
     * Revokes this user's offline recovery key [currentKey]
     * (docs/recovery-key-lifecycle.md): this device's signed request and
     * [currentKey]'s signature. Afterwards no last-device recovery is
     * possible, and outstanding challenges are dead, until a new key is
     * registered with [registerLastDeviceRecoveryKey] (the recovery key
     * epoch continues). Nothing is generated as a replacement.
     *
     * Reads the status first: an already revoked key gives
     * [LastDeviceRecoveryKeyRevocationResult.ALREADY_REVOKED] without
     * sending anything. Throws [SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured]
     * if the user never registered a key,
     * [SecureMessageClientException.LastDeviceRecoveryKeyMismatch] if
     * [currentKey] is not the active key, and
     * [SecureMessageTransportException.RecoveryKeyRevocationRejected] if the
     * server refused. Never called implicitly.
     */
    suspend fun revokeLastDeviceRecoveryKey(currentKey: LastDeviceRecoveryKey): LastDeviceRecoveryKeyRevocationResult =
        deviceAuthenticationMutex.withLock {
            withRequestSigner { _, signer ->
                val active = when (val status = transport.lastDeviceRecoveryKeyStatus(localAddress, signer)) {
                    LastDeviceRecoveryKeyStatus.Unconfigured -> throw SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured()
                    is LastDeviceRecoveryKeyStatus.Revoked -> return@withRequestSigner LastDeviceRecoveryKeyRevocationResult.ALREADY_REVOKED
                    is LastDeviceRecoveryKeyStatus.Active -> status
                }
                if (!active.isKey(currentKey.publicKey)) throw SecureMessageClientException.LastDeviceRecoveryKeyMismatch()
                val authorization = RecoveryKeyRevocation.authorize(currentKey, localAddress, active.epoch, clock.now())
                try {
                    transport.revokeLastDeviceRecoveryKey(authorization, signer)
                } catch (e: SecureMessageTransportException.RecoveryKeyRevocationRejected) {
                    // Another device may have revoked the key meanwhile (CONFLICT, or NOT_CONFIGURED once revoked): the goal is reached.
                    val now = runCatching { transport.lastDeviceRecoveryKeyStatus(localAddress, signer) }.getOrNull()
                    if (e.reason in REVOCATION_RACE_FAILURES && now is LastDeviceRecoveryKeyStatus.Revoked) {
                        return@withRequestSigner LastDeviceRecoveryKeyRevocationResult.ALREADY_REVOKED
                    }
                    throw e
                }
                LastDeviceRecoveryKeyRevocationResult.REVOKED
            }
        }

    /**
     * Requests a delayed reset of this user's offline recovery key, for when
     * that key is **lost** (docs/recovery-key-reset.md). Exceptional: if the
     * current key is still available, use [rotateLastDeviceRecoveryKey].
     *
     * A signed request of this device; the server stores the reset with its
     * own time and policy delay and returns it. Every registered device of
     * the user can see it ([lastDeviceRecoveryKeyResetStatus]) and cancel it
     * ([cancelLastDeviceRecoveryKeyReset]), and so can the current recovery
     * key. If a reset is pending already, it is returned unchanged: calling
     * this again (after a lost response or a restart) never restarts the
     * delay. Nothing completes automatically: after
     * [RecoveryKeyResetStatus.Pending.eligibleAt] call
     * [completeLastDeviceRecoveryKeyReset] with a new, backed-up key.
     *
     * Throws [SecureMessageTransportException.RecoveryKeyResetRejected]
     * (`NOT_AVAILABLE` if the server has no reset policy, `NOT_CONFIGURED`
     * if no key is active). Never called implicitly.
     */
    suspend fun requestLastDeviceRecoveryKeyReset(): RecoveryKeyResetStatus.Pending = deviceAuthenticationMutex.withLock {
        withRequestSigner { _, signer -> transport.requestLastDeviceRecoveryKeyReset(localAddress, signer) }
    }

    /**
     * The pending recovery key reset of this user, or [RecoveryKeyResetStatus.None]
     * (docs/recovery-key-reset.md). A signed request; never cached. The
     * library never polls: applications that want every device to notice a
     * reset must call this themselves (for example on start and
     * periodically) and warn the user while one is pending.
     */
    suspend fun lastDeviceRecoveryKeyResetStatus(): RecoveryKeyResetStatus = deviceAuthenticationMutex.withLock {
        withRequestSigner { _, signer -> transport.lastDeviceRecoveryKeyResetStatus(localAddress, signer) }
    }

    /**
     * Whether this user has a pending recovery key reset to surface
     * (docs/recovery-key-reset.md, "Reset awareness"). Read-only: reads the
     * recovery key status and then the reset status (two signed requests
     * with this device's active device authentication key, never cached),
     * checks that the reset is bound to the active key and epoch of this
     * user, and classifies it with the client clock:
     * [RecoveryKeyResetAwareness.Pending] before
     * [RecoveryKeyResetStatus.Pending.eligibleAt],
     * [RecoveryKeyResetAwareness.Eligible] from then on. The server still
     * decides eligibility with its own clock when a completion is submitted.
     *
     * The two reads are not atomic. A mismatch that a transition between
     * them can explain is read again once (at most four requests); if it
     * persists, returns [RecoveryKeyResetAwareness.Inconsistent]. Never
     * requests, cancels or completes a reset, never rotates a key, stores
     * nothing, and is never called implicitly.
     */
    suspend fun recoveryKeyResetAwareness(): RecoveryKeyResetAwareness = deviceAuthenticationMutex.withLock {
        withRequestSigner { _, signer ->
            suspend fun read(): Pair<LastDeviceRecoveryKeyStatus, RecoveryKeyResetStatus> =
                transport.lastDeviceRecoveryKeyStatus(localAddress, signer) to transport.lastDeviceRecoveryKeyResetStatus(localAddress, signer)

            var (keyStatus, resetStatus) = read()
            var inconsistency = resetAwarenessInconsistency(keyStatus, resetStatus)
            if (inconsistency != null && inconsistency != RecoveryKeyResetAwarenessInconsistency.RESET_OF_OTHER_USER) {
                // A transition between the two reads can explain it: read the pair once more, never loop.
                read().let { (key, reset) -> keyStatus = key; resetStatus = reset }
                inconsistency = resetAwarenessInconsistency(keyStatus, resetStatus)
            }
            if (inconsistency != null) return@withRequestSigner RecoveryKeyResetAwareness.Inconsistent(inconsistency)
            val reset = resetStatus as? RecoveryKeyResetStatus.Pending ?: return@withRequestSigner RecoveryKeyResetAwareness.None
            val now = clock.now()
            if (reset.isEligibleAt(now)) RecoveryKeyResetAwareness.Eligible(reset, now) else RecoveryKeyResetAwareness.Pending(reset, now)
        }
    }

    private fun resetAwarenessInconsistency(
        keyStatus: LastDeviceRecoveryKeyStatus,
        resetStatus: RecoveryKeyResetStatus,
    ): RecoveryKeyResetAwarenessInconsistency? {
        val reset = resetStatus as? RecoveryKeyResetStatus.Pending ?: return null
        return when {
            reset.userId != localAddress.userId -> RecoveryKeyResetAwarenessInconsistency.RESET_OF_OTHER_USER
            keyStatus !is LastDeviceRecoveryKeyStatus.Active -> RecoveryKeyResetAwarenessInconsistency.RESET_WITHOUT_ACTIVE_RECOVERY_KEY
            keyStatus.epoch != reset.recoveryKeyEpoch -> RecoveryKeyResetAwarenessInconsistency.RESET_EPOCH_MISMATCH
            !keyStatus.isKey(reset.recoveryPublicKey) -> RecoveryKeyResetAwarenessInconsistency.RESET_KEY_MISMATCH
            else -> null
        }
    }

    /**
     * Completes the pending recovery key reset with [newKey]
     * (docs/recovery-key-reset.md): this device's signed request and
     * [newKey]'s proof of possession over the pending reset. The server
     * accepts it only from the reset's eligibility time on (its own clock).
     * [newKey] is not stored.
     *
     * **Back up [newKey] before calling this**, exactly as for a rotation:
     * once the server accepted it, the old key recovers nothing any more.
     *
     * Reads the recovery key status first: if [newKey] is already active (a
     * lost response, a restart), returns
     * [LastDeviceRecoveryKeyResetResult.ALREADY_ACTIVE] without sending
     * anything. Throws [SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured]
     * if no key is active, [SecureMessageClientException.LastDeviceRecoveryKeyResetNotPending]
     * if no reset is pending, [IllegalArgumentException] if [newKey] is the
     * key being replaced, and [SecureMessageTransportException.RecoveryKeyResetRejected]
     * if the server refused (`NOT_YET_ELIGIBLE`, `CONFLICT`, …). Never called
     * implicitly.
     */
    suspend fun completeLastDeviceRecoveryKeyReset(newKey: LastDeviceRecoveryKey): LastDeviceRecoveryKeyResetResult =
        deviceAuthenticationMutex.withLock {
            withRequestSigner { _, signer ->
                val status = transport.lastDeviceRecoveryKeyStatus(localAddress, signer)
                val active = status as? LastDeviceRecoveryKeyStatus.Active ?: throw SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured()
                val pending = transport.lastDeviceRecoveryKeyResetStatus(localAddress, signer) as? RecoveryKeyResetStatus.Pending
                if (active.isKey(newKey.publicKey)) {
                    // The key the pending reset would replace is no new key; any other active key means a completion happened.
                    require(pending == null || !pending.recoveryPublicKey.contentEquals(newKey.publicKey)) {
                        "The new recovery key must differ from the key being reset"
                    }
                    return@withRequestSigner LastDeviceRecoveryKeyResetResult.ALREADY_ACTIVE
                }
                val reset = pending ?: throw SecureMessageClientException.LastDeviceRecoveryKeyResetNotPending()
                val authorization = RecoveryKeyReset.complete(newKey, reset, localAddress)
                try {
                    transport.completeLastDeviceRecoveryKeyReset(authorization, signer)
                } catch (e: SecureMessageTransportException.RecoveryKeyResetRejected) {
                    // Another submission of this completion may have won; then the new key is active.
                    val now = runCatching { transport.lastDeviceRecoveryKeyStatus(localAddress, signer) }.getOrNull()
                    if (e.reason in RESET_RACE_FAILURES && now is LastDeviceRecoveryKeyStatus.Active && now.isKey(newKey.publicKey)) {
                        return@withRequestSigner LastDeviceRecoveryKeyResetResult.COMPLETED
                    }
                    throw e
                }
                LastDeviceRecoveryKeyResetResult.COMPLETED
            }
        }

    /**
     * Cancels the pending recovery key [reset] as this device (a signed
     * request; docs/recovery-key-reset.md). The recovery key and its epoch
     * stay; last-device recovery challenges stay valid.
     *
     * If [reset] is no longer pending, returns
     * [LastDeviceRecoveryKeyResetCancellationResult.NotPending] with the
     * current recovery key status and reset: the same key and epoch mean it
     * was cancelled (by an earlier call whose response was lost, or by
     * another authority); another key means a completion or rotation won.
     * Never recreates a reset.
     */
    suspend fun cancelLastDeviceRecoveryKeyReset(reset: RecoveryKeyResetStatus.Pending): LastDeviceRecoveryKeyResetCancellationResult {
        require(reset.userId == localAddress.userId) { "The reset belongs to another user" }
        return deviceAuthenticationMutex.withLock {
            withRequestSigner { _, signer ->
                try {
                    transport.cancelLastDeviceRecoveryKeyReset(localAddress, reset.resetId, signer)
                    LastDeviceRecoveryKeyResetCancellationResult.Cancelled
                } catch (e: SecureMessageTransportException.RecoveryKeyResetRejected) {
                    if (e.reason != SecureMessageTransportException.RecoveryKeyResetFailure.NOT_PENDING) throw e
                    LastDeviceRecoveryKeyResetCancellationResult.NotPending(
                        transport.lastDeviceRecoveryKeyStatus(localAddress, signer),
                        transport.lastDeviceRecoveryKeyResetStatus(localAddress, signer),
                    )
                }
            }
        }
    }

    /**
     * The pending recovery key reset of this user, queried with the current
     * offline recovery key [currentKey] instead of a device
     * (docs/recovery-key-reset.md). Works without this device's
     * authentication key and before [initialize]: the holder of the offline
     * key can always see a reset that would replace it. [currentKey] is not
     * stored or sent; only its signature is. Throws
     * [SecureMessageTransportException.RecoveryKeyResetRejected]
     * (`INVALID_PROOF` if [currentKey] is not the active key, `NOT_CONFIGURED`
     * if none is active).
     */
    suspend fun lastDeviceRecoveryKeyResetStatusByRecoveryKey(currentKey: LastDeviceRecoveryKey): RecoveryKeyResetStatus =
        transport.lastDeviceRecoveryKeyResetStatusByRecoveryKey(RecoveryKeyReset.statusQuery(currentKey, localAddress.userId, clock.now()))

    /**
     * Cancels the pending recovery key [reset] with the offline recovery key
     * it would replace, [currentKey] (docs/recovery-key-reset.md): an
     * independent veto that needs no device and works without this device's
     * authentication key. Throws [IllegalArgumentException] if [currentKey]
     * is not the key [reset] replaces.
     *
     * If [reset] is no longer pending, returns
     * [LastDeviceRecoveryKeyResetCancellationResult.NotPending] with the
     * reset now pending as seen by [currentKey] (`null` when [currentKey] is
     * no longer the active key: a completion or rotation won) and no
     * recovery key status.
     */
    suspend fun cancelLastDeviceRecoveryKeyResetByRecoveryKey(
        currentKey: LastDeviceRecoveryKey,
        reset: RecoveryKeyResetStatus.Pending,
    ): LastDeviceRecoveryKeyResetCancellationResult {
        require(reset.userId == localAddress.userId) { "The reset belongs to another user" }
        val authorization = RecoveryKeyReset.cancel(currentKey, reset)
        return try {
            transport.cancelLastDeviceRecoveryKeyResetByRecoveryKey(authorization)
            LastDeviceRecoveryKeyResetCancellationResult.Cancelled
        } catch (e: SecureMessageTransportException.RecoveryKeyResetRejected) {
            if (e.reason != SecureMessageTransportException.RecoveryKeyResetFailure.NOT_PENDING) throw e
            val current = try {
                lastDeviceRecoveryKeyResetStatusByRecoveryKey(currentKey)
            } catch (f: SecureMessageTransportException.RecoveryKeyResetRejected) {
                if (f.reason != SecureMessageTransportException.RecoveryKeyResetFailure.INVALID_PROOF &&
                    f.reason != SecureMessageTransportException.RecoveryKeyResetFailure.NOT_CONFIGURED
                ) {
                    throw f
                }
                null
            }
            LastDeviceRecoveryKeyResetCancellationResult.NotPending(recoveryKeyStatus = null, currentReset = current)
        }
    }

    /**
     * Starts or resumes a last-device recovery of this device
     * (docs/last-device-recovery.md): for a device whose registered device
     * authentication key is lost when no other registered device of the
     * user can authorize a device recovery. Creates the replacement key pair
     * once and keeps it as pending last-device recovery key, sealed at rest;
     * later calls reuse it until the recovery completes or is cancelled. The
     * active key (if any) is not touched. No network I/O: call
     * [completeLastDeviceRecovery] with the offline recovery key.
     *
     * Recovers server authentication only. Needs the local messaging identity
     * ([SecureMessageClientException.NotInitialized]); throws
     * [SecureMessageClientException.DeviceAuthenticationRecoveryInProgress]
     * or [SecureMessageClientException.DeviceAuthenticationRotationInProgress]
     * while another transition is pending.
     */
    suspend fun prepareLastDeviceRecovery() {
        deviceAuthenticationMutex.withLock { prepareLastDeviceRecoveryLocked() }
    }

    private suspend fun prepareLastDeviceRecoveryLocked() {
        storage.transaction {
            requireIdentity()
            deviceAuthentication.pendingRecoveryKeyPair()?.let {
                it.privateKey.fill(0)
                throw SecureMessageClientException.DeviceAuthenticationRecoveryInProgress()
            }
            deviceAuthentication.pendingRotationKeyPair()?.let {
                it.privateKey.fill(0)
                throw SecureMessageClientException.DeviceAuthenticationRotationInProgress()
            }
            val pending = deviceAuthentication.pendingLastDeviceRecoveryKeyPair()
                ?: protocol.createDeviceAuthenticationKey().also { deviceAuthentication.storePendingLastDeviceRecoveryKeyPair(it) }
            pending.privateKey.fill(0)
        }
    }

    /**
     * Recovers this device's server authentication with the offline
     * [recoveryKey] (docs/last-device-recovery.md): requests a challenge from
     * the server, signs it together with the pending replacement key (with
     * [recoveryKey] and, as proof of possession, with the replacement key),
     * submits it, and once the server replaced the registered key makes the
     * pending key the active device authentication key. [recoveryKey] is
     * used only in memory and never stored.
     *
     * Safe to call again after a failure, a lost response or a crash before
     * the local promotion: if the server rejects the recovery as conflicting,
     * expired or for an invalid challenge, this asks the server whether the
     * pending key is registered already ([resolveLastDeviceRecovery]) before
     * failing. Other failures keep the pending key for another attempt.
     * Throws [SecureMessageClientException.NoPendingLastDeviceRecovery],
     * [SecureMessageClientException.InvalidLastDeviceRecovery] and
     * [SecureMessageTransportException.LastDeviceRecoveryRejected].
     */
    suspend fun completeLastDeviceRecovery(recoveryKey: LastDeviceRecoveryKey) {
        deviceAuthenticationMutex.withLock { completeLastDeviceRecoveryLocked(recoveryKey) }
    }

    /** [prepareLastDeviceRecovery] followed by [completeLastDeviceRecovery]. Resumes a pending recovery with its existing key. */
    suspend fun recoverLastDevice(recoveryKey: LastDeviceRecoveryKey) {
        deviceAuthenticationMutex.withLock {
            prepareLastDeviceRecoveryLocked()
            completeLastDeviceRecoveryLocked(recoveryKey)
        }
    }

    private suspend fun completeLastDeviceRecoveryLocked(recoveryKey: LastDeviceRecoveryKey) {
        val pending = storage.transaction { deviceAuthentication.pendingLastDeviceRecoveryKeyPair() }
            ?: throw SecureMessageClientException.NoPendingLastDeviceRecovery()
        val replacementKey = pending.publicKey
        try {
            val challenge = transport.lastDeviceRecoveryChallenge(localAddress)
            if (challenge.target != localAddress) {
                throw SecureMessageClientException.InvalidLastDeviceRecovery("The challenge is for another device")
            }
            val authorization = LastDeviceRecovery.authorize(recoveryKey, pending, challenge)
            try {
                transport.recoverLastDevice(authorization)
            } catch (e: SecureMessageTransportException.LastDeviceRecoveryRejected) {
                // A lost response, or an earlier attempt that won: the key may be registered already.
                if (e.reason in RESOLVABLE_LAST_DEVICE_RECOVERY_FAILURES && resolveLastDeviceRecoveryLocked()) return
                throw e
            }
        } finally {
            pending.privateKey.fill(0)
        }
        promotePendingLastDeviceRecoveryKey(replacementKey)
    }

    /**
     * Asks the server whether this device's pending last-device recovery
     * key is its registered key, with a registration request signed by that
     * key (a registration of exactly the registered key changes nothing). If
     * it is, makes it the active key and returns `true`; if the server holds
     * another key, returns `false` and keeps the pending key. Throws
     * [SecureMessageClientException.NoPendingLastDeviceRecovery].
     */
    suspend fun resolveLastDeviceRecovery(): Boolean =
        deviceAuthenticationMutex.withLock { resolveLastDeviceRecoveryLocked() }

    private suspend fun resolveLastDeviceRecoveryLocked(): Boolean {
        val pending = storage.transaction { deviceAuthentication.pendingLastDeviceRecoveryKeyPair() }
            ?: throw SecureMessageClientException.NoPendingLastDeviceRecovery()
        val publicKey = pending.publicKey
        if (!probeRegistration(pending)) return false
        promotePendingLastDeviceRecoveryKey(publicKey)
        return true
    }

    /**
     * Deletes the pending last-device recovery key; the active key and the
     * other slots are not touched. Only for a recovery that will not be
     * completed: call [resolveLastDeviceRecovery] first, because if the
     * server already accepted it, the device has to be recovered again.
     */
    suspend fun cancelLastDeviceRecovery() {
        deviceAuthenticationMutex.withLock {
            storage.transaction { deviceAuthentication.removePendingLastDeviceRecoveryKeyPair() }
        }
    }

    /**
     * Promotes the pending last-device recovery key only if it is still the
     * one the server accepted. If another client instance on the same storage
     * promoted exactly this key already, there is nothing left to do.
     */
    private suspend fun promotePendingLastDeviceRecoveryKey(publicKey: ByteArray) = storage.transaction {
        val pending = deviceAuthentication.pendingLastDeviceRecoveryKeyPair()
        if (pending == null) {
            val active = deviceAuthentication.keyPair()?.also { it.privateKey.fill(0) }
            if (active != null && active.publicKey.contentEquals(publicKey)) return@transaction
            throw SecureMessageClientException.NoPendingLastDeviceRecovery()
        }
        pending.privateKey.fill(0)
        if (!pending.publicKey.contentEquals(publicKey)) {
            throw SecureMessageClientException.InvalidLastDeviceRecovery("The pending last-device recovery key changed")
        }
        deviceAuthentication.promotePendingLastDeviceRecoveryKeyPair()
    }

    /** Promotes the pending key only if it is still the one the server accepted. */
    private suspend fun promotePendingRecoveryKey(publicKey: ByteArray) = storage.transaction {
        val pending = deviceAuthentication.pendingRecoveryKeyPair() ?: throw SecureMessageClientException.NoPendingDeviceRecovery()
        pending.privateKey.fill(0)
        if (!pending.publicKey.contentEquals(publicKey)) {
            throw SecureMessageClientException.InvalidDeviceRecovery("The pending recovery key changed")
        }
        deviceAuthentication.promotePendingRecoveryKeyPair()
    }

    /**
     * Removes and returns the envelopes the server holds for this device, in
     * an authenticated request. Pass them to [decrypt] one at a time, in this
     * order (docs/transport-ordering.md).
     */
    suspend fun receive(): List<EncryptedEnvelope> =
        withRequestSigner { _, signer -> transport.receive(localAddress, signer) }

    /**
     * Loads the device authentication key in its own transaction and runs
     * [block], which does the network I/O, outside of it. The signer signs
     * only requests for [localAddress], each with the current time and a
     * fresh nonce.
     */
    private suspend fun <T> withRequestSigner(
        block: suspend (DeviceAuthenticationKeyPair, ServerRequestSigner) -> T,
    ): T {
        val keyPair = storage.transaction { requireDeviceAuthenticationKey() }
        return withRequestSigner(keyPair, block)
    }

    private suspend fun <T> withRequestSigner(
        keyPair: DeviceAuthenticationKeyPair,
        block: suspend (DeviceAuthenticationKeyPair, ServerRequestSigner) -> T,
    ): T {
        val signer = ServerRequestSigner { request ->
            require(request.address == localAddress) { "Request is not for this device" }
            ServerRequestAuthentication.sign(keyPair, request, clock.now())
        }
        try {
            return block(keyPair, signer)
        } finally {
            keyPair.privateKey.fill(0)
        }
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
     *
     * Every request is signed with the device authentication key; the device
     * must be registered ([registerDevice]).
     */
    suspend fun publishPreKeys() {
        lateinit var keyPair: DeviceAuthenticationKeyPair
        val publications = storage.transaction {
            val identity = requireIdentity()
            keyPair = requireDeviceAuthenticationKey()
            val signedPreKey = preKeys.currentSignedPreKey() ?: throw SecureMessageClientException.NotInitialized()
            preKeys.publicOneTimePreKeys()
                .chunked(PreKeyFormat.MAX_ONE_TIME_PRE_KEYS_PER_PUBLICATION)
                .ifEmpty { listOf(emptyList()) }
                .map { batch ->
                    PreKeyPublication(localAddress, identity.publicKey, signedPreKey.toPublic(), batch)
                }
        }
        // Outside the transaction: it must not wait for the network.
        withRequestSigner(keyPair) { _, signer ->
            for (publication in publications) transport.publishPreKeys(publication, signer)
        }
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

    /**
     * The trust state of [remote]: pinned identity key and verification
     * state, or `null` if nothing is pinned yet (docs/identity-verification.md).
     */
    suspend fun remoteIdentityTrust(remote: DeviceAddress): RemoteIdentityTrust? = storage.transaction {
        requireIdentity()
        remoteIdentities.record(remote)?.let { RemoteIdentityTrust(remote, PublicIdentityKey(it.identityKey), it.verification) }
    }

    /**
     * The safety number of this device and [remote], from the local identity
     * key and the key **pinned** for [remote] (docs/identity-verification.md).
     * Both devices derive the same value. Show [SafetyNumber.displayString]
     * or [SafetyNumber.encode] (for example as a QR code) and let the user
     * compare it with the other device. Throws
     * [SecureMessageClientException.RemoteIdentityNotKnown] if nothing is
     * pinned; never fetches a bundle. Changes nothing.
     */
    suspend fun safetyNumber(remote: DeviceAddress): SafetyNumber = storage.transaction { currentSafetyNumber(remote) }

    /**
     * The safety number [change]'s presented key would have, so the user can
     * compare it with the other device before accepting the change. Changes
     * nothing and trusts nothing.
     */
    suspend fun safetyNumber(change: RemoteIdentityChange): SafetyNumber {
        val identity = storage.transaction { requireIdentity() }
        return SafetyNumber.derive(localAddress, localIdentityKey(identity), change.remote, change.presentedIdentityKey)
    }

    /**
     * Compares the safety number of [remote] with [scanned], the payload the
     * other device shows ([SafetyNumber.encode]). Never changes trust state,
     * also on a match: call [markRemoteIdentityVerified] once the user
     * confirmed. Throws [SecureMessageClientException.InvalidSafetyNumberPayload]
     * for a payload that does not decode and
     * [SecureMessageClientException.RemoteIdentityNotKnown] if nothing is
     * pinned.
     */
    suspend fun compareSafetyNumber(remote: DeviceAddress, scanned: ByteArray): SafetyNumberComparison {
        val payload = try {
            SafetyNumberCodec.decode(scanned)
        } catch (e: IllegalArgumentException) {
            throw SecureMessageClientException.InvalidSafetyNumberPayload(e)
        }
        return safetyNumber(remote).compare(payload)
    }

    /**
     * Records that the user compared [safetyNumber] with the other device and
     * confirmed it: the pinned identity of the remote device in it becomes
     * [VerificationState.VERIFIED]. Bound to that exact key: if the pin
     * changed since [safetyNumber] was derived, this throws
     * [SecureMessageClientException.RemoteIdentityConflict] and changes
     * nothing. A later accepted identity change resets it to
     * [VerificationState.UNVERIFIED].
     */
    suspend fun markRemoteIdentityVerified(safetyNumber: SafetyNumber) {
        val remote = when (localAddress) {
            safetyNumber.first -> safetyNumber.second
            safetyNumber.second -> safetyNumber.first
            else -> throw IllegalArgumentException("The safety number does not involve this device")
        }
        storage.transaction {
            if (currentSafetyNumber(remote) != safetyNumber) throw SecureMessageClientException.RemoteIdentityConflict(remote)
            val pinned = checkNotNull(remoteIdentities.identityKey(remote))
            remoteIdentities.setVerification(remote, pinned, VerificationState.VERIFIED)
        }
    }

    /**
     * Makes the pinned identity of [remote] [VerificationState.UNVERIFIED]
     * again, for example when the user withdraws a verification. The pin
     * stays. Throws [SecureMessageClientException.RemoteIdentityNotKnown].
     */
    suspend fun markRemoteIdentityUnverified(remote: DeviceAddress) {
        storage.transaction {
            requireIdentity()
            val pinned = remoteIdentities.identityKey(remote) ?: throw SecureMessageClientException.RemoteIdentityNotKnown(remote)
            remoteIdentities.setVerification(remote, pinned, VerificationState.UNVERIFIED)
        }
    }

    /**
     * Accepts [change], an identity change the user explicitly approved
     * (docs/identity-verification.md). Never called by the client itself:
     * until this runs, every message and bundle with the new key fails with
     * [SecureMessageClientException.IdentityChanged].
     *
     * Only if [RemoteIdentityChange.previousIdentityKey] is still pinned, in
     * one transaction: the session with the remote device is removed and its
     * initiation retired (so neither it nor a replay of its PreKeyMessages
     * can come back), and the pin becomes exactly
     * [RemoteIdentityChange.presentedIdentityKey], never a key fetched now,
     * as [VerificationState.UNVERIFIED]. Otherwise it throws
     * [SecureMessageClientException.RemoteIdentityConflict] (for example a
     * second, competing acceptance) or
     * [SecureMessageClientException.RemoteIdentityNotKnown] and changes
     * nothing. Other devices' sessions and pins are not touched.
     *
     * Pending messages to the device stay pending and processed message IDs
     * stay processed: [retryPendingMessages] sends pending messages again,
     * with their logical IDs, on a new session with the new identity. The
     * envelope that raised [SecureMessageClientException.IdentityChanged]
     * changed nothing, so it can be passed to [decrypt] again. No network I/O.
     */
    suspend fun acceptRemoteIdentityChange(change: RemoteIdentityChange) {
        val remote = change.remote
        // Serialized with sends, retries and acknowledgements: none of them
        // sees the session disappear between its steps.
        sendMutex.withLock {
            storage.transaction {
                requireIdentity()
                val pinned = remoteIdentities.identityKey(remote) ?: throw SecureMessageClientException.RemoteIdentityNotKnown(remote)
                if (!change.previousIdentityKey.contentEquals(pinned)) throw SecureMessageClientException.RemoteIdentityConflict(remote)
                sessions.load(remote)?.let { session ->
                    val info = protocol.sessionInfo(session)
                    session.state.fill(0)
                    info.initiationId?.let { sessionInitiations.retire(remote, it, info.acceptedSignedPreKeyId) }
                    sessions.remove(remote)
                }
                remoteIdentities.replace(remote, pinned, change.presentedIdentityKey.bytes)
            }
        }
    }

    /** The safety number with the pinned identity of [remote]. Runs inside a transaction. */
    private suspend fun ClientStorage.currentSafetyNumber(remote: DeviceAddress): SafetyNumber {
        val identity = requireIdentity()
        val pinned = remoteIdentities.identityKey(remote) ?: throw SecureMessageClientException.RemoteIdentityNotKnown(remote)
        return SafetyNumber.derive(localAddress, localIdentityKey(identity), remote, PublicIdentityKey(pinned))
    }

    private fun localIdentityKey(identity: LocalIdentity): PublicIdentityKey {
        identity.privateKey.fill(0)
        return PublicIdentityKey(identity.publicKey)
    }

    internal suspend fun ensureSession(remote: DeviceAddress): SecureSession {
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
     * send pending messages again, [abandonPendingMessage] to give one up.
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
     * acknowledges them, which it does only after its application committed
     * them (docs/application-delivery.md), so calling this again sends them
     * again. Before that commit the recipient delivers the retry again as the
     * same message; after it, the recipient only acknowledges it again.
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
     *
     * Each message is read and encrypted in its own transaction, so a message
     * acknowledged meanwhile is skipped. An abandoned message
     * ([abandonPendingMessage]) is never sent again; one abandoned after its
     * envelope was handed off may still be delivered
     * (docs/outbound-message-lifecycle.md).
     */
    suspend fun retryPendingMessages(remote: DeviceAddress): List<LogicalMessageId> = sendMutex.withLock {
        val sent = mutableListOf<LogicalMessageId>()
        var afterSequence = 0L
        // Fetched outside any transaction, only when a message waits and
        // there is no session; used for at most one encryption.
        var bundle: PreKeyBundle? = null
        while (true) {
            val step = storage.transaction {
                requireIdentity()
                // The next pending message as of now: acknowledged or
                // abandoned ones are gone and skipped.
                val pending = pendingOutbound.page(afterSequence, 1, remote).singleOrNull() ?: return@transaction RetryStep.Done
                try {
                    if (bundle == null && sessions.load(remote) == null) return@transaction RetryStep.NeedsBundle
                    RetryStep.Encrypted(pending.id, pending.sequence, encryptOn(remote, bundle, pending.frame))
                } finally {
                    pending.frame.fill(0)
                }
            }
            when (step) {
                RetryStep.Done -> break
                RetryStep.NeedsBundle -> bundle = transport.fetchPreKeyBundle(remote)
                is RetryStep.Encrypted -> {
                    bundle = null
                    afterSequence = step.sequence
                    handOff(step.id, step.envelope)
                    sent += step.id
                }
            }
        }
        sent
    }

    private sealed interface RetryStep {
        data object Done : RetryStep
        data object NeedsBundle : RetryStep
        class Encrypted(val id: LogicalMessageId, val sequence: Long, val envelope: EncryptedEnvelope) : RetryStep
    }

    /**
     * One page of the sent messages not acknowledged yet, with their plaintext
     * (docs/outbound-message-lifecycle.md): at most [limit]
     * (1..[PendingMessagePage.MAX_SIZE]) messages with a
     * [PendingMessage.sequence] greater than [afterSequence] (from the start
     * if `null`), to [recipient] only if given, in ascending sequence order.
     *
     * The cursor is the sequence number, never an offset: messages
     * acknowledged or abandoned between pages do not shift later pages, and no
     * message is returned twice by one enumeration. Each page is read in its
     * own transaction; an enumeration is not a snapshot, so messages sent
     * meanwhile (higher sequence numbers) can appear on later pages. A
     * recipient filter uses the same global sequence as cursor.
     *
     * Throws [IllegalArgumentException] for a [limit] outside
     * 1..[PendingMessagePage.MAX_SIZE] or a negative [afterSequence].
     */
    suspend fun pendingMessages(
        afterSequence: Long? = null,
        limit: Int,
        recipient: DeviceAddress? = null,
    ): PendingMessagePage {
        require(limit in 1..PendingMessagePage.MAX_SIZE) { "limit must be in 1..${PendingMessagePage.MAX_SIZE}" }
        require(afterSequence == null || afterSequence >= 0) { "afterSequence must not be negative" }
        val pending = storage.transaction {
            requireIdentity()
            // One more than asked: tells whether another page exists.
            pendingOutbound.page(afterSequence ?: 0, limit + 1, recipient)
        }
        val more = pending.size > limit
        val messages = pending.take(limit).map {
            val payload = SecurePayloadCodec.decode(it.frame) as SecurePayload.ApplicationMessage
            it.frame.fill(0)
            PendingMessage(it.recipient, it.id, it.sequence, payload.body)
        }
        pending.drop(limit).forEach { it.frame.fill(0) }
        return PendingMessagePage(messages, if (more) messages.last().sequence else null)
    }

    /** The number of sent messages not acknowledged yet, to [recipient] only if given. Opens no record. */
    suspend fun pendingMessageCount(recipient: DeviceAddress? = null): Long = storage.transaction {
        requireIdentity()
        pendingOutbound.count(recipient)
    }

    /** Abandons [message] (docs/outbound-message-lifecycle.md). */
    suspend fun abandonPendingMessage(message: PendingMessage): AbandonStatus = abandonPendingMessage(message.recipient, message.id)

    /**
     * Gives up on delivering message [id] to [recipient]: removes it, plaintext
     * included, from the pending messages in one transaction
     * ([AbandonStatus.ABANDONED]), so no retry sends it again
     * (docs/outbound-message-lifecycle.md). Only this message changes; the
     * session and every other message stay as they are.
     *
     * Local only: nothing is sent, the recipient and the server are not told,
     * and it is not a recall. Envelopes already handed to the transport can
     * still be delivered, and the recipient can still finalize the message and
     * acknowledge it; such an acknowledgement is harmless
     * ([ReceiveResult.Acknowledgement.cleared] is `false`).
     *
     * Idempotent: a message that is not pending (acknowledged, abandoned
     * before, or never sent) changes nothing ([AbandonStatus.NOT_PENDING]).
     * Runs after a send or retry in progress has handed off its envelope,
     * never between its steps. The removal is logical: earlier copies of the
     * sealed record can remain in database files (docs/storage-encryption.md).
     */
    suspend fun abandonPendingMessage(recipient: DeviceAddress, id: LogicalMessageId): AbandonStatus = sendMutex.withLock {
        storage.transaction {
            requireIdentity()
            if (pendingOutbound.remove(recipient, id)) AbandonStatus.ABANDONED else AbandonStatus.NOT_PENDING
        }
    }

    /**
     * Decrypts and processes [envelope] (docs/message-reliability.md,
     * docs/application-delivery.md).
     *
     * - A new application message is stored as pending, sealed at rest, in
     *   the same transaction as its ratchet step, and returned as
     *   [ReceiveResult.Delivery]. It is **not** acknowledged: call
     *   [commitReceivedMessage] once the application has applied it.
     * - A message whose logical ID is pending (a retry before the commit) is
     *   returned again as the same [ReceiveResult.Delivery], not
     *   acknowledged, and not stored twice.
     * - A message whose logical ID was committed is returned as
     *   [ReceiveResult.AlreadyCommitted] without its plaintext and
     *   acknowledged again; one that was discarded likewise as
     *   [ReceiveResult.AlreadyDiscarded].
     * - An acknowledgement removes the matching pending message sent to this
     *   sender ([ReceiveResult.Acknowledgement]). It is never acknowledged.
     *
     * A logical ID that arrives again with another body fails with
     * [SecureMessageClientException.LogicalMessageConflict] and changes
     * nothing and is not acknowledged, also after a discard. For IDs
     * committed before milestone 20 no digest is stored, so such a mismatch
     * is not detected; they count as committed.
     *
     * A failed acknowledgement does not fail this call: the result says
     * `ackSent = false` and the sender's next retry triggers a new one.
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
            is Processed.Delivered -> ReceiveResult.Delivery(processed.message)
            is Processed.AlreadyCommitted -> ReceiveResult.AlreadyCommitted(sender, processed.id, acknowledge(sender, processed.id))
            is Processed.AlreadyDiscarded -> ReceiveResult.AlreadyDiscarded(sender, processed.id, acknowledge(sender, processed.id))
            is Processed.Acknowledged -> ReceiveResult.Acknowledgement(sender, processed.id, processed.cleared)
        }
    }

    /**
     * One page of the received messages the application has not finalized
     * yet, with their plaintext (docs/message-discard.md): at most [limit]
     * (1..[PendingReceivedMessagePage.MAX_SIZE]) messages with a
     * [ReceivedMessage.sequence] greater than [afterSequence] (from the
     * start if `null`), from [sender] only if given, in ascending sequence
     * order. Call it after a restart: a message stays pending until
     * [commitReceivedMessage] or [discardReceivedMessage], whether or not its
     * sender sends it again.
     *
     * The cursor is the sequence number, never an offset: messages finalized
     * between pages do not shift later pages, and no message is returned
     * twice by one enumeration. Each page is read in its own transaction; an
     * enumeration is not a snapshot, so messages accepted meanwhile (higher
     * sequence numbers) can appear on later pages. A sender filter uses the
     * same global sequence as cursor.
     *
     * Throws [IllegalArgumentException] for a [limit] outside
     * 1..[PendingReceivedMessagePage.MAX_SIZE] or a negative [afterSequence].
     */
    suspend fun pendingReceivedMessages(
        afterSequence: Long? = null,
        limit: Int,
        sender: DeviceAddress? = null,
    ): PendingReceivedMessagePage {
        require(limit in 1..PendingReceivedMessagePage.MAX_SIZE) { "limit must be in 1..${PendingReceivedMessagePage.MAX_SIZE}" }
        require(afterSequence == null || afterSequence >= 0) { "afterSequence must not be negative" }
        val pending = storage.transaction {
            requireIdentity()
            // One more than asked: tells whether another page exists.
            pendingInbound.page(afterSequence ?: 0, limit + 1, sender)
        }
        val more = pending.size > limit
        val messages = pending.take(limit).map { it.toReceivedMessage() }
        pending.drop(limit).forEach { it.frame.fill(0) }
        return PendingReceivedMessagePage(messages, if (more) messages.last().sequence else null)
    }

    /** The number of received messages not finalized yet, from [sender] only if given. Opens no record. */
    suspend fun pendingReceivedMessageCount(sender: DeviceAddress? = null): Long = storage.transaction {
        requireIdentity()
        pendingInbound.count(sender)
    }

    /**
     * Records that the application has durably applied [message] and
     * acknowledges it to its sender (docs/application-delivery.md).
     */
    suspend fun commitReceivedMessage(message: ReceivedMessage): CommitResult = commitReceivedMessage(message.sender, message.id)

    /**
     * Records that the application has durably applied message [id] from
     * [sender] and acknowledges it (docs/application-delivery.md).
     *
     * In one transaction the pending message is removed and its logical ID
     * recorded as committed, with the commit time and a digest of its body
     * ([CommitStatus.COMMITTED]). Only after that commit, outside it, the
     * encrypted acknowledgement is sent on the existing session. A failed
     * acknowledgement never undoes the commit: [CommitResult.ackSent] is
     * `false`, and the sender's next retry is acknowledged.
     *
     * Idempotent: for a message committed before, nothing changes and the
     * acknowledgement is sent again ([CommitStatus.ALREADY_COMMITTED]). A
     * discarded message stays discarded ([CommitStatus.ALREADY_DISCARDED],
     * acknowledged again). A message that is neither pending nor finalized
     * (never received, or its entry was pruned) throws
     * [SecureMessageClientException.ReceivedMessageNotPending].
     *
     * Call it only after the application's own transaction committed. If the
     * application crashes in between, the message is delivered again; apply
     * it idempotently, keyed by ([sender], [id]).
     */
    suspend fun commitReceivedMessage(sender: DeviceAddress, id: LogicalMessageId): CommitResult {
        val status = when (finalizeReceived(sender, id, null)) {
            Finalized.NOW -> CommitStatus.COMMITTED
            Finalized.BEFORE_COMMITTED -> CommitStatus.ALREADY_COMMITTED
            Finalized.BEFORE_DISCARDED -> CommitStatus.ALREADY_DISCARDED
        }
        return CommitResult(sender, id, status, acknowledge(sender, id))
    }

    /**
     * Discards [message] for good and acknowledges it to its sender
     * (docs/message-discard.md).
     */
    suspend fun discardReceivedMessage(message: ReceivedMessage, reason: MessageDiscardReason): DiscardResult =
        discardReceivedMessage(message.sender, message.id, reason)

    /**
     * Discards message [id] from [sender] for good: the application will never
     * apply it (docs/message-discard.md). Only for permanent decisions; leave
     * a message that failed for a temporary reason pending.
     *
     * In one transaction the pending message, plaintext included, is removed
     * and a discarded tombstone recorded with the discard time, a digest of
     * its body and [reason] ([DiscardStatus.DISCARDED]). The plaintext is not
     * kept anywhere; store it yourself first if you need it. Only after that
     * commit, outside it, the encrypted acknowledgement is sent on the
     * existing session, the same acknowledgement a commit sends: the sender
     * learns only that the message was finalized, never that it was discarded
     * or why. A failed acknowledgement never undoes the discard:
     * [DiscardResult.ackSent] is `false`, and the sender's next retry is
     * acknowledged. A later copy of the message is not delivered again
     * ([ReceiveResult.AlreadyDiscarded]).
     *
     * Idempotent: a message discarded before stays as it is, with its first
     * reason ([DiscardStatus.ALREADY_DISCARDED]); a committed message stays
     * committed ([DiscardStatus.ALREADY_COMMITTED]); both are acknowledged
     * again. A message that is neither pending nor finalized throws
     * [SecureMessageClientException.ReceivedMessageNotPending] and records
     * nothing.
     */
    suspend fun discardReceivedMessage(sender: DeviceAddress, id: LogicalMessageId, reason: MessageDiscardReason): DiscardResult {
        val status = when (finalizeReceived(sender, id, reason)) {
            Finalized.NOW -> DiscardStatus.DISCARDED
            Finalized.BEFORE_COMMITTED -> DiscardStatus.ALREADY_COMMITTED
            Finalized.BEFORE_DISCARDED -> DiscardStatus.ALREADY_DISCARDED
        }
        return DiscardResult(sender, id, status, acknowledge(sender, id))
    }

    /**
     * In one transaction: commits (no [discardReason]) or discards a pending
     * message, or reports the outcome recorded before. A terminal outcome is
     * never changed. Sends nothing.
     */
    private suspend fun finalizeReceived(sender: DeviceAddress, id: LogicalMessageId, discardReason: MessageDiscardReason?): Finalized =
        storage.transaction {
            requireIdentity()
            val pending = pendingInbound.get(sender, id)
            if (pending != null) {
                val body = pending.body()
                val digest = try {
                    ApplicationMessageDigest.of(body)
                } finally {
                    body.fill(0)
                }
                pendingInbound.remove(sender, id)
                val now = preKeyManager.now()
                if (discardReason == null) {
                    processedInbound.markCommitted(sender, id, digest, now)
                } else {
                    processedInbound.markDiscarded(sender, id, digest, now, discardReason)
                }
                return@transaction Finalized.NOW
            }
            when (processedInbound.get(sender, id)?.finalization) {
                InboundFinalization.COMMITTED -> Finalized.BEFORE_COMMITTED
                InboundFinalization.DISCARDED -> Finalized.BEFORE_DISCARDED
                null -> throw SecureMessageClientException.ReceivedMessageNotPending(sender, id)
            }
        }

    /**
     * Removes the tombstones of finalized (committed or discarded) messages
     * whose age (the [clock] now minus their commit or discard time) is at
     * least [ProcessedInboundRetentionPolicy.maxAge], and returns their number
     * (docs/application-delivery.md, docs/message-discard.md). Pending
     * messages are never removed. Entries from before milestone 20 without a
     * commit time are kept until [initialize] stamps them.
     *
     * Nothing calls this implicitly. After an entry is removed, committed or
     * discarded, a copy of that message the sender sends later is no longer
     * recognized: it is delivered again as new (unless the ratchet rejects the old ciphertext,
     * which it does for a replayed envelope). The retention uses the wall
     * clock: a clock set back removes less, a clock set forward removes
     * earlier.
     */
    suspend fun pruneProcessedMessages(policy: ProcessedInboundRetentionPolicy): Int = storage.transaction {
        requireIdentity()
        if (policy.maxAge.isInfinite()) return@transaction 0
        val now = preKeyManager.now().toEpochMilliseconds()
        // Adapters keep whole milliseconds: age >= maxAge means age >= maxAge rounded up.
        var maxAgeMillis = policy.maxAge.inWholeMilliseconds
        if (maxAgeMillis.milliseconds < policy.maxAge) maxAgeMillis++
        // Nothing can be older than the earliest representable time.
        if (now < Long.MIN_VALUE + maxAgeMillis) return@transaction 0
        processedInbound.pruneFinalizedAtOrBefore(Instant.fromEpochMilliseconds(now - maxAgeMillis))
    }

    /**
     * Applies a decrypted reliability frame inside the receive transaction.
     * A malformed frame or a logical message conflict throws, which rolls
     * back the ratchet step too.
     */
    private suspend fun ClientStorage.process(sender: DeviceAddress, plaintext: ByteArray): Processed {
        val payload = try {
            SecurePayloadCodec.decode(plaintext)
        } finally {
            plaintext.fill(0)
        }
        return when (payload) {
            is SecurePayload.ApplicationMessage -> processApplicationMessage(sender, payload)
            // Scoped to the sender: only the device a message went to can clear it.
            is SecurePayload.Acknowledgement -> Processed.Acknowledged(payload.id, pendingOutbound.remove(sender, payload.id))
        }
    }

    private suspend fun ClientStorage.processApplicationMessage(sender: DeviceAddress, payload: SecurePayload.ApplicationMessage): Processed {
        val id = payload.id
        val body = payload.body
        var delivered = false
        try {
            val processed = processedInbound.get(sender, id)
            if (processed != null) {
                // No digest for IDs committed before milestone 20: they cannot be compared.
                val digest = processed.digest
                if (digest != null && !constantTimeEquals(digest, ApplicationMessageDigest.of(body))) {
                    throw SecureMessageClientException.LogicalMessageConflict(sender, id)
                }
                return when (processed.finalization) {
                    InboundFinalization.COMMITTED -> Processed.AlreadyCommitted(id)
                    InboundFinalization.DISCARDED -> Processed.AlreadyDiscarded(id)
                }
            }
            val pending = pendingInbound.get(sender, id)
            if (pending != null) {
                val message = pending.toReceivedMessage()
                if (!constantTimeEquals(message.plaintext, body)) {
                    message.plaintext.fill(0)
                    throw SecureMessageClientException.LogicalMessageConflict(sender, id)
                }
                return Processed.Delivered(message)
            }
            val receivedAt = preKeyManager.now()
            val frame = SecurePayloadCodec.encode(payload)
            val sequence = try {
                pendingInbound.store(sender, id, frame, receivedAt)
            } finally {
                frame.fill(0)
            }
            delivered = true
            return Processed.Delivered(ReceivedMessage(sender, id, sequence, receivedAt, body))
        } finally {
            if (!delivered) body.fill(0)
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
                submit(envelope)
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
            submit(envelope)
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
        sendMutex.withLock { encryptRaw(remote, plaintext).also { submit(it) } }

    /**
     * Submits [envelope] signed by this device's authentication key (S1):
     * the server accepts only envelopes whose sender is the signing device.
     * Loads the key in its own transaction; the network I/O runs outside it.
     */
    private suspend fun submit(envelope: EncryptedEnvelope) {
        withRequestSigner { _, signer -> transport.send(envelope, signer) }
    }

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
                Received.Plaintext(decryptOn(session, message, identity))
            }
        }
    }

    /**
     * Session setup, repetition, replacement and collision handling for an
     * incoming [PreKeyMessage], see docs/session-lifecycle.md.
     *
     * Only a [SessionInitiationVersion.V2] message can create, replace or win
     * anything; its transcript binds [sender], this device's address and
     * every header field, so a relay that changes any of them makes it fail
     * to decrypt before anything is pinned or retired (S1, findings F3/F4).
     * A [SessionInitiationVersion.V1] message only continues an existing
     * version 1 session as its initiator's repetition.
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
        val session = sessions.load(sender)
        val current = session?.let { protocol.sessionInfo(it) }

        if (message.initiationVersion != SessionInitiationVersion.V2) {
            // Never a new session, replacement, collision win, first pin or
            // retired entry: only the repetition of the initiation that
            // created the existing version 1 session, checked by the engine.
            if (session == null || current?.initiationVersion != SessionInitiationVersion.V1) {
                throw ProtocolException.InvalidMessage("Version 1 session initiations are not accepted")
            }
            val plaintext = decryptOn(session, message, identity)
            if (!pinned) pinLegacySession(sender, session, message, identity)
            return Received.Plaintext(plaintext)
        }

        // A lookup key until acceptSession decrypted with the same transcript.
        val initiation = SessionInitiationId.v2Of(message, sender, localAddress, identity.publicKey)
        val currentInitiation = current?.initiationId

        val plaintext = when {
            // The initiator repeats its PreKeyMessage until it sees a reply.
            session != null && currentInitiation == initiation -> decryptOn(session, message, identity)
            sessionInitiations.isRetired(sender, initiation) ->
                throw SecureMessageClientException.StaleSessionInitiation(sender)
            session == null || current == null -> acceptSession(identity, sender, message, replaced = null)
            // A session from before pinning is never replaced: without a pin
            // there is no identity to hold the new initiation against.
            !pinned -> throw ProtocolException.InvalidMessage("Session without a pinned identity cannot be replaced")
            // Established before milestone 6, so its initiation is unknown.
            // A version 2 message never belongs to it: it is a new initiation.
            currentInitiation == null -> acceptSession(identity, sender, message, replaced = null)
            // Simultaneous initiation: the smaller ID wins on both sides.
            current.awaitingReply && initiation > currentInitiation -> {
                rejectLosingInitiation(identity, sender, message, initiation)
                return Received.CollisionLost
            }
            else -> acceptSession(identity, sender, message, replaced = current)
        }
        // Reached unpinned only by acceptance: the transcript authenticated
        // the sender address and the identity key.
        if (!pinned) pinRemoteIdentity(sender, message.identityKey)
        return Received.Plaintext(plaintext)
    }

    /**
     * Pins a session created before identity pinning (milestone 5) from a
     * version 1 repetition that just decrypted on it. Only the identity key
     * the session itself was established with as remote may be pinned, and
     * only if it is the message's: never the local identity, never a guess
     * (S1, finding F9). Otherwise the session stays unpinned.
     */
    private suspend fun ClientStorage.pinLegacySession(
        sender: DeviceAddress,
        session: SecureSession,
        message: PreKeyMessage,
        identity: LocalIdentity,
    ) {
        val remoteIdentityKey = protocol.sessionRemoteIdentityKey(session, identity.publicKey) ?: return
        if (remoteIdentityKey.contentEquals(identity.publicKey) || !remoteIdentityKey.contentEquals(message.identityKey)) return
        pinRemoteIdentity(sender, remoteIdentityKey)
    }

    private suspend fun ClientStorage.decryptOn(session: SecureSession, message: CiphertextMessage, identity: LocalIdentity): ByteArray {
        val result = protocol.decrypt(session, message, identity.publicKey)
        sessions.store(result.updatedSession)
        return result.plaintext
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
        // The session and the pin are stored under remote, so the bundle must
        // be for it.
        if (bundle.address != remote) throw ProtocolException.InvalidPreKeyBundle("Prekey bundle is for another device")
        if (bundle.identityKey.size != PublicIdentityKey.SIZE) throw ProtocolException.InvalidPreKeyBundle("Identity key has an invalid size")
        val pinned = checkRemoteIdentity(remote, bundle.identityKey)
        // Verifies the bundle (key sizes, signed prekey signature) first, so an
        // invalid bundle is never pinned. The caller stores the session in the
        // same transaction.
        val session = protocol.initiateSession(requireIdentity(), localAddress, bundle)
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
        return protocol.acceptSession(identity, localAddress, sender, signedPreKey, oneTimePreKey, message)
    }

    /** Result of a decrypt transaction. A collision is reported after the commit. */
    private sealed interface Received {
        class Plaintext(val plaintext: ByteArray) : Received

        data object CollisionLost : Received
    }

    /** What [finalizeReceived] found: finalized by this call, or before with that outcome. */
    private enum class Finalized { NOW, BEFORE_COMMITTED, BEFORE_DISCARDED }

    /** What a received reliability frame did. Acknowledgements are sent after the commit. */
    private sealed interface Processed {
        /** New or still pending: delivered to the application, not acknowledged. */
        class Delivered(val message: ReceivedMessage) : Processed

        class AlreadyCommitted(val id: LogicalMessageId) : Processed

        class AlreadyDiscarded(val id: LogicalMessageId) : Processed

        class Acknowledged(val id: LogicalMessageId, val cleared: Boolean) : Processed
    }

    private companion object {
        /** Version of the envelope metadata, see [EncryptedEnvelope.protocolVersion]. */
        const val ENVELOPE_VERSION = 1

        fun newEnvelopeId() = MessageId(Uuid.random().toString())

        /** Recovery rejections after which the pending key may be registered already. */
        private val RESOLVABLE_RECOVERY_FAILURES = setOf(
            SecureMessageTransportException.RecoveryFailure.CONFLICT,
            SecureMessageTransportException.RecoveryFailure.EXPIRED,
            SecureMessageTransportException.RecoveryFailure.REPLAY,
        )

        /** Recovery key revocation rejections after which another device may have revoked the key already. */
        /** A completion that lost to an identical one that committed first. */
        private val RESET_RACE_FAILURES = setOf(
            SecureMessageTransportException.RecoveryKeyResetFailure.CONFLICT,
            SecureMessageTransportException.RecoveryKeyResetFailure.NOT_PENDING,
        )

        private val REVOCATION_RACE_FAILURES = setOf(
            SecureMessageTransportException.RecoveryKeyTransitionFailure.CONFLICT,
            SecureMessageTransportException.RecoveryKeyTransitionFailure.NOT_CONFIGURED,
        )

        /** Last-device recovery rejections after which the pending key may be registered already. */
        private val RESOLVABLE_LAST_DEVICE_RECOVERY_FAILURES = setOf(
            SecureMessageTransportException.LastDeviceRecoveryFailure.CONFLICT,
            SecureMessageTransportException.LastDeviceRecoveryFailure.EXPIRED,
            SecureMessageTransportException.LastDeviceRecoveryFailure.CHALLENGE_INVALID,
        )

        /** Rotation rejections after which the pending key may be registered already. */
        private val RESOLVABLE_ROTATION_FAILURES = setOf(
            SecureMessageTransportException.RotationFailure.CONFLICT,
            SecureMessageTransportException.RotationFailure.EXPIRED,
            SecureMessageTransportException.RotationFailure.REPLAY,
        )
    }
}

/** The application body of a pending inbound frame. The frame is authenticated with its row key. */
private fun PendingInboundMessage.body(): ByteArray {
    val payload = try {
        SecurePayloadCodec.decode(frame)
    } finally {
        frame.fill(0)
    }
    if (payload !is SecurePayload.ApplicationMessage || payload.id != id) {
        throw SecureMessageClientException.InconsistentStorage("Pending received message $id does not hold its frame")
    }
    return payload.body
}

private fun PendingInboundMessage.toReceivedMessage() = ReceivedMessage(sender, id, sequence, receivedAt, body())

/** Compares without an early exit on the first differing byte. The length is not secret. */
private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var difference = 0
    for (i in a.indices) difference = difference or (a[i].toInt() xor b[i].toInt())
    return difference == 0
}
