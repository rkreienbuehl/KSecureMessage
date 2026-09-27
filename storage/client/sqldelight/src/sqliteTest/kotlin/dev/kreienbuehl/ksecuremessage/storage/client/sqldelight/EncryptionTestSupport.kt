package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.client.PendingReceivedPage
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.ReceivedMessage
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceAuthenticationRegistrationStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.encryption.ClientRecordCipher
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationPhase
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationStatus
import kotlin.coroutines.cancellation.CancellationException
import kotlin.test.assertIs
import kotlin.test.fail
import kotlin.time.Clock
import kotlin.time.Instant

/** Relay with bundles set directly; envelopes wait per recipient. */
class TestRelay : SecureMessageTransport {
    val bundles = mutableMapOf<DeviceAddress, PreKeyBundle>()
    private val mailboxes = mutableMapOf<DeviceAddress, MutableList<EncryptedEnvelope>>()

    suspend fun publish(client: SecureMessageClient) {
        bundles[client.localAddress] = bundleOf(client)
    }

    suspend fun bundleOf(client: SecureMessageClient): PreKeyBundle =
        client.currentPreKeyBundle().copy(oneTimePreKey = client.publicOneTimePreKeys().first())

    override suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner) =
        error("Tests set bundles directly")

    override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) = error("Tests set bundles directly")

    override suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization) = error("Tests set bundles directly")

    override suspend fun registrationStatus(address: DeviceAddress, signer: ServerRequestSigner): DeviceAuthenticationRegistrationStatus = error("Tests set bundles directly")

    override suspend fun registerLastDeviceRecoveryKey(address: DeviceAddress, registration: LastDeviceRecoveryKeyRegistration, signer: ServerRequestSigner) =
        error("not used")

    override suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge = error("not used")

    override suspend fun lastDeviceRecoveryKeyStatus(
        address: DeviceAddress,
        signer: ServerRequestSigner,
    ): LastDeviceRecoveryKeyStatus = error("not used")

    override suspend fun rotateLastDeviceRecoveryKey(
        authorization: RecoveryKeyRotationAuthorization,
        signer: ServerRequestSigner,
    ) = error("not used")

    override suspend fun revokeLastDeviceRecoveryKey(
        authorization: RecoveryKeyRevocationAuthorization,
        signer: ServerRequestSigner,
    ) = error("not used")

    override suspend fun requestLastDeviceRecoveryKeyReset(
        address: DeviceAddress,
        signer: ServerRequestSigner,
    ): dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus.Pending = error("not used")

    override suspend fun lastDeviceRecoveryKeyResetStatus(
        address: DeviceAddress,
        signer: ServerRequestSigner,
    ): dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus = error("not used")

    override suspend fun completeLastDeviceRecoveryKeyReset(
        authorization: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization,
        signer: ServerRequestSigner,
    ) = error("not used")

    override suspend fun cancelLastDeviceRecoveryKeyReset(
        address: DeviceAddress,
        resetId: dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId,
        signer: ServerRequestSigner,
    ) = error("not used")

    override suspend fun lastDeviceRecoveryKeyResetStatusByRecoveryKey(
        query: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQuery,
    ): dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus = error("not used")

    override suspend fun cancelLastDeviceRecoveryKeyResetByRecoveryKey(
        authorization: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization,
    ) = error("not used")

    override suspend fun recoverLastDevice(authorization: LastDeviceRecoveryAuthorization) = error("not used")

    override suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization) =
        error("Tests set bundles directly")

    override suspend fun fetchPreKeyBundle(address: DeviceAddress) = bundles.getValue(address)

    override suspend fun send(envelope: EncryptedEnvelope) {
        mailboxes.getOrPut(envelope.recipient) { mutableListOf() }.add(envelope)
    }

    override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner) = receive(address)

    fun receive(address: DeviceAddress) = mailboxes.remove(address)?.toList().orEmpty()

    fun waiting(address: DeviceAddress): Int = mailboxes[address]?.size ?: 0
}

/** Decrypts [envelope], commits the delivered message (which sends its acknowledgement) and returns it. */
suspend fun SecureMessageClient.accept(envelope: EncryptedEnvelope): ReceivedMessage =
    assertIs<ReceiveResult.Delivery>(decrypt(envelope)).message.also { commitReceivedMessage(it) }

/** Decrypts every envelope in order and commits each delivered message, as an application would. */
suspend fun SecureMessageClient.acceptAll(envelopes: List<EncryptedEnvelope>) {
    for (envelope in envelopes) {
        val result = decrypt(envelope)
        if (result is ReceiveResult.Delivery) commitReceivedMessage(result.message)
    }
}

fun ReceivedMessage.text(): String = plaintext.decodeToString()

class TestClock(var now: Instant) : Clock {
    override fun now(): Instant = now
}

/** Record cipher whose seal calls fail on demand, for atomicity tests. */
class FailingRecords(private val delegate: ClientRecordCipher) : ClientRecordCipher by delegate {
    /**
     * Names of the seal functions that fail: identity, deviceAuthenticationKey,
     * deviceAuthenticationRecoveryKey, deviceAuthenticationRotationKey,
     * deviceAuthenticationLastDeviceRecoveryKey, signedPreKey, oneTimePreKey, session, pending, pendingInbound, processedDigest.
     */
    var failing: Set<String> = emptySet()

    /** Fails the seal call with this number (1-based, all record kinds counted), if set. */
    var failAtSeal: Int? = null
    /** Cancels the coroutine at the seal call with this number (1-based), if set. */
    var cancelAtSeal: Int? = null

    var seals = 0
        private set

    private fun check(kind: String) {
        seals++
        if (seals == cancelAtSeal) throw CancellationException("Injected cancellation at $kind encryption")
        if (kind in failing || seals == failAtSeal) throw IllegalStateException("Injected $kind encryption failure")
    }

    override suspend fun sealIdentity(identity: LocalIdentity): ByteArray = check("identity").let { delegate.sealIdentity(identity) }
    override suspend fun sealDeviceAuthenticationKey(keyPair: DeviceAuthenticationKeyPair): ByteArray =
        check("deviceAuthenticationKey").let { delegate.sealDeviceAuthenticationKey(keyPair) }
    override suspend fun sealDeviceAuthenticationRecoveryKey(keyPair: DeviceAuthenticationKeyPair): ByteArray =
        check("deviceAuthenticationRecoveryKey").let { delegate.sealDeviceAuthenticationRecoveryKey(keyPair) }
    override suspend fun sealDeviceAuthenticationRotationKey(keyPair: DeviceAuthenticationKeyPair): ByteArray =
        check("deviceAuthenticationRotationKey").let { delegate.sealDeviceAuthenticationRotationKey(keyPair) }
    override suspend fun sealDeviceAuthenticationLastDeviceRecoveryKey(keyPair: DeviceAuthenticationKeyPair): ByteArray =
        check("deviceAuthenticationLastDeviceRecoveryKey").let { delegate.sealDeviceAuthenticationLastDeviceRecoveryKey(keyPair) }
    override suspend fun sealSignedPreKey(preKey: SignedPreKeyPair): ByteArray =
        check("signedPreKey").let { delegate.sealSignedPreKey(preKey) }
    override suspend fun sealOneTimePreKey(preKey: OneTimePreKeyPair): ByteArray =
        check("oneTimePreKey").let { delegate.sealOneTimePreKey(preKey) }
    override suspend fun sealSession(session: SecureSession): ByteArray = check("session").let { delegate.sealSession(session) }
    override suspend fun sealPendingFrame(recipient: DeviceAddress, id: LogicalMessageId, frame: ByteArray): ByteArray =
        check("pending").let { delegate.sealPendingFrame(recipient, id, frame) }
    override suspend fun sealPendingInboundFrame(sender: DeviceAddress, id: LogicalMessageId, frame: ByteArray): ByteArray =
        check("pendingInbound").let { delegate.sealPendingInboundFrame(sender, id, frame) }
    override suspend fun sealProcessedDigest(sender: DeviceAddress, id: LogicalMessageId, digest: ByteArray): ByteArray =
        check("processedDigest").let { delegate.sealProcessedDigest(sender, id, digest) }

    companion object {
        /** A factory for [SqlDelightClientStorage.open] that records the cipher it created. */
        fun factory(created: MutableList<FailingRecords>, failAtSeal: Int? = null): RecordCipherFactory =
            { key, retained -> FailingRecords(ClientRecordCipher(key, *retained.toTypedArray())).also { it.failAtSeal = failAtSeal; created += it } }
    }
}

/**
 * Calls [resume] until it reports STABLE, at most [maxSteps] times, and
 * returns the STABLE status. A rotation that stops making progress fails the
 * test after the bound instead of hanging it. The failure names the last
 * status (phase, key IDs, remaining records), never key material.
 */
suspend fun completeStorageKeyRotation(
    maxSteps: Int = 100,
    resume: suspend () -> StorageKeyRotationStatus,
): StorageKeyRotationStatus {
    require(maxSteps > 0) { "maxSteps must be positive" }
    lateinit var last: StorageKeyRotationStatus
    repeat(maxSteps) {
        last = resume()
        if (last.phase == StorageKeyRotationPhase.STABLE) return last
    }
    fail(
        "Storage key rotation did not converge after $maxSteps resume steps; last status: " +
            "phase=${last.phase}, currentKeyId=${last.currentKeyId.value}, nextKeyId=${last.nextKeyId?.value}, " +
            "retiringKeyId=${last.retiringKeyId?.value}, remainingRecords=${last.remainingRecords}",
    )
}

/** Every pending received message, page by page. */
suspend fun SecureMessageClient.allPendingReceivedMessages(): List<ReceivedMessage> {
    val all = mutableListOf<ReceivedMessage>()
    var after: Long? = null
    do {
        val page = pendingReceivedMessages(after, PendingReceivedPage.MAX_SIZE)
        all += page.messages
        after = page.nextAfterSequence
    } while (after != null)
    return all
}
