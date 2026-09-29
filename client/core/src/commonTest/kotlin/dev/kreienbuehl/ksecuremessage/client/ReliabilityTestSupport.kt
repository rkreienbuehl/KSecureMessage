package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceAuthenticationRegistrationStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.SecurePayload
import dev.kreienbuehl.ksecuremessage.protocol.SecurePayloadCodec
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlin.coroutines.cancellation.CancellationException
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.time.Clock

/**
 * [FakeNetwork] that can refuse sends of chosen devices and checks that no
 * device calls it from inside a storage transaction.
 */
internal class FlakyNetwork(val fake: FakeNetwork = FakeNetwork()) : SecureMessageTransport {
    /** Senders whose envelopes are refused with a transport exception. */
    val failingSenders = mutableSetOf<DeviceAddress>()

    /** Senders whose sends are cancelled. */
    val cancellingSenders = mutableSetOf<DeviceAddress>()

    private val watched = mutableListOf<TransactionTrackingStorage>()

    /** Every envelope that was handed over successfully, in order. */
    val sent = mutableListOf<EncryptedEnvelope>()

    fun watch(storage: TransactionTrackingStorage) {
        watched += storage
    }

    private fun checkNoTransaction() {
        for (storage in watched) assertEquals(0, storage.depth, "network call inside a storage transaction")
    }

    override suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner) {
        checkNoTransaction()
        fake.registerDevice(registration, signer)
    }

    override suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization) {
        checkNoTransaction()
        fake.recoverDevice(authorization)
    }

    override suspend fun registrationStatus(address: DeviceAddress, signer: ServerRequestSigner): DeviceAuthenticationRegistrationStatus {
        checkNoTransaction()
        return fake.registrationStatus(address, signer)
    }

    override suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization) {
        checkNoTransaction()
        fake.rotateDeviceAuthenticationKey(authorization)
    }

    override suspend fun registerLastDeviceRecoveryKey(
        address: DeviceAddress,
        registration: LastDeviceRecoveryKeyRegistration,
        signer: ServerRequestSigner,
    ) {
        checkNoTransaction()
        fake.registerLastDeviceRecoveryKey(address, registration, signer)
    }

    override suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge {
        checkNoTransaction()
        return fake.lastDeviceRecoveryChallenge(target)
    }

    override suspend fun recoverLastDevice(authorization: LastDeviceRecoveryAuthorization) {
        checkNoTransaction()
        fake.recoverLastDevice(authorization)
    }

    override suspend fun lastDeviceRecoveryKeyStatus(
        address: DeviceAddress,
        signer: ServerRequestSigner,
    ): dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus {
        checkNoTransaction()
        return fake.lastDeviceRecoveryKeyStatus(address, signer)
    }

    override suspend fun rotateLastDeviceRecoveryKey(
        authorization: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization,
        signer: ServerRequestSigner,
    ) {
        checkNoTransaction()
        fake.rotateLastDeviceRecoveryKey(authorization, signer)
    }

    override suspend fun revokeLastDeviceRecoveryKey(
        authorization: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization,
        signer: ServerRequestSigner,
    ) {
        checkNoTransaction()
        fake.revokeLastDeviceRecoveryKey(authorization, signer)
    }

    override suspend fun requestLastDeviceRecoveryKeyReset(address: DeviceAddress, signer: ServerRequestSigner) =
        fake.requestLastDeviceRecoveryKeyReset(address, signer)

    override suspend fun lastDeviceRecoveryKeyResetStatus(address: DeviceAddress, signer: ServerRequestSigner) =
        fake.lastDeviceRecoveryKeyResetStatus(address, signer)

    override suspend fun completeLastDeviceRecoveryKeyReset(
        authorization: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization,
        signer: ServerRequestSigner,
    ) = fake.completeLastDeviceRecoveryKeyReset(authorization, signer)

    override suspend fun cancelLastDeviceRecoveryKeyReset(
        address: DeviceAddress,
        resetId: dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId,
        signer: ServerRequestSigner,
    ) = fake.cancelLastDeviceRecoveryKeyReset(address, resetId, signer)

    override suspend fun lastDeviceRecoveryKeyResetStatusByRecoveryKey(query: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQuery) =
        fake.lastDeviceRecoveryKeyResetStatusByRecoveryKey(query)

    override suspend fun cancelLastDeviceRecoveryKeyResetByRecoveryKey(
        authorization: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization,
    ) = fake.cancelLastDeviceRecoveryKeyResetByRecoveryKey(authorization)

    override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) {
        checkNoTransaction()
        fake.publishPreKeys(publication, signer)
    }

    /** How many prekey bundles were fetched. */
    var bundleFetches = 0
        private set

    override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle {
        checkNoTransaction()
        bundleFetches++
        return fake.fetchPreKeyBundle(address)
    }

    override suspend fun send(envelope: EncryptedEnvelope, signer: ServerRequestSigner) {
        checkNoTransaction()
        if (envelope.sender in cancellingSenders) throw CancellationException("Injected cancellation")
        if (envelope.sender in failingSenders) throw SecureMessageTransportException.UnexpectedResponse(503)
        fake.send(envelope, signer)
        sent += envelope
    }

    override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope> = receive(address)

    fun receive(address: DeviceAddress): List<EncryptedEnvelope> {
        checkNoTransaction()
        return fake.receive(address)
    }
}

/** One device using the reliability API, on in-memory storage with failure injection. */
internal class ReliableDevice(
    val address: DeviceAddress,
    val network: FlakyNetwork,
    val engine: ProtocolEngine = KodiumProtocolEngine(),
    val configuration: PreKeyConfiguration = PreKeyConfiguration(oneTimePreKeyTarget = 4),
    val clock: Clock = Clock.System,
) {
    val storage = InMemoryClientStorage()
    val failing = FailingClientStorage(storage)
    private val tracking = TransactionTrackingStorage(failing).also { network.watch(it) }
    var client = newClient()
        private set

    private fun newClient() = SecureMessageClient(address, tracking, engine, network, configuration, clock)

    /** A new client instance on the same storage, like an application restart. */
    fun restart() {
        client = newClient()
    }

    suspend fun start(withOneTimePreKey: Boolean = true) = also {
        client.initialize()
        network.fake.publish(client, withOneTimePreKey)
    }

    suspend fun send(to: ReliableDevice, text: String): SentMessage = client.send(to.address, text.encodeToByteArray())

    suspend fun inbox(): List<EncryptedEnvelope> = network.receive(address)

    suspend fun receive(envelope: EncryptedEnvelope): ReceiveResult = client.decrypt(envelope)

    /** Decrypts the single envelope waiting for this device. */
    suspend fun receiveOne(): ReceiveResult = receive(inbox().single())

    suspend fun pending(to: ReliableDevice): List<LogicalMessageId> = client.allPendingMessages(to.address).map { it.id }

    suspend fun isProcessed(from: ReliableDevice, id: LogicalMessageId) = storage.processedInbound.isProcessed(from.address, id)

    /** Whether message [id] from [from] waits for the application's commit. */
    suspend fun isPendingInbound(from: ReliableDevice, id: LogicalMessageId) = storage.pendingInbound.contains(from.address, id)

    /** Commits the message [result] delivered. */
    suspend fun commit(result: ReceiveResult): CommitResult = client.commitReceivedMessage(result.delivery())

    /** Decrypts the single waiting envelope, commits the delivered message and returns its text. */
    suspend fun acceptOne(): String {
        val result = receiveOne()
        return result.text().also { commit(result) }
    }

    /** Sends a hand-made reliability frame through the raw session layer. */
    suspend fun sendFrame(to: ReliableDevice, payload: SecurePayload) =
        client.sendRaw(to.address, SecurePayloadCodec.encode(payload))

    suspend fun initiationOf(envelope: EncryptedEnvelope): SessionInitiationId = SessionInitiationId.v2Of(
        assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(envelope.payload)),
        envelope.sender,
        envelope.recipient,
        assertNotNull(storage.identity.identity()).publicKey,
    )
}

/** Decrypts [envelope], commits the delivered message and returns its plaintext. */
internal suspend fun SecureMessageClient.accept(envelope: EncryptedEnvelope): ByteArray {
    val message = decrypt(envelope).delivery()
    commitReceivedMessage(message)
    return message.plaintext
}

internal fun ReceiveResult.delivery(): ReceivedMessage = assertIs<ReceiveResult.Delivery>(this).message

internal fun ReceiveResult.text(): String = delivery().plaintext.decodeToString()

/** Every pending received message, page by page (test helper; applications should page themselves). */
internal suspend fun SecureMessageClient.allPendingReceivedMessages(sender: DeviceAddress? = null): List<ReceivedMessage> {
    val all = mutableListOf<ReceivedMessage>()
    var after: Long? = null
    do {
        val page = pendingReceivedMessages(after, PendingReceivedMessagePage.MAX_SIZE, sender)
        all += page.messages
        after = page.nextAfterSequence
    } while (after != null)
    return all
}

/** Every pending sent message, page by page (test helper; applications should page themselves). */
internal suspend fun SecureMessageClient.allPendingMessages(recipient: DeviceAddress? = null): List<PendingMessage> {
    val all = mutableListOf<PendingMessage>()
    var after: Long? = null
    do {
        val page = pendingMessages(after, PendingMessagePage.MAX_SIZE, recipient)
        all += page.messages
        after = page.nextAfterSequence
    } while (after != null)
    return all
}
