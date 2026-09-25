package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
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

    override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) {
        checkNoTransaction()
        fake.publishPreKeys(publication, signer)
    }

    override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle {
        checkNoTransaction()
        return fake.fetchPreKeyBundle(address)
    }

    override suspend fun send(envelope: EncryptedEnvelope) {
        checkNoTransaction()
        if (envelope.sender in cancellingSenders) throw CancellationException("Injected cancellation")
        if (envelope.sender in failingSenders) throw SecureMessageTransportException.UnexpectedResponse(503)
        fake.send(envelope)
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

    suspend fun pending(to: ReliableDevice): List<LogicalMessageId> = client.pendingMessages(to.address).map { it.id }

    suspend fun isProcessed(from: ReliableDevice, id: LogicalMessageId) = storage.processedInbound.isProcessed(from.address, id)

    /** Sends a hand-made reliability frame through the raw session layer. */
    suspend fun sendFrame(to: ReliableDevice, payload: SecurePayload) =
        client.sendRaw(to.address, SecurePayloadCodec.encode(payload))

    suspend fun initiationOf(envelope: EncryptedEnvelope): SessionInitiationId = SessionInitiationId.of(
        assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(envelope.payload)),
        assertNotNull(storage.identity.identity()).publicKey,
    )
}

internal fun ReceiveResult.text(): String = assertIs<ReceiveResult.Message>(this).plaintext.decodeToString()
