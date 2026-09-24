package dev.kreienbuehl.ksecuremessage.storage.testing

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Behavior every server [MailboxRepository] must have
 * (docs/transport-ordering.md): per (sender, recipient) pair, envelopes are
 * drained in enqueue order, each exactly once. Order across senders or across
 * recipients is deliberately not checked; it is not part of the contract.
 */
abstract class MailboxRepositoryContractTest {
    /** Returns a new, empty repository. */
    protected abstract suspend fun newRepository(): MailboxRepository

    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))
    private val carol = DeviceAddress(UserId("carol"), DeviceId("tablet"))

    private fun sender(index: Int) = DeviceAddress(UserId("sender-$index"), DeviceId("device"))

    /** Envelope number [sequence] of [sender] for [recipient]; the ID encodes all three. */
    private fun envelope(sender: DeviceAddress, recipient: DeviceAddress, sequence: Int) = EncryptedEnvelope(
        id = MessageId("${sender.userId.value}>${recipient.userId.value}#$sequence"),
        sender = sender,
        recipient = recipient,
        payload = byteArrayOf(sequence.toByte(), (sequence shr 8).toByte()),
    )

    private fun EncryptedEnvelope.sequence() = id.value.substringAfter('#').toInt()

    /** Fails unless each sender's envelopes in [drained] are exactly 0 until [perSender] - 1, in order. */
    private fun assertPerSenderOrder(drained: List<EncryptedEnvelope>, senders: List<DeviceAddress>, perSender: Int) {
        assertEquals(senders.size * perSender, drained.size, "every envelope exactly once")
        val bySender = drained.groupBy { it.sender }
        for (sender in senders) {
            assertEquals((0 until perSender).toList(), bySender[sender].orEmpty().map { it.sequence() }, "order of $sender")
        }
    }

    @Test
    fun emptyMailboxDrainsNothing() = runTest {
        val repository = newRepository()
        assertEquals(emptyList(), repository.drain(bob))
        repository.enqueue(envelope(sender(0), carol, 0))
        assertEquals(emptyList(), repository.drain(bob))
    }

    @Test
    fun oneSenderToOneRecipientKeepsEnqueueOrder() = runTest {
        val repository = newRepository()
        val sent = List(50) { envelope(sender(0), bob, it) }
        for (envelope in sent) repository.enqueue(envelope)

        val drained = repository.drain(bob)
        assertEquals(sent.map { it.id }, drained.map { it.id })
        assertContentEquals(sent.last().payload, drained.last().payload)
        assertEquals(emptyList(), repository.drain(bob), "drain removes what it returns")
    }

    @Test
    fun orderSurvivesSeveralDrains() = runTest {
        val repository = newRepository()
        repository.enqueue(envelope(sender(0), bob, 0))
        repository.enqueue(envelope(sender(0), bob, 1))
        val first = repository.drain(bob)
        repository.enqueue(envelope(sender(0), bob, 2))
        repository.enqueue(envelope(sender(0), bob, 3))
        assertPerSenderOrder(first + repository.drain(bob), listOf(sender(0)), 4)
    }

    @Test
    fun severalSendersToOneRecipientKeepEachSendersOrder() = runTest {
        val repository = newRepository()
        val senders = List(3) { sender(it) }
        repeat(20) { sequence -> for (sender in senders) repository.enqueue(envelope(sender, bob, sequence)) }
        assertPerSenderOrder(repository.drain(bob), senders, 20)
    }

    @Test
    fun oneSenderToSeveralRecipientsKeepsEachStreamsOrder() = runTest {
        val repository = newRepository()
        repeat(20) { sequence ->
            repository.enqueue(envelope(sender(0), bob, sequence))
            repository.enqueue(envelope(sender(0), carol, sequence))
        }
        assertPerSenderOrder(repository.drain(bob), listOf(sender(0)), 20)
        assertPerSenderOrder(repository.drain(carol), listOf(sender(0)), 20)
    }

    /**
     * Many producers on [Dispatchers.Default] (a thread pool on JVM and
     * native), each sending its own stream in order, to two recipients.
     */
    @Test
    fun concurrentProducersLoseNothingAndKeepEachStreamsOrder() = runTest {
        val repository = newRepository()
        val senders = List(PRODUCERS) { sender(it) }
        withContext(Dispatchers.Default) {
            val start = CompletableDeferred<Unit>()
            val producers = senders.map { sender ->
                async {
                    start.await()
                    repeat(PER_PRODUCER) { sequence ->
                        repository.enqueue(envelope(sender, bob, sequence))
                        repository.enqueue(envelope(sender, carol, sequence))
                    }
                }
            }
            start.complete(Unit)
            producers.awaitAll()
        }
        assertPerSenderOrder(repository.drain(bob), senders, PER_PRODUCER)
        assertPerSenderOrder(repository.drain(carol), senders, PER_PRODUCER)
    }

    /** Draining while producers run: every envelope comes out in exactly one drain, in order. */
    @Test
    fun drainsDuringConcurrentEnqueueSplitTheStreamsWithoutLossOrReordering() = runTest {
        val repository = newRepository()
        val senders = List(PRODUCERS) { sender(it) }
        val drained = withContext(Dispatchers.Default) {
            val start = CompletableDeferred<Unit>()
            val producers = senders.map { sender ->
                launch {
                    start.await()
                    repeat(PER_PRODUCER) { repository.enqueue(envelope(sender, bob, it)) }
                }
            }
            val consumer = async {
                val batches = mutableListOf<EncryptedEnvelope>()
                start.await()
                while (producers.any { it.isActive }) {
                    batches += repository.drain(bob)
                    yield()
                }
                batches
            }
            start.complete(Unit)
            consumer.await() + repository.drain(bob)
        }
        assertTrue(drained.isNotEmpty())
        assertPerSenderOrder(drained, senders, PER_PRODUCER)
    }

    private companion object {
        const val PRODUCERS = 16
        const val PER_PRODUCER = 200
    }
}
