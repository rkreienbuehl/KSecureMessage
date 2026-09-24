package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.inmemory.InMemoryServerStorage
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import java.util.Collections
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PreKeyServiceTest {
    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))
    private val storage = InMemoryServerStorage()
    private val service = PreKeyService(storage.preKeys)

    private fun key(seed: Int, size: Int = PreKeyFormat.PUBLIC_KEY_SIZE) = ByteArray(size) { (seed + it).toByte() }

    private fun publication(oneTimePreKeys: IntRange = 0..9) = PreKeyPublication(
        address = bob,
        identityKey = key(1),
        signedPreKey = PublicSignedPreKey(SignedPreKeyId(0), key(2), key(3, PreKeyFormat.SIGNATURE_SIZE)),
        oneTimePreKeys = oneTimePreKeys.map { PublicOneTimePreKey(OneTimePreKeyId(it), key(100 + it)) },
    )

    @Test
    fun malformedPublicationsAreRejectedWithoutChanges() = runTest {
        val valid = publication()
        val invalid = listOf(
            valid.copy(identityKey = key(1, 32)),
            valid.copy(signedPreKey = valid.signedPreKey.copy(publicKey = key(2, 65))),
            valid.copy(signedPreKey = valid.signedPreKey.copy(signature = ByteArray(0))),
            valid.copy(oneTimePreKeys = valid.oneTimePreKeys + PublicOneTimePreKey(OneTimePreKeyId(50), key(5, 63))),
            valid.copy(oneTimePreKeys = valid.oneTimePreKeys + valid.oneTimePreKeys.first()),
            publication(0..PreKeyFormat.MAX_ONE_TIME_PRE_KEYS_PER_PUBLICATION),
        )
        for (publication in invalid) {
            assertFailsWith<PreKeyPublicationException.InvalidPublication> { service.publish(publication) }
        }
        assertNull(service.fetchPreKeyBundle(bob))

        service.publish(valid)
        for (publication in invalid) {
            assertFailsWith<PreKeyPublicationException.InvalidPublication> { service.publish(publication) }
        }
        assertEquals(10, storage.preKeys.oneTimePreKeyCount(bob))
    }

    @Test
    fun bundlePreservesPublishedBytes() = runTest {
        val published = publication()
        service.publish(published)
        val bundle = assertNotNull(service.fetchPreKeyBundle(bob))
        assertContentEquals(published.identityKey, bundle.identityKey)
        assertContentEquals(published.signedPreKey.signature, bundle.signedPreKey.signature)
        assertContentEquals(published.oneTimePreKeys.first().publicKey, bundle.oneTimePreKey?.publicKey)
    }

    @Test
    fun hundredParallelConsumersGetDistinctOneTimePreKeys() = runTest {
        service.publish(publication(0..99))
        val ids = fetchInParallel(100)
        assertEquals(100, ids.filterNotNull().toSet().size)
        assertTrue(ids.none { it == null })
        assertEquals(0, storage.preKeys.oneTimePreKeyCount(bob))
    }

    @Test
    fun consumersBeyondTheInventoryGetNoOneTimePreKey() = runTest {
        service.publish(publication(0..9))
        val ids = fetchInParallel(20)
        assertEquals((0..9).toList(), ids.filterNotNull().sorted())
        assertEquals(10, ids.count { it == null })
    }

    /**
     * Runs [consumers] fetches on 16 real threads. All wait for one start
     * signal; the thread set shows the calls did run in parallel.
     */
    private suspend fun fetchInParallel(consumers: Int): List<Int?> {
        val threads = Collections.synchronizedSet(mutableSetOf<String>())
        val ids = Executors.newFixedThreadPool(16).asCoroutineDispatcher().use { dispatcher ->
            withContext(dispatcher) {
                val start = CompletableDeferred<Unit>()
                val fetches = List(consumers) {
                    async {
                        start.await()
                        threads += Thread.currentThread().name
                        assertNotNull(service.fetchPreKeyBundle(bob)).oneTimePreKey?.id?.value
                    }
                }
                start.complete(Unit)
                fetches.awaitAll()
            }
        }
        assertTrue(threads.size > 1, "fetches ran on more than one thread")
        return ids
    }
}
