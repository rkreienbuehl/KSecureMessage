package dev.kreienbuehl.ksecuremessage.storage.testing

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Behavior every server [PreKeyRepository] must have. Subclass it in an
 * adapter's tests. Key material is fake: the repository never interprets it.
 */
abstract class PreKeyRepositoryContractTest {
    /** Returns a new, empty repository. */
    protected abstract suspend fun newRepository(): PreKeyRepository

    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))
    private val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))

    private fun key(seed: Int) = ByteArray(64) { (seed + it).toByte() }

    private fun signedPreKey(id: Int, seed: Int = id) =
        PublicSignedPreKey(SignedPreKeyId(id), key(1000 + seed), key(2000 + seed))

    private fun oneTimePreKey(id: Int, seed: Int = id) = PublicOneTimePreKey(OneTimePreKeyId(id), key(3000 + seed))

    private fun publication(
        address: DeviceAddress = bob,
        identitySeed: Int = 1,
        signedPreKey: PublicSignedPreKey = signedPreKey(0),
        oneTimePreKeys: List<PublicOneTimePreKey> = emptyList(),
    ) = PreKeyPublication(address, key(identitySeed), signedPreKey, oneTimePreKeys)

    private fun oneTimePreKeys(ids: IntRange) = ids.map { oneTimePreKey(it) }

    /** Fetches bundles until the inventory is empty; returns the handed-out one-time prekey IDs. */
    private suspend fun PreKeyRepository.drain(address: DeviceAddress): List<Int> {
        val ids = mutableListOf<Int>()
        while (true) ids += consumePreKeyBundle(address)?.oneTimePreKey?.id?.value ?: return ids
    }

    private fun assertBundle(expected: PreKeyPublication, oneTimePreKey: PublicOneTimePreKey?, actual: PreKeyBundle?) {
        val bundle = assertNotNull(actual)
        assertEquals(expected.address, bundle.address)
        assertContentEquals(expected.identityKey, bundle.identityKey)
        assertEquals(expected.signedPreKey.id, bundle.signedPreKey.id)
        assertContentEquals(expected.signedPreKey.publicKey, bundle.signedPreKey.publicKey)
        assertContentEquals(expected.signedPreKey.signature, bundle.signedPreKey.signature)
        assertEquals(oneTimePreKey?.id, bundle.oneTimePreKey?.id)
        assertContentEquals(oneTimePreKey?.publicKey, bundle.oneTimePreKey?.publicKey)
    }

    @Test
    fun firstPublicationIsServedWithTheLowestOneTimePreKey() = runTest {
        val repository = newRepository()
        val published = publication(oneTimePreKeys = listOf(oneTimePreKey(12), oneTimePreKey(10), oneTimePreKey(11)))
        repository.publish(published)
        assertEquals(3, repository.oneTimePreKeyCount(bob))

        assertBundle(published, oneTimePreKey(10), repository.consumePreKeyBundle(bob))
        assertEquals(2, repository.oneTimePreKeyCount(bob))
        assertEquals(listOf(11, 12), repository.drain(bob))
    }

    @Test
    fun identicalRetryIsIdempotent() = runTest {
        val repository = newRepository()
        val published = publication(oneTimePreKeys = oneTimePreKeys(10..12))
        repository.publish(published)
        repository.publish(published)
        repository.publish(published.copy(oneTimePreKeys = oneTimePreKeys(11..13)))

        assertEquals(4, repository.oneTimePreKeyCount(bob))
        assertEquals(listOf(10, 11, 12, 13), repository.drain(bob))
    }

    @Test
    fun exhaustedInventoryStillServesABundle() = runTest {
        val repository = newRepository()
        val published = publication(oneTimePreKeys = oneTimePreKeys(0..0))
        repository.publish(published)

        assertBundle(published, oneTimePreKey(0), repository.consumePreKeyBundle(bob))
        assertBundle(published, null, repository.consumePreKeyBundle(bob))
        assertBundle(published, null, repository.consumePreKeyBundle(bob))
        assertEquals(0, repository.oneTimePreKeyCount(bob))
    }

    @Test
    fun unknownDeviceHasNoBundle() = runTest {
        val repository = newRepository()
        assertNull(repository.consumePreKeyBundle(bob))
        assertEquals(0, repository.oneTimePreKeyCount(bob))
    }

    @Test
    fun consumedOneTimePreKeysAreNeverServedAgain() = runTest {
        val repository = newRepository()
        val published = publication(oneTimePreKeys = oneTimePreKeys(0..2))
        repository.publish(published)
        assertEquals(0, repository.consumePreKeyBundle(bob)?.oneTimePreKey?.id?.value)

        // The device still holds private #0 until a message uses it, so it uploads it again.
        repository.publish(published)
        assertEquals(2, repository.oneTimePreKeyCount(bob))
        assertEquals(listOf(1, 2), repository.drain(bob))

        // Skipped even with other bytes: the ID is spent.
        repository.publish(published.copy(oneTimePreKeys = listOf(oneTimePreKey(0, seed = 99))))
        assertEquals(0, repository.oneTimePreKeyCount(bob))
    }

    @Test
    fun signedPreKeyRotationReplacesTheCurrentOne() = runTest {
        val repository = newRepository()
        repository.publish(publication(signedPreKey = signedPreKey(5), oneTimePreKeys = oneTimePreKeys(0..1)))
        val rotated = publication(signedPreKey = signedPreKey(6))
        repository.publish(rotated)
        repository.publish(rotated)

        assertBundle(rotated, oneTimePreKey(0), repository.consumePreKeyBundle(bob))
    }

    @Test
    fun conflictingOrStaleSignedPreKeyIsRejected() = runTest {
        val repository = newRepository()
        val current = publication(signedPreKey = signedPreKey(5))
        repository.publish(current)

        assertFailsWith<PreKeyPublicationException.SignedPreKeyConflict> {
            repository.publish(publication(signedPreKey = signedPreKey(5, seed = 99), oneTimePreKeys = oneTimePreKeys(0..0)))
        }
        assertFailsWith<PreKeyPublicationException.SignedPreKeyConflict> {
            val signatureChanged = signedPreKey(5).copy(signature = key(77))
            repository.publish(publication(signedPreKey = signatureChanged))
        }
        assertFailsWith<PreKeyPublicationException.SignedPreKeyConflict> {
            repository.publish(publication(signedPreKey = signedPreKey(4), oneTimePreKeys = oneTimePreKeys(0..0)))
        }

        assertEquals(0, repository.oneTimePreKeyCount(bob))
        assertBundle(current, null, repository.consumePreKeyBundle(bob))
    }

    @Test
    fun differentIdentityKeyIsRejectedWithoutChanges() = runTest {
        val repository = newRepository()
        val original = publication(signedPreKey = signedPreKey(0), oneTimePreKeys = oneTimePreKeys(0..0))
        repository.publish(original)

        assertFailsWith<PreKeyPublicationException.IdentityKeyConflict> {
            repository.publish(publication(identitySeed = 2, signedPreKey = signedPreKey(1), oneTimePreKeys = oneTimePreKeys(1..3)))
        }

        assertEquals(1, repository.oneTimePreKeyCount(bob))
        assertBundle(original, oneTimePreKey(0), repository.consumePreKeyBundle(bob))
    }

    @Test
    fun conflictingOneTimePreKeyRollsBackTheWholePublication() = runTest {
        val repository = newRepository()
        val original = publication(signedPreKey = signedPreKey(0), oneTimePreKeys = oneTimePreKeys(40..42))
        repository.publish(original)

        assertFailsWith<PreKeyPublicationException.OneTimePreKeyConflict> {
            repository.publish(
                publication(
                    signedPreKey = signedPreKey(1),
                    oneTimePreKeys = listOf(oneTimePreKey(43), oneTimePreKey(42, seed = 99), oneTimePreKey(44)),
                ),
            )
        }

        assertEquals(3, repository.oneTimePreKeyCount(bob))
        assertBundle(original, oneTimePreKey(40), repository.consumePreKeyBundle(bob))
        assertEquals(listOf(41, 42), repository.drain(bob))
    }

    @Test
    fun repeatedIdWithinOnePublicationIsRejected() = runTest {
        val repository = newRepository()
        assertFailsWith<PreKeyPublicationException.InvalidPublication> {
            repository.publish(publication(oneTimePreKeys = listOf(oneTimePreKey(1), oneTimePreKey(1))))
        }
        assertFailsWith<PreKeyPublicationException.InvalidPublication> {
            repository.publish(publication(oneTimePreKeys = listOf(oneTimePreKey(1), oneTimePreKey(1, seed = 99))))
        }
        assertNull(repository.consumePreKeyBundle(bob))
    }

    @Test
    fun devicesAreIndependent() = runTest {
        val repository = newRepository()
        val laptop = publication(address = bob, identitySeed = 1, oneTimePreKeys = oneTimePreKeys(0..1))
        val phone = publication(
            address = bobPhone,
            identitySeed = 2,
            signedPreKey = signedPreKey(0, seed = 50),
            oneTimePreKeys = listOf(oneTimePreKey(0, seed = 50)),
        )
        repository.publish(laptop)
        repository.publish(phone)

        assertBundle(phone, oneTimePreKey(0, seed = 50), repository.consumePreKeyBundle(bobPhone))
        assertBundle(phone, null, repository.consumePreKeyBundle(bobPhone))
        assertEquals(2, repository.oneTimePreKeyCount(bob))
        assertBundle(laptop, oneTimePreKey(0), repository.consumePreKeyBundle(bob))
    }

    @Test
    fun storedBytesCannotBeChangedThroughAliases() = runTest {
        val repository = newRepository()
        val published = publication(oneTimePreKeys = oneTimePreKeys(0..1))
        val expected = publication(oneTimePreKeys = oneTimePreKeys(0..1))
        repository.publish(published)
        published.identityKey.fill(0)
        published.signedPreKey.publicKey.fill(0)
        published.oneTimePreKeys.forEach { it.publicKey.fill(0) }

        val first = assertNotNull(repository.consumePreKeyBundle(bob))
        assertBundle(expected, oneTimePreKey(0), first)
        first.identityKey.fill(0)
        first.signedPreKey.signature.fill(0)
        assertBundle(expected, oneTimePreKey(1), repository.consumePreKeyBundle(bob))
    }

    @Test
    fun concurrentFetchesNeverShareAOneTimePreKey() = runTest {
        val repository = newRepository()
        repository.publish(publication(oneTimePreKeys = oneTimePreKeys(0..99)))

        val ids = consumeConcurrently(repository, 100)

        assertEquals(100, ids.filterNotNull().toSet().size, "every consumer got a different one-time prekey")
        assertEquals((0..99).toSet(), ids.filterNotNull().toSet())
        assertEquals(0, repository.oneTimePreKeyCount(bob))
    }

    @Test
    fun concurrentFetchesBeyondTheInventoryGetNoOneTimePreKey() = runTest {
        val repository = newRepository()
        repository.publish(publication(oneTimePreKeys = oneTimePreKeys(0..9)))

        val ids = consumeConcurrently(repository, 20)

        assertEquals((0..9).toList(), ids.filterNotNull().sorted(), "no one-time prekey was handed out twice")
        assertEquals(10, ids.count { it == null })
        assertEquals(0, repository.oneTimePreKeyCount(bob))
    }

    /**
     * Starts [consumers] fetches on [Dispatchers.Default] (a thread pool on
     * JVM and native) and releases them together.
     */
    private suspend fun consumeConcurrently(repository: PreKeyRepository, consumers: Int): List<Int?> =
        withContext(Dispatchers.Default) {
            val start = CompletableDeferred<Unit>()
            val fetches = List(consumers) {
                async {
                    start.await()
                    assertNotNull(repository.consumePreKeyBundle(bob)).oneTimePreKey?.id?.value
                }
            }
            start.complete(Unit)
            fetches.awaitAll()
        }
}
