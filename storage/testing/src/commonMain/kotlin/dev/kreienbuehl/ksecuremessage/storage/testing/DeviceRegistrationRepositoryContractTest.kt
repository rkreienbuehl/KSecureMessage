package dev.kreienbuehl.ksecuremessage.storage.testing

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Behavior every server [DeviceRegistrationRepository] must have
 * (docs/server-authentication.md): one key per address, registered once,
 * never replaced, atomic under concurrency.
 */
abstract class DeviceRegistrationRepositoryContractTest {
    /** Returns a new, empty repository. */
    protected abstract suspend fun newRepository(): DeviceRegistrationRepository

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }

    @Test
    fun firstRegistrationIsStoredAndRetriesAreIdempotent() = runTest {
        val repository = newRepository()
        assertNull(repository.registration(alice))

        assertTrue(repository.register(DeviceRegistration(alice, key(1))))
        assertContentEquals(key(1), repository.registration(alice)?.publicKey)
        assertFalse(repository.register(DeviceRegistration(alice, key(1))), "identical retry")
        assertContentEquals(key(1), repository.registration(alice)?.publicKey)
        assertNull(repository.registration(laptop), "per device")
    }

    @Test
    fun conflictingRegistrationIsRejectedAndChangesNothing() = runTest {
        val repository = newRepository()
        repository.register(DeviceRegistration(alice, key(1)))

        assertFailsWith<DeviceRegistrationException.Conflict> { repository.register(DeviceRegistration(alice, key(2))) }
        assertContentEquals(key(1), repository.registration(alice)?.publicKey)
        assertTrue(repository.register(DeviceRegistration(laptop, key(2))), "another device may use its own key")
    }

    @Test
    fun keysAreCopied() = runTest {
        val repository = newRepository()
        val bytes = key(1)
        repository.register(DeviceRegistration(alice, bytes))
        bytes.fill(0)
        repository.registration(alice)!!.publicKey.fill(0)
        assertContentEquals(key(1), repository.registration(alice)?.publicKey)
    }

    @Test
    fun concurrentIdenticalRegistrationsConverge() = runTest {
        val repository = newRepository()
        val results = withContext(Dispatchers.Default) {
            List(64) { async { repository.register(DeviceRegistration(alice, key(1))) } }.awaitAll()
        }
        assertEquals(1, results.count { it }, "exactly one call stored it")
        assertContentEquals(key(1), repository.registration(alice)?.publicKey)
    }

    @Test
    fun concurrentConflictingRegistrationsHaveExactlyOneWinner() = runTest {
        repeat(20) {
            val repository = newRepository()
            val outcomes = withContext(Dispatchers.Default) {
                List(32) { seed ->
                    async {
                        try {
                            if (repository.register(DeviceRegistration(alice, key(seed)))) seed else null
                        } catch (e: DeviceRegistrationException.Conflict) {
                            -1
                        }
                    }
                }.awaitAll()
            }
            val winners = outcomes.filterNotNull().filter { it >= 0 }
            assertEquals(1, winners.size, "exactly one key became authoritative")
            assertEquals(31, outcomes.count { it == -1 }, "every other key conflicted")
            assertContentEquals(key(winners.single()), repository.registration(alice)?.publicKey)
            for (seed in 0 until 32) {
                if (seed != winners.single()) {
                    assertFailsWith<DeviceRegistrationException.Conflict> { repository.register(DeviceRegistration(alice, key(seed))) }
                }
            }
            assertContentEquals(key(winners.single()), repository.registration(alice)?.publicKey, "never overwritten")
        }
    }
}
