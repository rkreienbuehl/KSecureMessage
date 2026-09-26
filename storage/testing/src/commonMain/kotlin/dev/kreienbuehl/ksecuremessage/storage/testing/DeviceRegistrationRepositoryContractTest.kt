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
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/**
 * Behavior every server [DeviceRegistrationRepository] must have
 * (docs/server-authentication.md): one key per address, registered once,
 * never replaced, atomic under concurrency, with the caller's installation
 * time recorded once (docs/device-authentication-rotation.md).
 */
abstract class DeviceRegistrationRepositoryContractTest {
    /** Returns a new, empty repository. */
    protected abstract suspend fun newRepository(): DeviceRegistrationRepository

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))

    private val registeredAt = Instant.fromEpochMilliseconds(1_767_225_600_000)

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }

    @Test
    fun firstRegistrationRecordsEpochOneAndItsInstallationTimeWhichRetriesKeep() = runTest {
        val repository = newRepository()
        val t1 = registeredAt
        assertTrue(repository.register(DeviceRegistration(alice, key(1)), t1))
        val state = assertNotNull(repository.registrationState(alice))
        assertEquals(1, state.authEpoch)
        assertEquals(t1, state.authKeyInstalledAt)

        // An identical retry later (a lost response, a recovery/rotation probe) never refreshes the key's age.
        assertFalse(repository.register(DeviceRegistration(alice, key(1)), t1 + 30.days))
        assertEquals(t1, repository.registrationState(alice)?.authKeyInstalledAt)
        assertEquals(1, repository.registrationState(alice)?.authEpoch)
        // Neither does a rejected conflicting registration.
        assertFailsWith<DeviceRegistrationException.Conflict> { repository.register(DeviceRegistration(alice, key(2)), t1 + 31.days) }
        assertEquals(t1, repository.registrationState(alice)?.authKeyInstalledAt)

        assertTrue(repository.register(DeviceRegistration(laptop, key(3)), t1 + 2.days))
        assertEquals(t1 + 2.days, repository.registrationState(laptop)?.authKeyInstalledAt, "per device")
        assertEquals(t1, repository.registrationState(alice)?.authKeyInstalledAt)
    }

    @Test
    fun firstRegistrationIsStoredAndRetriesAreIdempotent() = runTest {
        val repository = newRepository()
        assertNull(repository.registration(alice))

        assertTrue(repository.register(DeviceRegistration(alice, key(1)), registeredAt))
        assertContentEquals(key(1), repository.registration(alice)?.publicKey)
        assertFalse(repository.register(DeviceRegistration(alice, key(1)), registeredAt), "identical retry")
        assertContentEquals(key(1), repository.registration(alice)?.publicKey)
        assertNull(repository.registration(laptop), "per device")
    }

    @Test
    fun conflictingRegistrationIsRejectedAndChangesNothing() = runTest {
        val repository = newRepository()
        repository.register(DeviceRegistration(alice, key(1)), registeredAt)

        assertFailsWith<DeviceRegistrationException.Conflict> { repository.register(DeviceRegistration(alice, key(2)), registeredAt) }
        assertContentEquals(key(1), repository.registration(alice)?.publicKey)
        assertTrue(repository.register(DeviceRegistration(laptop, key(2)), registeredAt), "another device may use its own key")
    }

    @Test
    fun keysAreCopied() = runTest {
        val repository = newRepository()
        val bytes = key(1)
        repository.register(DeviceRegistration(alice, bytes), registeredAt)
        bytes.fill(0)
        repository.registration(alice)!!.publicKey.fill(0)
        assertContentEquals(key(1), repository.registration(alice)?.publicKey)
    }

    @Test
    fun concurrentIdenticalRegistrationsConverge() = runTest {
        val repository = newRepository()
        val results = withContext(Dispatchers.Default) {
            List(64) { async { repository.register(DeviceRegistration(alice, key(1)), registeredAt) } }.awaitAll()
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
                            if (repository.register(DeviceRegistration(alice, key(seed)), registeredAt)) seed else null
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
                    assertFailsWith<DeviceRegistrationException.Conflict> { repository.register(DeviceRegistration(alice, key(seed)), registeredAt) }
                }
            }
            assertContentEquals(key(winners.single()), repository.registration(alice)?.publicKey, "never overwritten")
        }
    }
}
