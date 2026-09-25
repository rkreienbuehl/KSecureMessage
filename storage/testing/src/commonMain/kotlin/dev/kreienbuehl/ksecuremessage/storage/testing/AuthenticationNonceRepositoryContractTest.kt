package dev.kreienbuehl.ksecuremessage.storage.testing

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Behavior every server [AuthenticationNonceRepository] must have
 * (docs/server-authentication.md): a nonce is accepted once per device,
 * atomically, and entries leave only through pruning by request timestamp.
 */
abstract class AuthenticationNonceRepositoryContractTest {
    /** Returns a new, empty repository. */
    protected abstract suspend fun newRepository(): AuthenticationNonceRepository

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)
    private val longAgo = Instant.fromEpochMilliseconds(0)

    private fun nonce(seed: Int) = ByteArray(16) { (seed + it).toByte() }

    @Test
    fun aNonceIsAcceptedOncePerDevice() = runTest {
        val repository = newRepository()
        assertTrue(repository.claim(alice, nonce(1), t0, longAgo))
        assertFalse(repository.claim(alice, nonce(1), t0, longAgo), "replay")
        assertFalse(repository.claim(alice, nonce(1), t0 + 1.minutes, longAgo), "replay with another timestamp")
        assertTrue(repository.claim(alice, nonce(2), t0, longAgo), "another nonce")
        assertTrue(repository.claim(bob, nonce(1), t0, longAgo), "same nonce, other device")
        assertFalse(repository.claim(bob, nonce(1), t0, longAgo))
    }

    @Test
    fun nonceBytesAreCopied() = runTest {
        val repository = newRepository()
        val bytes = nonce(1)
        assertTrue(repository.claim(alice, bytes, t0, longAgo))
        bytes.fill(0)
        assertFalse(repository.claim(alice, nonce(1), t0, longAgo))
        assertTrue(repository.claim(alice, ByteArray(16), t0, longAgo))
    }

    @Test
    fun entriesBeforeThePruneBoundAreRemovedAndOthersKept() = runTest {
        val repository = newRepository()
        assertTrue(repository.claim(alice, nonce(1), t0, longAgo))
        assertTrue(repository.claim(bob, nonce(2), t0 + 1.milliseconds, longAgo))

        // The bound is exclusive: an entry exactly at it is kept.
        assertFalse(repository.claim(alice, nonce(1), t0 + 5.minutes, pruneBefore = t0))
        // One millisecond later it is pruned; the newer one of another device is kept.
        assertTrue(repository.claim(alice, nonce(1), t0 + 5.minutes, pruneBefore = t0 + 1.milliseconds), "pruned, so new again")
        assertFalse(repository.claim(bob, nonce(2), t0 + 5.minutes, pruneBefore = t0 + 1.milliseconds), "kept")
        assertFalse(repository.claim(alice, nonce(1), t0 + 5.minutes, pruneBefore = t0 + 1.milliseconds), "the new entry is recorded")
    }

    @Test
    fun concurrentClaimsOfOneNonceHaveExactlyOneWinner() = runTest {
        repeat(20) { round ->
            val repository = newRepository()
            val results = withContext(Dispatchers.Default) {
                List(64) { async { repository.claim(alice, nonce(round), t0, longAgo) } }.awaitAll()
            }
            assertEquals(1, results.count { it })
        }
    }

    @Test
    fun concurrentClaimsOfDistinctNoncesAllSucceed() = runTest {
        val repository = newRepository()
        val results = withContext(Dispatchers.Default) {
            List(200) { index -> async { repository.claim(if (index % 2 == 0) alice else bob, nonce(index / 2), t0, longAgo) } }.awaitAll()
        }
        assertTrue(results.all { it })
    }
}
