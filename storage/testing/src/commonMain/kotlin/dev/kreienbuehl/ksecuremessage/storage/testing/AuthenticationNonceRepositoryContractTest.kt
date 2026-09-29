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

    // S1, finding F8 (docs/security-review-remediation.md): the server accepts
    // now - W <= ts <= now + W, so a request with timestamp ts can be replayed
    // at any server time up to ts + W. Callers read their clocks at different
    // times; a claim whose pruneBefore is later than another caller's must not
    // prune a nonce that caller could still accept.

    @Test
    fun f8InterleavedPruneBeforeReplayClaimIsRejected() = runTest {
        val repository = newRepository()
        val window = 5.minutes
        val ts = t0
        assertTrue(repository.claim(alice, nonce(1), ts, pruneBefore = ts - window))
        // A replay passed its window check at server time ts + W (inclusive) ...
        val replayPruneBefore = ts + window - window
        // ... then another request, checked 1 ms later, prunes with ts + W + 1 - W.
        assertTrue(repository.claim(bob, nonce(2), ts + window + 1.milliseconds, pruneBefore = ts + 1.milliseconds))
        // The original nonce may be gone, but the replay must still be refused.
        assertFalse(repository.claim(alice, nonce(1), ts, pruneBefore = replayPruneBefore), "replay after a concurrent prune")
    }

    @Test
    fun f8NonceIsRetainedForItsWholeReplayLifetime() = runTest {
        val window = 5.minutes
        // Earliest valid, latest (future-dated) valid and a timestamp in between.
        for (offset in listOf(-window, 0.minutes, window)) {
            val repository = newRepository()
            val acceptedAt = t0
            val ts = acceptedAt + offset
            assertTrue(repository.claim(alice, nonce(1), ts, pruneBefore = acceptedAt - window))
            // Every server time at which ts still passes the window: ts - W .. ts + W.
            for (serverTime in listOf(acceptedAt, ts + window - 1.milliseconds, ts + window)) {
                if (serverTime < acceptedAt) continue
                assertFalse(
                    repository.claim(alice, nonce(1), ts, pruneBefore = serverTime - window),
                    "replay at offset $offset, server time ${serverTime - acceptedAt} after acceptance",
                )
            }
        }
    }

    @Test
    fun f8ExactPruneBoundary() = runTest {
        val repository = newRepository()
        val window = 5.minutes
        val ts = t0
        assertTrue(repository.claim(alice, nonce(1), ts, pruneBefore = ts - window))
        // At server time ts + W the request is still valid: the entry exactly at the bound is kept.
        assertFalse(repository.claim(alice, nonce(1), ts, pruneBefore = ts))
        // At ts + W + 1 ms the request is outside the window; the entry may go, and a claim with ts is refused.
        assertTrue(repository.claim(bob, nonce(2), ts + window + 1.milliseconds, pruneBefore = ts + 1.milliseconds))
        assertFalse(repository.claim(alice, nonce(3), ts, pruneBefore = ts), "timestamp before the watermark")
        assertTrue(repository.claim(alice, nonce(4), ts + 1.milliseconds, pruneBefore = ts), "timestamp exactly at the watermark")
    }

    @Test
    fun f8WatermarkNeverDecreases() = runTest {
        val repository = newRepository()
        assertTrue(repository.claim(alice, nonce(1), t0 + 10.minutes, pruneBefore = t0 + 5.minutes))
        // A caller with an older clock does not lower the watermark.
        assertFalse(repository.claim(alice, nonce(2), t0 + 1.minutes, pruneBefore = t0))
        assertTrue(repository.claim(alice, nonce(3), t0 + 5.minutes, pruneBefore = t0))
    }

    @Test
    fun f8ConcurrentPruneAndReplayClaimsNeverAcceptAReplay() = runTest {
        val window = 5.minutes
        repeat(20) { round ->
            val repository = newRepository()
            val ts = t0
            assertTrue(repository.claim(alice, nonce(round), ts, pruneBefore = ts - window))
            val results = withContext(Dispatchers.Default) {
                List(64) { index ->
                    async {
                        if (index % 2 == 0) {
                            // Replays checked at server times ts .. ts + W.
                            repository.claim(alice, nonce(round), ts, pruneBefore = ts - window + (index % 3).milliseconds)
                        } else {
                            // Other requests whose clocks are already past ts + W.
                            repository.claim(bob, nonce(1000 + index), ts + window + index.milliseconds, pruneBefore = ts + index.milliseconds)
                            false
                        }
                    }
                }.awaitAll()
            }
            assertEquals(0, results.count { it }, "a replay was accepted")
        }
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
