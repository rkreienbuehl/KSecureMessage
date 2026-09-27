package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Milestone 8's main scenario (docs/message-reliability.md): a message sent
 * on the initiation that loses a simultaneous-initiation collision is
 * discarded by the winner without an acknowledgement, stays pending, and is
 * delivered exactly once after the sender retries on the winning session.
 */
class MessageCollisionRecoveryTest {
    private class Collision(
        val winner: ReliableDevice,
        val loser: ReliableDevice,
        val toWinner: EncryptedEnvelope,
        val toLoser: EncryptedEnvelope,
        val winnerMessage: SentMessage,
        val loserMessage: SentMessage,
        val aliceWins: Boolean,
    )

    /** Alice and Bob both start a session with the other at the same time. */
    private suspend fun collision(): Collision {
        val network = FlakyNetwork()
        val alice = ReliableDevice(ALICE, network).start()
        val bob = ReliableDevice(BOB, network).start()
        val fromAlice = alice.send(bob, "from Alice")
        val fromBob = bob.send(alice, "from Bob")
        val toBob = bob.inbox().single()
        val toAlice = alice.inbox().single()
        val aliceWins = bob.initiationOf(toBob) < alice.initiationOf(toAlice)
        return if (aliceWins) {
            Collision(alice, bob, toAlice, toBob, fromAlice, fromBob, aliceWins = true)
        } else {
            Collision(bob, alice, toBob, toAlice, fromBob, fromAlice, aliceWins = false)
        }
    }

    /** Runs [scenario] until both Alice and Bob have lost a collision once (the winner is random). */
    private fun bothWinners(scenario: suspend (Collision) -> Unit) = runTest {
        val seen = mutableSetOf<Boolean>()
        var rounds = 0
        while (seen.size < 2) {
            check(++rounds <= 64) { "the same side won 64 times" }
            val collision = collision()
            if (collision.aliceWins in seen) continue
            scenario(collision)
            seen += collision.aliceWins
        }
    }

    private suspend fun recover(c: Collision, winnerProcessesFirst: Boolean, restartBeforeRetry: Boolean) {
        val (winner, loser) = c.winner to c.loser
        val loserText = if (c.aliceWins) "from Bob" else "from Alice"
        val winnerText = if (c.aliceWins) "from Alice" else "from Bob"

        suspend fun winnerRejectsTheLosingInitiation() {
            assertFailsWith<SecureMessageClientException.SessionCollision> { winner.receive(c.toWinner) }
            assertTrue(!winner.isProcessed(loser, c.loserMessage.id), "discarded, not processed")
            assertTrue(!winner.isPendingInbound(loser, c.loserMessage.id), "discarded, not pending")
        }

        suspend fun loserSwitchesToTheWinningSession() {
            val result = loser.receive(c.toLoser)
            val received = result.delivery()
            assertEquals(winnerText, received.plaintext.decodeToString())
            assertEquals(c.winnerMessage.id, received.id)
            assertTrue(loser.commit(result).ackSent)
        }

        if (winnerProcessesFirst) {
            winnerRejectsTheLosingInitiation()
            loserSwitchesToTheWinningSession()
        } else {
            loserSwitchesToTheWinningSession()
            winnerRejectsTheLosingInitiation()
        }

        // No acknowledgement for the discarded message; it stays pending.
        assertEquals(emptyList(), loser.inbox())
        assertEquals(listOf(c.loserMessage.id), loser.pending(winner))

        // The winner's message was acknowledged on the winning session.
        val ack = assertIs<ReceiveResult.Acknowledgement>(winner.receiveOne())
        assertEquals(c.winnerMessage.id, ack.id)
        assertTrue(ack.cleared)
        assertEquals(emptyList(), winner.pending(loser))

        if (restartBeforeRetry) {
            winner.restart()
            loser.restart()
            assertEquals(listOf(c.loserMessage.id), loser.pending(winner))
        }

        assertEquals(listOf(c.loserMessage.id), loser.client.retryPendingMessages(winner.address))
        val resent = winner.inbox().single()
        assertNotEquals(c.loserMessage.envelope.id, resent.id, "new envelope")
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(resent.payload), "encrypted on the winning session")

        val result = winner.receive(resent)
        val delivered = result.delivery()
        assertEquals(c.loserMessage.id, delivered.id, "same logical message")
        assertEquals(loserText, delivered.plaintext.decodeToString())
        // Still pending for the sender until the winner's application commits it.
        assertEquals(emptyList(), loser.inbox())
        assertEquals(listOf(c.loserMessage.id), loser.pending(winner))
        assertTrue(winner.commit(result).ackSent)

        val loserAck = assertIs<ReceiveResult.Acknowledgement>(loser.receiveOne())
        assertEquals(c.loserMessage.id, loserAck.id)
        assertTrue(loserAck.cleared)
        assertEquals(emptyList(), loser.pending(winner))
        assertEquals(emptyList(), winner.inbox())
        assertEquals(emptyList(), loser.client.retryPendingMessages(winner.address))

        // Both sides keep working on one session.
        loser.send(winner, "after recovery")
        assertEquals("after recovery", winner.acceptOne())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(loser.receiveOne()).cleared)
    }

    @Test
    fun lostMessageIsResentAfterConvergence() = bothWinners { recover(it, winnerProcessesFirst = true, restartBeforeRetry = false) }

    @Test
    fun lostMessageIsResentWhenTheLoserConvergesFirst() =
        bothWinners { recover(it, winnerProcessesFirst = false, restartBeforeRetry = false) }

    @Test
    fun lostMessageIsResentAfterRestart() = bothWinners { recover(it, winnerProcessesFirst = true, restartBeforeRetry = true) }

    /**
     * A retry before the loser learned about the collision re-encrypts on the
     * losing session. The winner rejects it as stale, without an
     * acknowledgement, and the message stays pending.
     */
    @Test
    fun retryBeforeConvergenceIsRejectedAndKeptPending() = bothWinners { c ->
        assertFailsWith<SecureMessageClientException.SessionCollision> { c.winner.receive(c.toWinner) }

        assertEquals(listOf(c.loserMessage.id), c.loser.client.retryPendingMessages(c.winner.address))
        val early = c.winner.inbox().single()
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { c.winner.receive(early) }
        assertEquals(emptyList(), c.loser.inbox())
        assertEquals(listOf(c.loserMessage.id), c.loser.pending(c.winner))

        c.loser.commit(c.loser.receive(c.toLoser))
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(c.winner.receiveOne()).cleared)
        c.loser.client.retryPendingMessages(c.winner.address)
        val delivery = c.winner.receiveOne()
        assertEquals(c.loserMessage.id, delivery.delivery().id)
        c.winner.commit(delivery)
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(c.loser.receiveOne()).cleared)
        assertEquals(emptyList(), c.loser.pending(c.winner))
    }

    /**
     * A message lost in a collision and abandoned before the sessions
     * converged is never resent on the winning session
     * (docs/outbound-message-lifecycle.md); the winning session keeps working.
     */
    @Test
    fun messageAbandonedBeforeConvergenceIsNotResent() = bothWinners { c ->
        assertFailsWith<SecureMessageClientException.SessionCollision> { c.winner.receive(c.toWinner) }
        assertEquals(listOf(c.loserMessage.id), c.loser.pending(c.winner))

        assertEquals(AbandonStatus.ABANDONED, c.loser.client.abandonPendingMessage(c.winner.address, c.loserMessage.id))
        assertEquals(emptyList(), c.winner.inbox(), "abandoning sends nothing")

        c.loser.commit(c.loser.receive(c.toLoser))
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(c.winner.receiveOne()).cleared)
        assertEquals(emptyList(), c.loser.client.retryPendingMessages(c.winner.address))
        assertEquals(emptyList(), c.winner.inbox())
        assertEquals(emptyList(), c.loser.pending(c.winner))

        c.loser.send(c.winner, "after convergence")
        assertEquals("after convergence", c.winner.acceptOne())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(c.loser.receiveOne()).cleared)
    }
}
