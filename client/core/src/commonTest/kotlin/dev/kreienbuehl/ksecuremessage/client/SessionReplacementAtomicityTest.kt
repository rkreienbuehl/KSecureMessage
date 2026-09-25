package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Replacing a session, retiring the old initiation and consuming the one-time
 * prekey happen in one transaction; a failure in any write leaves every piece
 * of state as it was, and the old session keeps working.
 */
class SessionReplacementAtomicityTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()
    private val network = FakeNetwork()

    private inner class Device(val address: DeviceAddress) {
        val storage = InMemoryClientStorage()
        val failing = FailingClientStorage(storage)
        val client = SecureMessageClient(address, failing, engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 4))

        suspend fun receiveOne(): EncryptedEnvelope = network.receive(address).single()

        suspend fun initiationOf(envelope: EncryptedEnvelope) = SessionInitiationId.of(
            assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(envelope.payload)),
            assertNotNull(storage.identity.identity()).publicKey,
        )

        suspend fun origin(remote: DeviceAddress) =
            engine.sessionInfo(assertNotNull(storage.sessions.load(remote))).initiationId

        fun healthy() {
            failing.failSessionStore = false
            failing.failRetire = false
            failing.failOneTimePreKeyRemoval = false
            failing.failRemoteIdentityStore = false
        }
    }

    private suspend fun device(address: DeviceAddress) = Device(address).also {
        it.client.initialize()
        network.publish(it.client)
    }

    private class State(
        val session: ByteArray?,
        val pin: ByteArray?,
        val oneTimePreKeys: List<Int>,
        val retired: List<Boolean>,
    )

    private suspend fun Device.state(remote: DeviceAddress, vararg initiations: SessionInitiationId) = State(
        session = storage.sessions.load(remote)?.state,
        pin = storage.remoteIdentities.identityKey(remote),
        oneTimePreKeys = storage.preKeys.publicOneTimePreKeys().map { it.id.value },
        retired = initiations.map { storage.sessionInitiations.isRetired(remote, it) },
    )

    private fun assertSame(expected: State, actual: State) {
        assertContentEquals(expected.session, actual.session, "session bytes")
        assertContentEquals(expected.pin, actual.pin, "pin")
        assertEquals(expected.oneTimePreKeys, actual.oneTimePreKeys, "one-time prekeys")
        assertEquals(expected.retired, actual.retired, "retired initiations")
    }

    /**
     * Bob and Alice share session S1. Returns a message still in flight on S1
     * and Alice's first message of a new session S2 (she lost S1).
     */
    private suspend fun replacement(): Triple<Device, Device, Pair<EncryptedEnvelope, EncryptedEnvelope>> {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.client.sendRaw(BOB, "hello".encodeToByteArray())
        bob.client.decryptRaw(bob.receiveOne())
        bob.client.sendRaw(ALICE, "hi".encodeToByteArray())
        alice.client.decryptRaw(alice.receiveOne())
        alice.client.sendRaw(BOB, "late on S1".encodeToByteArray())
        val late = bob.receiveOne()

        alice.storage.sessions.remove(BOB)
        network.publish(bob.client)
        alice.client.sendRaw(BOB, "on S2".encodeToByteArray())
        return Triple(alice, bob, late to bob.receiveOne())
    }

    private suspend fun assertReplacementFailureChangesNothing(inject: FailingClientStorage.() -> Unit) {
        val (_, bob, messages) = replacement()
        val (late, s2) = messages
        val s1 = assertNotNull(bob.origin(ALICE))
        val s2Id = bob.initiationOf(s2)
        val before = bob.state(ALICE, s1, s2Id)

        bob.failing.inject()
        assertFailsWith<StorageFailure> { bob.client.decryptRaw(s2) }
        assertSame(before, bob.state(ALICE, s1, s2Id))
        assertEquals(s1, bob.origin(ALICE))

        // The old session still works, and the replacement succeeds later.
        bob.healthy()
        assertEquals("late on S1", bob.client.decryptRaw(late).decodeToString())
        assertEquals("on S2", bob.client.decryptRaw(s2).decodeToString())
        assertEquals(s2Id, bob.origin(ALICE))
        assertTrue(bob.storage.sessionInitiations.isRetired(ALICE, s1))
        assertEquals(before.oneTimePreKeys.drop(1), bob.state(ALICE).oneTimePreKeys)
    }

    @Test
    fun sessionStoreFailureDuringReplacement() = runTest {
        assertReplacementFailureChangesNothing { failSessionStore = true }
    }

    @Test
    fun retireFailureDuringReplacement() = runTest {
        assertReplacementFailureChangesNothing { failRetire = true }
    }

    @Test
    fun oneTimePreKeyRemovalFailureDuringReplacement() = runTest {
        assertReplacementFailureChangesNothing { failOneTimePreKeyRemoval = true }
    }

    @Test
    fun tamperedReplacementChangesNothing() = runTest {
        val (_, bob, messages) = replacement()
        val (late, s2) = messages
        val s1 = assertNotNull(bob.origin(ALICE))
        val before = bob.state(ALICE, s1, bob.initiationOf(s2))
        assertFails { bob.client.decryptRaw(s2.tampered()) }
        assertSame(before, bob.state(ALICE, s1, bob.initiationOf(s2)))
        assertEquals("late on S1", bob.client.decryptRaw(late).decodeToString())
    }

    /** Both sides started a session at once. [toWinner] carries the losing initiation. */
    private inner class Collision(
        val winner: Device,
        val loser: Device,
        val toWinner: EncryptedEnvelope,
        val toLoser: EncryptedEnvelope,
    )

    private suspend fun collision(): Collision {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.client.sendRaw(BOB, "hello".encodeToByteArray())
        bob.client.decryptRaw(bob.receiveOne())
        bob.client.sendRaw(ALICE, "hi".encodeToByteArray())
        alice.client.decryptRaw(alice.receiveOne())
        alice.storage.sessions.remove(BOB)
        bob.storage.sessions.remove(ALICE)
        network.publish(alice.client)
        network.publish(bob.client)

        alice.client.sendRaw(BOB, "from Alice".encodeToByteArray())
        bob.client.sendRaw(ALICE, "from Bob".encodeToByteArray())
        val toBob = bob.receiveOne()
        val toAlice = alice.receiveOne()
        return if (bob.initiationOf(toBob) < alice.initiationOf(toAlice)) {
            Collision(winner = alice, loser = bob, toWinner = toAlice, toLoser = toBob)
        } else {
            Collision(winner = bob, loser = alice, toWinner = toBob, toLoser = toAlice)
        }
    }

    @Test
    fun retireFailureWhenRejectingTheLoserChangesNothing() = runTest {
        val (winner, loser, toWinner) = with(collision()) { Triple(winner, loser, toWinner) }
        val losing = winner.initiationOf(toWinner)
        val before = winner.state(loser.address, losing)

        winner.failing.failRetire = true
        assertFailsWith<StorageFailure> { winner.client.decryptRaw(toWinner) }
        assertSame(before, winner.state(loser.address, losing))

        winner.healthy()
        assertFailsWith<SecureMessageClientException.SessionCollision> { winner.client.decryptRaw(toWinner) }
        assertEquals(listOf(true), winner.state(loser.address, losing).retired)
        assertEquals(before.oneTimePreKeys, winner.state(loser.address).oneTimePreKeys)
    }

    @Test
    fun failureWhenSwitchingToTheWinnerKeepsThePendingSession() = runTest {
        val (winner, loser, toLoser) = with(collision()) { Triple(winner, loser, toLoser) }
        val own = assertNotNull(loser.origin(winner.address))
        val winning = loser.initiationOf(toLoser)

        for (inject in listOf<FailingClientStorage.() -> Unit>(
            { failSessionStore = true },
            { failRetire = true },
            { failOneTimePreKeyRemoval = true },
        )) {
            val before = loser.state(winner.address, own, winning)
            loser.failing.inject()
            assertFailsWith<StorageFailure> { loser.client.decryptRaw(toLoser) }
            assertSame(before, loser.state(winner.address, own, winning))
            assertTrue(engine.sessionInfo(assertNotNull(loser.storage.sessions.load(winner.address))).awaitingReply)
            loser.healthy()
        }

        assertEquals("from ${if (winner.address == ALICE) "Alice" else "Bob"}", loser.client.decryptRaw(toLoser).decodeToString())
        assertEquals(winning, loser.origin(winner.address))
        assertTrue(loser.storage.sessionInitiations.isRetired(winner.address, own))
        assertFalse(loser.storage.sessionInitiations.isRetired(winner.address, winning))
    }
}
