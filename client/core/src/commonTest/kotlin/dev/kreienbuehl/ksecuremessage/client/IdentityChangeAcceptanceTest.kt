package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.protocol.PublicIdentityKey
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Explicit acceptance of a changed remote identity
 * (docs/identity-verification.md): changes still fail by default, acceptance
 * installs exactly the confirmed key as unverified, removes and retires the
 * old session atomically, and keeps pending messages for a retry.
 */
class IdentityChangeAcceptanceTest {
    private val network = FlakyNetwork()
    private val engine = KodiumProtocolEngine()

    private suspend fun device(address: DeviceAddress) = ReliableDevice(address, network).start()

    private suspend fun ReliableDevice.identityKey() = PublicIdentityKey(assertNotNull(storage.identity.identity()).publicKey)

    private suspend fun ReliableDevice.trust() = client.remoteIdentityTrust(BOB)

    private suspend fun ReliableDevice.initiationWith(remote: ReliableDevice): SessionInitiationId? =
        storage.sessions.load(remote.address)?.let { engine.sessionInfo(it).initiationId }

    private fun EncryptedEnvelope.isPreKeyMessage() = CiphertextMessageCodec.decode(payload) is PreKeyMessage

    /** Alice and Bob exchanged a message each way. */
    private suspend fun conversation(): Pair<ReliableDevice, ReliableDevice> {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(bob, "hi bob")
        bob.acceptOne()
        alice.receiveOne()
        bob.send(alice, "hi alice")
        alice.acceptOne()
        bob.receiveOne()
        return alice to bob
    }

    /** Bob's device is reinstalled: new messaging identity, new bundle, no state. */
    private suspend fun reinstalledBob() = device(BOB)

    /** The reinstalled Bob writes to Alice; Alice refuses the new identity. */
    private suspend fun identityChange(alice: ReliableDevice, newBob: ReliableDevice): Pair<EncryptedEnvelope, SecureMessageClientException.IdentityChanged> {
        // Like the relay, hand out a one-time prekey Alice still has.
        network.fake.publish(alice.client)
        newBob.send(alice, "new phone, who dis")
        val envelope = alice.inbox().single()
        return envelope to assertFailsWith<SecureMessageClientException.IdentityChanged> { alice.receive(envelope) }
    }

    @Test
    fun changedIdentityFailsUntilExplicitlyAcceptedAndThenStartsUnverified() = runTest {
        val (alice, oldBob) = conversation()
        val carol = device(CAROL)
        alice.send(carol, "hi carol")
        carol.acceptOne()
        alice.receiveOne()
        alice.client.markRemoteIdentityVerified(alice.client.safetyNumber(BOB))
        val oldInitiation = assertNotNull(alice.initiationWith(oldBob))
        val carolSession = assertNotNull(alice.storage.sessions.load(CAROL)).state

        val newBob = reinstalledBob()
        val (envelope, changed) = identityChange(alice, newBob)
        assertEquals(BOB, changed.address)
        assertEquals(oldBob.identityKey(), changed.pinnedIdentityKey)
        assertEquals(newBob.identityKey(), changed.presentedIdentityKey)
        assertEquals(RemoteIdentityChange(BOB, oldBob.identityKey(), newBob.identityKey()), changed.change)
        assertEquals("Remote identity changed for $BOB", changed.message, "no key material in the message")

        // Nothing changed, and trying again does not accept anything.
        assertFailsWith<SecureMessageClientException.IdentityChanged> { alice.receive(envelope) }
        assertEquals(RemoteIdentityTrust(BOB, oldBob.identityKey(), VerificationState.VERIFIED), alice.trust())
        assertEquals(oldInitiation, alice.initiationWith(oldBob))

        // The user compares the safety number of the new key before accepting.
        assertEquals(newBob.client.safetyNumber(ALICE), alice.client.safetyNumber(changed.change))
        assertEquals(RemoteIdentityTrust(BOB, oldBob.identityKey(), VerificationState.VERIFIED), alice.trust(), "comparing accepts nothing")

        alice.client.acceptRemoteIdentityChange(changed.change)
        assertEquals(RemoteIdentityTrust(BOB, newBob.identityKey(), VerificationState.UNVERIFIED), alice.trust())
        assertNull(alice.storage.sessions.load(BOB), "the session with the old identity is gone")
        assertTrue(alice.storage.sessionInitiations.isRetired(BOB, oldInitiation), "and retired")
        assertContentEquals(carolSession, alice.storage.sessions.load(CAROL)?.state, "other peers are not touched")

        // The refused envelope changed nothing, so it can be processed now.
        val result = alice.receive(envelope)
        assertEquals("new phone, who dis", result.text())
        assertTrue(alice.commit(result).ackSent)
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(newBob.receiveOne()).cleared)

        alice.client.markRemoteIdentityVerified(alice.client.safetyNumber(BOB))
        assertEquals(VerificationState.VERIFIED, alice.trust()?.verification)
        alice.send(newBob, "welcome back")
        assertEquals("welcome back", newBob.acceptOne())
        assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne())
    }

    @Test
    fun oldSafetyNumberCannotVerifyTheNewIdentity() = runTest {
        val (alice, _) = conversation()
        val old = alice.client.safetyNumber(BOB)
        alice.client.markRemoteIdentityVerified(old)
        val (_, changed) = identityChange(alice, reinstalledBob())
        alice.client.acceptRemoteIdentityChange(changed.change)

        assertNotEquals(old, alice.client.safetyNumber(BOB))
        assertFailsWith<SecureMessageClientException.RemoteIdentityConflict> { alice.client.markRemoteIdentityVerified(old) }
        assertEquals(VerificationState.UNVERIFIED, alice.trust()?.verification)
    }

    @Test
    fun acceptanceInstallsTheConfirmedKeyNotTheLatestFetchedOne() = runTest {
        val (alice, _) = conversation()
        val bobTwo = reinstalledBob()
        val (envelope, changed) = identityChange(alice, bobTwo)
        // While the user looks at K2, the server starts serving yet another identity K3.
        val bobThree = reinstalledBob()
        assertNotEquals(bobTwo.identityKey(), bobThree.identityKey())

        alice.client.acceptRemoteIdentityChange(changed.change)
        assertEquals(bobTwo.identityKey(), alice.trust()?.identityKey)

        // Without a session, sending fetches K3, which is a new change and fails; nothing is stored.
        val refused = assertFailsWith<SecureMessageClientException.IdentityChanged> { alice.send(bobThree, "to whom?") }
        assertEquals(bobTwo.identityKey(), refused.pinnedIdentityKey)
        assertEquals(bobThree.identityKey(), refused.presentedIdentityKey)
        assertEquals(emptyList(), alice.pending(bobThree))
        assertNull(alice.storage.sessions.load(BOB))
        assertEquals(RemoteIdentityTrust(BOB, bobTwo.identityKey(), VerificationState.UNVERIFIED), alice.trust())

        // The confirmed identity K2 works.
        assertEquals("new phone, who dis", alice.receive(envelope).text())
    }

    @Test
    fun oldIdentityTrafficIsRejectedAndCannotRestoreTheOldSession() = runTest {
        val alice = device(ALICE)
        val oldBob = device(BOB)
        // Bob starts the session, so Alice holds his initiation; keep copies of his old traffic.
        oldBob.send(alice, "first")
        val oldPreKeyMessage = alice.inbox().single()
        assertTrue(oldPreKeyMessage.isPreKeyMessage())
        alice.commit(alice.receive(oldPreKeyMessage))
        oldBob.receiveOne()
        oldBob.send(alice, "second")
        val oldRatchetMessage = alice.inbox().single()
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(oldRatchetMessage.payload))
        alice.commit(alice.receive(oldRatchetMessage))
        oldBob.receiveOne()
        val oldInitiation = assertNotNull(alice.initiationWith(oldBob))

        val newBob = reinstalledBob()
        val (envelope, changed) = identityChange(alice, newBob)
        alice.client.acceptRemoteIdentityChange(changed.change)

        // Old identity: its PreKeyMessage is a changed identity now, its ratchet traffic has no session.
        val replayed = assertFailsWith<SecureMessageClientException.IdentityChanged> { alice.receive(oldPreKeyMessage) }
        assertEquals(oldBob.identityKey(), replayed.presentedIdentityKey)
        assertFailsWith<ProtocolException> { alice.receive(oldRatchetMessage) }
        assertNull(alice.storage.sessions.load(BOB))

        // With the new session in place, old ratchet traffic does not touch it.
        alice.receive(envelope)
        val session = assertNotNull(alice.storage.sessions.load(BOB)).state
        assertFailsWith<ProtocolException> { alice.receive(oldRatchetMessage) }
        assertContentEquals(session, alice.storage.sessions.load(BOB)?.state)

        // Even if the user went back to the old identity, its session never returns: its initiation is retired.
        alice.client.acceptRemoteIdentityChange(RemoteIdentityChange(BOB, newBob.identityKey(), oldBob.identityKey()))
        assertTrue(alice.storage.sessionInitiations.isRetired(BOB, oldInitiation))
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { alice.receive(oldPreKeyMessage) }
        assertNull(alice.storage.sessions.load(BOB))
    }

    @Test
    fun pendingMessagesSurviveAcceptanceAndAreRetriedUnderTheNewIdentity() = runTest {
        val (alice, oldBob) = conversation()
        val processed = oldBob.send(alice, "from the old phone").id
        alice.acceptOne()
        oldBob.receiveOne()
        val sent = alice.send(oldBob, "lost with the old phone")
        network.receive(BOB) // never delivered
        assertEquals(listOf(sent.id), alice.pending(oldBob))

        val newBob = reinstalledBob()
        val (envelope, changed) = identityChange(alice, newBob)
        alice.client.acceptRemoteIdentityChange(changed.change)
        assertEquals(listOf(sent.id), alice.pending(newBob), "acceptance keeps pending messages")
        assertEquals("lost with the old phone", alice.client.pendingMessages(BOB).single().plaintext.decodeToString())

        assertTrue(alice.storage.processedInbound.isProcessed(BOB, processed), "processed IDs are kept")

        alice.commit(alice.receive(envelope))
        assertIs<ReceiveResult.Acknowledgement>(newBob.receiveOne())

        assertEquals(listOf(sent.id), alice.client.retryPendingMessages(BOB))
        val resent = network.sent.last()
        assertEquals(BOB, resent.recipient)
        assertNotEquals(sent.envelope.id, resent.id, "a new envelope")
        assertFalse(sent.envelope.payload.contentEquals(resent.payload), "fresh ciphertext")

        val result = newBob.receive(newBob.inbox().single())
        val delivered = result.delivery()
        assertEquals(sent.id, delivered.id, "same logical ID")
        assertEquals("lost with the old phone", delivered.plaintext.decodeToString())
        newBob.commit(result)
        val ack = assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne())
        assertEquals(sent.id, ack.id)
        assertTrue(ack.cleared)
        assertEquals(emptyList(), alice.pending(newBob))
    }

    @Test
    fun concurrentAcceptancesOfDifferentKeysLetExactlyOneWin() = runTest {
        val (alice, oldBob) = conversation()
        val two = reinstalledBob().identityKey()
        val three = reinstalledBob().identityKey()
        val changes = listOf(RemoteIdentityChange(BOB, oldBob.identityKey(), two), RemoteIdentityChange(BOB, oldBob.identityKey(), three))

        val results = changes.map { change -> async { runCatching { alice.client.acceptRemoteIdentityChange(change) } } }.awaitAll()
        assertEquals(1, results.count { it.isSuccess })
        assertIs<SecureMessageClientException.RemoteIdentityConflict>(results.single { it.isFailure }.exceptionOrNull())
        val winner = changes[results.indexOfFirst { it.isSuccess }].presentedIdentityKey
        assertEquals(RemoteIdentityTrust(BOB, winner, VerificationState.UNVERIFIED), alice.trust())

        // The same change again is based on a pin that is gone.
        assertFailsWith<SecureMessageClientException.RemoteIdentityConflict> {
            alice.client.acceptRemoteIdentityChange(changes[results.indexOfFirst { it.isSuccess }])
        }
        assertEquals(winner, alice.trust()?.identityKey)
    }

    @Test
    fun acceptanceNeedsAPinAndTwoDifferentKeys() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        assertFailsWith<SecureMessageClientException.RemoteIdentityNotKnown> {
            alice.client.acceptRemoteIdentityChange(RemoteIdentityChange(BOB, alice.identityKey(), bob.identityKey()))
        }
        assertNull(alice.trust())
        assertFailsWith<IllegalArgumentException> { RemoteIdentityChange(BOB, bob.identityKey(), bob.identityKey()) }
    }

    @Test
    fun failedAcceptanceChangesNothing() = runTest {
        val (alice, oldBob) = conversation()
        alice.client.markRemoteIdentityVerified(alice.client.safetyNumber(BOB))
        val oldInitiation = assertNotNull(alice.initiationWith(oldBob))
        val session = assertNotNull(alice.storage.sessions.load(BOB)).state
        val (_, changed) = identityChange(alice, reinstalledBob())

        val failures = listOf<(Boolean) -> Unit>(
            { alice.failing.failRetire = it },
            { alice.failing.failSessionRemoval = it },
            { alice.failing.failRemoteIdentityReplace = it },
        )
        for (fail in failures) {
            fail(true)
            assertFailsWith<StorageFailure> { alice.client.acceptRemoteIdentityChange(changed.change) }
            fail(false)
            assertEquals(RemoteIdentityTrust(BOB, oldBob.identityKey(), VerificationState.VERIFIED), alice.trust())
            assertContentEquals(session, alice.storage.sessions.load(BOB)?.state)
            assertFalse(alice.storage.sessionInitiations.isRetired(BOB, oldInitiation))
        }

        alice.client.acceptRemoteIdentityChange(changed.change)
        assertEquals(changed.presentedIdentityKey, alice.trust()?.identityKey)
    }
}
