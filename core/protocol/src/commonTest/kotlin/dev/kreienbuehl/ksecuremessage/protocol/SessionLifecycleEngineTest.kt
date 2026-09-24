package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Session origin (initiation ID) handling of the engine and the local state format. */
class SessionLifecycleEngineTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()

    /** Re-encodes [session] in the version 1 state format (before milestone 6). */
    private fun SecureSession.asVersion1(): SecureSession {
        val state = SessionState.decode(state)
        val out = BinaryWriter()
        out.byte(1)
        out.bytes(state.associatedData)
        val pending = state.pending
        if (pending == null) {
            out.byte(0)
        } else {
            out.byte(1)
            out.bytes(pending.identityKey)
            out.bytes(pending.ephemeralKey)
            out.int(pending.signedPreKeyId.value)
            val oneTimePreKeyId = pending.oneTimePreKeyId
            if (oneTimePreKeyId == null) out.byte(0) else { out.byte(1); out.int(oneTimePreKeyId.value) }
        }
        out.bytes(state.ratchet)
        return copy(state = out.toByteArray())
    }

    @Test
    fun bothSidesDeriveTheSameInitiationId() = runTest {
        for (withOneTimePreKey in listOf(true, false)) {
            val alice = engine.party(ALICE)
            val bob = engine.party(BOB)
            val pending = engine.initiateSession(alice.identity, bob.bundle(withOneTimePreKey))
            val info = engine.sessionInfo(pending)
            assertTrue(info.awaitingReply)
            val id = assertNotNull(info.initiationId)

            val first = engine.encrypt(pending, "hi".encodeToByteArray())
            val message = assertIs<PreKeyMessage>(first.message)
            assertEquals(id, SessionInitiationId.of(message, bob.identity.publicKey))
            assertEquals(id, engine.sessionInfo(first.updatedSession.persistAndRestore()).initiationId)

            val accepted = engine.accept(bob, ALICE, message)
            val bobInfo = engine.sessionInfo(accepted.session)
            assertEquals(id, bobInfo.initiationId)
            assertFalse(bobInfo.awaitingReply)

            // The origin survives ratchet steps in both directions.
            val reply = engine.encrypt(accepted.session, "ack".encodeToByteArray())
            assertEquals(id, engine.sessionInfo(reply.updatedSession).initiationId)
            val aliceDone = engine.decrypt(first.updatedSession, reply.message).updatedSession
            val aliceInfo = engine.sessionInfo(aliceDone.persistAndRestore())
            assertEquals(id, aliceInfo.initiationId)
            assertFalse(aliceInfo.awaitingReply)
        }
    }

    @Test
    fun preKeyMessageOfAnotherInitiationIsRejectedOnTheSession() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val firstSession = engine.encrypt(engine.initiateSession(alice.identity, bob.bundle()), "one".encodeToByteArray())
        val bobSession = engine.accept(bob, ALICE, assertIs<PreKeyMessage>(firstSession.message)).session

        // Same identity, new initiation (Alice lost her session).
        val second = engine.encrypt(engine.initiateSession(alice.identity, bob.bundle(false)), "two".encodeToByteArray())
        val error = assertFailsWith<ProtocolException.InvalidMessage> { engine.decrypt(bobSession, second.message) }
        assertEquals("Prekey message belongs to another session initiation", error.message)
    }

    @Test
    fun version1PendingStateDerivesItsOrigin() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val pending = engine.initiateSession(alice.identity, bob.bundle())
        val legacy = pending.asVersion1()
        assertEquals(1, legacy.state[0].toInt())

        val info = engine.sessionInfo(legacy)
        assertEquals(engine.sessionInfo(pending).initiationId, info.initiationId)
        assertTrue(info.awaitingReply)

        // Still usable, and rewritten in the current format.
        val encrypted = engine.encrypt(legacy, "hi".encodeToByteArray())
        assertEquals(2, encrypted.updatedSession.state[0].toInt())
        val accepted = engine.accept(bob, ALICE, assertIs<PreKeyMessage>(encrypted.message))
        assertEquals(info.initiationId, engine.sessionInfo(accepted.session).initiationId)
    }

    @Test
    fun version1EstablishedStateHasNoOrigin() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val first = engine.encrypt(engine.initiateSession(alice.identity, bob.bundle()), "hi".encodeToByteArray())
        val accepted = engine.accept(bob, ALICE, assertIs<PreKeyMessage>(first.message))
        val legacy = accepted.session.asVersion1()

        val info = engine.sessionInfo(legacy)
        assertNull(info.initiationId, "an origin is never invented")
        assertFalse(info.awaitingReply)

        val reply = engine.encrypt(legacy, "ack".encodeToByteArray())
        assertNull(engine.sessionInfo(reply.updatedSession).initiationId)
        assertEquals("ack", engine.decrypt(first.updatedSession, reply.message).plaintext.decodeToString())
    }

    @Test
    fun malformedOriginIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val state = engine.initiateSession(alice.identity, bob.bundle()).state
        // Version 2 layout: version | associatedData | pending | origin flag | ...
        val flagOffset = 1 + 4 + 128 + 1 + (4 + 64) + (4 + 64) + 4 + 1 + 4
        assertEquals(1, state[flagOffset].toInt())
        val corrupted = state.copyOf().also { it[flagOffset] = 2 }
        assertFailsWith<ProtocolException.InvalidSessionState> { engine.sessionInfo(SecureSession(BOB, corrupted)) }
        assertFailsWith<ProtocolException.InvalidSessionState> { engine.sessionInfo(SecureSession(BOB, byteArrayOf(3))) }
    }

    @Test
    fun independentInitiationsHaveDifferentIds() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val one = engine.sessionInfo(engine.initiateSession(alice.identity, bob.bundle())).initiationId
        val two = engine.sessionInfo(engine.initiateSession(alice.identity, bob.bundle())).initiationId
        assertNotEquals(one, two, "a fresh ephemeral key per initiation")
    }
}
