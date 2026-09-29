package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
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

    @Test
    fun bothSidesDeriveTheSameInitiationId() = runTest {
        for (withOneTimePreKey in listOf(true, false)) {
            val alice = engine.party(ALICE)
            val bob = engine.party(BOB)
            val pending = engine.initiateSession(alice.identity, alice.address, bob.bundle(withOneTimePreKey))
            val info = engine.sessionInfo(pending)
            assertTrue(info.awaitingReply)
            val id = assertNotNull(info.initiationId)

            val first = engine.encrypt(pending, "hi".encodeToByteArray())
            val message = assertIs<PreKeyMessage>(first.message)
            assertEquals(id, SessionInitiationId.v2Of(message, ALICE, BOB, bob.identity.publicKey))
            assertEquals(id, engine.sessionInfo(first.updatedSession.persistAndRestore()).initiationId)

            val accepted = engine.accept(bob, ALICE, message)
            val bobInfo = engine.sessionInfo(accepted.session)
            assertEquals(id, bobInfo.initiationId)
            assertFalse(bobInfo.awaitingReply)

            // The origin survives ratchet steps in both directions.
            val reply = engine.encrypt(accepted.session, "ack".encodeToByteArray())
            assertEquals(id, engine.sessionInfo(reply.updatedSession).initiationId)
            val aliceDone = engine.decrypt(first.updatedSession, reply.message, alice.identity.publicKey).updatedSession
            val aliceInfo = engine.sessionInfo(aliceDone.persistAndRestore())
            assertEquals(id, aliceInfo.initiationId)
            assertFalse(aliceInfo.awaitingReply)
        }
    }

    @Test
    fun preKeyMessageOfAnotherInitiationIsRejectedOnTheSession() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val firstSession = engine.encrypt(engine.initiateSession(alice.identity, alice.address, bob.bundle()), "one".encodeToByteArray())
        val bobSession = engine.accept(bob, ALICE, assertIs<PreKeyMessage>(firstSession.message)).session

        // Same identity, new initiation (Alice lost her session).
        val second = engine.encrypt(engine.initiateSession(alice.identity, alice.address, bob.bundle(false)), "two".encodeToByteArray())
        val error = assertFailsWith<ProtocolException.InvalidMessage> { engine.decrypt(bobSession, second.message, bob.identity.publicKey) }
        assertEquals("Prekey message belongs to another session initiation", error.message)
    }

    @Test
    fun version1PendingStateDerivesItsOrigin() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val pending = LegacySessions.initiate(alice.identity, bob.bundle())
        val legacy = LegacySessions.encode(pending, 1)
        assertEquals(1, legacy.state[0].toInt())

        val info = engine.sessionInfo(legacy)
        assertEquals(engine.sessionInfo(pending).initiationId, info.initiationId)
        assertTrue(info.awaitingReply)
        assertEquals(SessionInitiationVersion.V1, info.initiationVersion)

        // Still usable, rewritten in the current format, and still a version 1 initiation.
        val encrypted = engine.encrypt(legacy, "hi".encodeToByteArray())
        assertEquals(4, encrypted.updatedSession.state[0].toInt())
        val message = assertIs<PreKeyMessage>(encrypted.message)
        assertEquals(SessionInitiationVersion.V1, message.initiationVersion)
        val accepted = LegacySessions.accept(bob, ALICE, message)
        assertEquals(info.initiationId, engine.sessionInfo(accepted.session).initiationId)
    }

    @Test
    fun version1EstablishedStateHasNoOrigin() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val first = engine.encrypt(LegacySessions.initiate(alice.identity, bob.bundle()), "hi".encodeToByteArray())
        val accepted = LegacySessions.accept(bob, ALICE, assertIs<PreKeyMessage>(first.message))
        val legacy = LegacySessions.encode(accepted.session, 1)

        val info = engine.sessionInfo(legacy)
        assertNull(info.initiationId, "an origin is never invented")
        assertFalse(info.awaitingReply)

        val reply = engine.encrypt(legacy, "ack".encodeToByteArray())
        assertNull(engine.sessionInfo(reply.updatedSession).initiationId)
        assertEquals("ack", engine.decrypt(first.updatedSession, reply.message, alice.identity.publicKey).plaintext.decodeToString())
    }

    @Test
    fun malformedOriginIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val state = engine.initiateSession(alice.identity, alice.address, bob.bundle()).state
        // Version 4 layout: version | initiation version | associatedData | initiator key
        // | responder key | pending | initiation | origin flag | ...
        val header = 1 + (4 + 64) + (4 + 64) + 4 + 1 + 4
        val flagOffset = 1 + 1 + 4 + SessionState.decode(state).associatedData.size + 2 * (4 + 64) + 2 * header
        assertEquals(1, state[flagOffset].toInt())
        val corrupted = state.copyOf().also { it[flagOffset] = 2 }
        assertFailsWith<ProtocolException.InvalidSessionState> { engine.sessionInfo(SecureSession(BOB, corrupted)) }
        assertFailsWith<ProtocolException.InvalidSessionState> { engine.sessionInfo(SecureSession(BOB, byteArrayOf(4))) }
    }

    @Test
    fun responderSessionRecordsTheAcceptedSignedPreKey() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val first = engine.encrypt(engine.initiateSession(alice.identity, alice.address, bob.bundle()), "hi".encodeToByteArray())
        assertNull(engine.sessionInfo(first.updatedSession).acceptedSignedPreKeyId, "the initiator used a remote key")

        val accepted = engine.accept(bob, ALICE, assertIs<PreKeyMessage>(first.message))
        assertEquals(bob.signedPreKey.id, engine.sessionInfo(accepted.session).acceptedSignedPreKeyId)

        // Kept across ratchet steps and restarts.
        val reply = engine.encrypt(accepted.session, "ack".encodeToByteArray())
        val restored = reply.updatedSession.persistAndRestore()
        assertEquals(bob.signedPreKey.id, engine.sessionInfo(restored).acceptedSignedPreKeyId)
        val aliceDone = engine.decrypt(first.updatedSession, reply.message, alice.identity.publicKey).updatedSession
        assertNull(engine.sessionInfo(aliceDone).acceptedSignedPreKeyId)
        val next = engine.encrypt(aliceDone, "again".encodeToByteArray())
        val bobNext = engine.decrypt(restored, next.message, bob.identity.publicKey).updatedSession
        assertEquals(bob.signedPreKey.id, engine.sessionInfo(bobNext).acceptedSignedPreKeyId)
    }

    @Test
    fun version2StateHasNoAcceptedSignedPreKey() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val first = engine.encrypt(LegacySessions.initiate(alice.identity, bob.bundle()), "hi".encodeToByteArray())
        val accepted = LegacySessions.accept(bob, ALICE, assertIs<PreKeyMessage>(first.message))
        val legacy = LegacySessions.encode(accepted.session, 2)
        assertEquals(2, legacy.state[0].toInt())

        val info = engine.sessionInfo(legacy)
        assertEquals(engine.sessionInfo(accepted.session).initiationId, info.initiationId, "the origin is kept")
        assertNull(info.acceptedSignedPreKeyId, "never invented for an old state")

        val reply = engine.encrypt(legacy, "ack".encodeToByteArray())
        assertEquals(4, reply.updatedSession.state[0].toInt())
        assertNull(engine.sessionInfo(reply.updatedSession).acceptedSignedPreKeyId)
        assertEquals("ack", engine.decrypt(first.updatedSession, reply.message, alice.identity.publicKey).plaintext.decodeToString())
    }

    @Test
    fun independentInitiationsHaveDifferentIds() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val one = engine.sessionInfo(engine.initiateSession(alice.identity, alice.address, bob.bundle())).initiationId
        val two = engine.sessionInfo(engine.initiateSession(alice.identity, alice.address, bob.bundle())).initiationId
        assertNotEquals(one, two, "a fresh ephemeral key per initiation")
    }
}
