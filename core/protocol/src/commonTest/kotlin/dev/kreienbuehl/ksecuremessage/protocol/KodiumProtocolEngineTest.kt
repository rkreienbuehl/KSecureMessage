package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.UserId
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

class KodiumProtocolEngineTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()
    private val carolAddress = DeviceAddress(UserId("carol"), DeviceId("tablet"))

    private suspend fun establish(alice: Party, bob: Party): Pair<SecureSession, SecureSession> {
        val aliceSession = engine.initiateSession(alice.identity, bob.bundle())
        val first = engine.encrypt(aliceSession, "hi".encodeToByteArray())
        val accepted = engine.accept(bob, alice.address, assertIs<PreKeyMessage>(first.message))
        return first.updatedSession to accepted.session
    }

    private fun RatchetMessage.tampered() = RatchetMessage(
        bytes.copyOf().also { it[it.lastIndex] = (it[it.lastIndex].toInt() xor 1).toByte() },
    )

    @Test
    fun tamperedCiphertextFailsAndKeepsSessionUsable() = runTest {
        val (aliceSession, bobSession) = establish(engine.party(ALICE), engine.party(BOB))
        val message = assertIs<RatchetMessage>(engine.encrypt(bobSession, "secret".encodeToByteArray()).message)

        assertFailsWith<ProtocolException.DecryptionFailed> { engine.decrypt(aliceSession, message.tampered()) }

        assertEquals("secret", engine.decrypt(aliceSession, message).plaintext.decodeToString())
    }

    @Test
    fun truncatedRatchetMessageIsRejected() = runTest {
        val (aliceSession, _) = establish(engine.party(ALICE), engine.party(BOB))

        assertFailsWith<ProtocolException.InvalidMessage> {
            engine.decrypt(aliceSession, RatchetMessage(ByteArray(10)))
        }
    }

    @Test
    fun invalidSignedPreKeySignatureIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bundle = engine.party(BOB).bundle()
        val signature = bundle.signedPreKey.signature.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val tampered = bundle.copy(signedPreKey = bundle.signedPreKey.copy(signature = signature))

        assertFailsWith<ProtocolException.InvalidSignature> { engine.initiateSession(alice.identity, tampered) }
    }

    @Test
    fun signedPreKeyFromAnotherIdentityIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val carol = engine.party(carolAddress)
        val forged = bob.bundle().copy(signedPreKey = carol.signedPreKey.toPublic())

        assertFailsWith<ProtocolException.InvalidSignature> { engine.initiateSession(alice.identity, forged) }
    }

    @Test
    fun malformedBundleKeyIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bundle = engine.party(BOB).bundle().copy(identityKey = ByteArray(12))

        assertFailsWith<ProtocolException.InvalidPreKeyBundle> { engine.initiateSession(alice.identity, bundle) }
    }

    @Test
    fun exportedStateRestoresEquivalentSession() = runTest {
        val (aliceSession, bobSession) = establish(engine.party(ALICE), engine.party(BOB))
        val message = engine.encrypt(bobSession, "round trip".encodeToByteArray()).message

        val live = engine.decrypt(aliceSession, message)
        val restored = engine.decrypt(aliceSession.persistAndRestore(), message)

        assertEquals("round trip", live.plaintext.decodeToString())
        assertEquals("round trip", restored.plaintext.decodeToString())
        assertEquals(aliceSession.remote, restored.updatedSession.remote)
    }

    @Test
    fun corruptedSessionStateIsRejected() = runTest {
        val (aliceSession, _) = establish(engine.party(ALICE), engine.party(BOB))
        val corrupted = aliceSession.copy(state = aliceSession.state.copyOf(aliceSession.state.size - 1))

        assertFailsWith<ProtocolException.InvalidSessionState> {
            engine.encrypt(corrupted, "x".encodeToByteArray())
        }
    }

    @Test
    fun differentIdentityCannotAcceptPreKeyMessage() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val carol = engine.party(carolAddress)
        val aliceSession = engine.initiateSession(alice.identity, bob.bundle())
        val message = assertIs<PreKeyMessage>(engine.encrypt(aliceSession, "for Bob".encodeToByteArray()).message)

        // Carol uses the same prekey IDs, but her keys derive a different secret.
        assertFailsWith<ProtocolException.DecryptionFailed> { engine.accept(carol, ALICE, message) }
    }

    @Test
    fun messageFromAnotherSessionIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val carol = engine.party(carolAddress)
        val (_, bobWithAlice) = establish(alice, bob)
        val (carolSession, bobWithCarol) = establish(carol, bob)

        val fromCarol = engine.decrypt(carolSession, engine.encrypt(bobWithCarol, "hi".encodeToByteArray()).message)
        val carolMessage = engine.encrypt(fromCarol.updatedSession, "to Bob".encodeToByteArray()).message

        assertFailsWith<ProtocolException.DecryptionFailed> { engine.decrypt(bobWithAlice, carolMessage) }
    }

    @Test
    fun preKeyMessageFromOtherIdentityOnExistingSessionIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val carol = engine.party(carolAddress)
        val (_, bobWithAlice) = establish(alice, bob)
        val carolSession = engine.initiateSession(carol.identity, bob.bundle())
        val carolMessage = engine.encrypt(carolSession, "hi".encodeToByteArray()).message

        assertFailsWith<ProtocolException.InvalidMessage> { engine.decrypt(bobWithAlice, carolMessage) }
    }

    @Test
    fun oneTimePreKeyIdSurvivesBundleAndMessage() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val bundle = bob.bundle()
        val aliceSession = engine.initiateSession(alice.identity, bundle)
        val message = assertIs<PreKeyMessage>(engine.encrypt(aliceSession, "hi".encodeToByteArray()).message)

        assertEquals(bob.signedPreKey.id, message.signedPreKeyId)
        assertEquals(bundle.oneTimePreKey?.id, message.oneTimePreKeyId)
        assertEquals(bundle.oneTimePreKey?.id, engine.accept(bob, ALICE, message).consumedOneTimePreKeyId)
    }

    @Test
    fun sessionWithoutOneTimePreKey() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val aliceSession = engine.initiateSession(alice.identity, bob.bundle(withOneTimePreKey = false))
        val message = assertIs<PreKeyMessage>(engine.encrypt(aliceSession, "hi".encodeToByteArray()).message)

        assertNull(message.oneTimePreKeyId)
        val accepted = engine.accept(bob, ALICE, message)
        assertEquals("hi", accepted.plaintext.decodeToString())
        assertNull(accepted.consumedOneTimePreKeyId)
    }

    @Test
    fun mismatchedPreKeyIdsAreRejected() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val aliceSession = engine.initiateSession(alice.identity, bob.bundle())
        val message = assertIs<PreKeyMessage>(engine.encrypt(aliceSession, "hi".encodeToByteArray()).message)

        assertFailsWith<ProtocolException.InvalidMessage> {
            engine.acceptSession(bob.identity, ALICE, bob.signedPreKey, bob.oneTimePreKeys[1], message)
        }
        assertFailsWith<ProtocolException.InvalidMessage> {
            engine.acceptSession(bob.identity, ALICE, bob.signedPreKey, null, message)
        }
    }
}
