package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
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
        val aliceSession = engine.initiateSession(alice.identity, alice.address, bob.bundle())
        val first = engine.encrypt(aliceSession, "hi".encodeToByteArray())
        val accepted = engine.accept(bob, alice.address, assertIs<PreKeyMessage>(first.message))
        return first.updatedSession to accepted.session
    }

    private fun RatchetMessage.tampered() = RatchetMessage(
        bytes.copyOf().also { it[it.lastIndex] = (it[it.lastIndex].toInt() xor 1).toByte() },
    )

    @Test
    fun tamperedCiphertextFailsAndKeepsSessionUsable() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (aliceSession, bobSession) = establish(alice, bob)
        val message = assertIs<RatchetMessage>(engine.encrypt(bobSession, "secret".encodeToByteArray()).message)

        assertFailsWith<ProtocolException.DecryptionFailed> { engine.decrypt(aliceSession, message.tampered(), alice.identity.publicKey) }

        assertEquals("secret", engine.decrypt(aliceSession, message, alice.identity.publicKey).plaintext.decodeToString())
    }

    @Test
    fun truncatedRatchetMessageIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (aliceSession, _) = establish(alice, bob)

        assertFailsWith<ProtocolException.InvalidMessage> {
            engine.decrypt(aliceSession, RatchetMessage(ByteArray(10)), alice.identity.publicKey)
        }
    }

    @Test
    fun invalidSignedPreKeySignatureIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bundle = engine.party(BOB).bundle()
        val signature = bundle.signedPreKey.signature.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val tampered = bundle.copy(signedPreKey = bundle.signedPreKey.copy(signature = signature))

        assertFailsWith<ProtocolException.InvalidSignature> { engine.initiateSession(alice.identity, alice.address, tampered) }
    }

    @Test
    fun signedPreKeyFromAnotherIdentityIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val carol = engine.party(carolAddress)
        val forged = bob.bundle().copy(signedPreKey = carol.signedPreKey.toPublic())

        assertFailsWith<ProtocolException.InvalidSignature> { engine.initiateSession(alice.identity, alice.address, forged) }
    }

    @Test
    fun malformedBundleKeyIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bundle = engine.party(BOB).bundle().copy(identityKey = ByteArray(12))

        assertFailsWith<ProtocolException.InvalidPreKeyBundle> { engine.initiateSession(alice.identity, alice.address, bundle) }
    }

    @Test
    fun exportedStateRestoresEquivalentSession() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (aliceSession, bobSession) = establish(alice, bob)
        val message = engine.encrypt(bobSession, "round trip".encodeToByteArray()).message

        val live = engine.decrypt(aliceSession, message, alice.identity.publicKey)
        val restored = engine.decrypt(aliceSession.persistAndRestore(), message, alice.identity.publicKey)

        assertEquals("round trip", live.plaintext.decodeToString())
        assertEquals("round trip", restored.plaintext.decodeToString())
        assertEquals(aliceSession.remote, restored.updatedSession.remote)
    }

    @Test
    fun corruptedSessionStateIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (aliceSession, _) = establish(alice, bob)
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
        val aliceSession = engine.initiateSession(alice.identity, alice.address, bob.bundle())
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

        val fromCarol = engine.decrypt(carolSession, engine.encrypt(bobWithCarol, "hi".encodeToByteArray()).message, carol.identity.publicKey)
        val carolMessage = engine.encrypt(fromCarol.updatedSession, "to Bob".encodeToByteArray()).message

        assertFailsWith<ProtocolException.DecryptionFailed> { engine.decrypt(bobWithAlice, carolMessage, bob.identity.publicKey) }
    }

    @Test
    fun preKeyMessageFromOtherIdentityOnExistingSessionIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val carol = engine.party(carolAddress)
        val (_, bobWithAlice) = establish(alice, bob)
        val carolSession = engine.initiateSession(carol.identity, carol.address, bob.bundle())
        val carolMessage = engine.encrypt(carolSession, "hi".encodeToByteArray()).message

        assertFailsWith<ProtocolException.InvalidMessage> { engine.decrypt(bobWithAlice, carolMessage, bob.identity.publicKey) }
    }

    @Test
    fun oneTimePreKeyIdSurvivesBundleAndMessage() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val bundle = bob.bundle()
        val aliceSession = engine.initiateSession(alice.identity, alice.address, bundle)
        val message = assertIs<PreKeyMessage>(engine.encrypt(aliceSession, "hi".encodeToByteArray()).message)

        assertEquals(bob.signedPreKey.id, message.signedPreKeyId)
        assertEquals(bundle.oneTimePreKey?.id, message.oneTimePreKeyId)
        assertEquals(bundle.oneTimePreKey?.id, engine.accept(bob, ALICE, message).consumedOneTimePreKeyId)
    }

    @Test
    fun sessionWithoutOneTimePreKey() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val aliceSession = engine.initiateSession(alice.identity, alice.address, bob.bundle(withOneTimePreKey = false))
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
        val aliceSession = engine.initiateSession(alice.identity, alice.address, bob.bundle())
        val message = assertIs<PreKeyMessage>(engine.encrypt(aliceSession, "hi".encodeToByteArray()).message)

        assertFailsWith<ProtocolException.InvalidMessage> {
            engine.acceptSession(bob.identity, BOB, ALICE, bob.signedPreKey, bob.oneTimePreKeys[1], message)
        }
        assertFailsWith<ProtocolException.InvalidMessage> {
            engine.acceptSession(bob.identity, BOB, ALICE, bob.signedPreKey, null, message)
        }
    }

    @Test
    fun generatedPublicMaterialMatchesPreKeyFormat() = runTest {
        val bob = engine.party(BOB)
        val publication = PreKeyPublication(
            address = BOB,
            identityKey = bob.identity.publicKey,
            signedPreKey = bob.signedPreKey.toPublic(),
            oneTimePreKeys = bob.oneTimePreKeys.map { it.toPublic() },
        )
        assertEquals(PreKeyFormat.PUBLIC_KEY_SIZE, publication.identityKey.size)
        assertEquals(PreKeyFormat.SIGNATURE_SIZE, publication.signedPreKey.signature.size)
        PreKeyFormat.validate(publication)

        assertFailsWith<IllegalArgumentException> {
            PreKeyFormat.validate(publication.copy(identityKey = publication.identityKey.copyOf(32)))
        }
        assertFailsWith<IllegalArgumentException> {
            PreKeyFormat.validate(
                publication.copy(signedPreKey = publication.signedPreKey.copy(signature = ByteArray(63))),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            PreKeyFormat.validate(publication.copy(oneTimePreKeys = publication.oneTimePreKeys + publication.oneTimePreKeys[0]))
        }
        assertFailsWith<IllegalArgumentException> {
            val tooMany = List(PreKeyFormat.MAX_ONE_TIME_PRE_KEYS_PER_PUBLICATION + 1) {
                PublicOneTimePreKey(OneTimePreKeyId(it), ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE))
            }
            PreKeyFormat.validate(publication.copy(oneTimePreKeys = tooMany))
        }
    }
}
