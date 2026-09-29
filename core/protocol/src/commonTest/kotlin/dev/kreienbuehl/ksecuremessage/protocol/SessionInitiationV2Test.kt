package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

/**
 * Session initiation v2 at the engine level (S1, findings F3, F4 and F9;
 * docs/security-review-remediation.md). A relay must not be able to change
 * any byte an initiation ID or the sender binding depends on without the
 * first message failing to decrypt.
 */
class SessionInitiationV2Test {
    private val engine: ProtocolEngine = KodiumProtocolEngine()
    private val mallory = DeviceAddress(UserId("mallory"), DeviceId("phone"))

    private suspend fun firstMessage(alice: Party, bob: Party, withOneTimePreKey: Boolean = true): Pair<SecureSession, PreKeyMessage> {
        val first = engine.encrypt(engine.initiateSession(alice.identity, alice.address, bob.bundle(withOneTimePreKey)), "hi".encodeToByteArray())
        return first.updatedSession to assertIs<PreKeyMessage>(first.message)
    }

    private fun ByteArray.flipped(index: Int) = copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }

    @Test
    fun newInitiationsAreVersion2() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (session, message) = firstMessage(alice, bob)
        assertEquals(SessionInitiationVersion.V2, message.initiationVersion)
        assertEquals(SessionInitiationVersion.V2, engine.sessionInfo(session).initiationVersion)
        val accepted = engine.accept(bob, ALICE, message)
        assertEquals(SessionInitiationVersion.V2, engine.sessionInfo(accepted.session).initiationVersion)
        assertEquals(SessionInitiationId.v2Of(message, ALICE, BOB, bob.identity.publicKey), engine.sessionInfo(accepted.session).initiationId)
    }

    @Test
    fun f3MutatedEphemeralSigningHalfFailsAcceptance() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (_, message) = firstMessage(alice, bob)
        // Bytes 32..63 are the ephemeral key's Ed25519 half: X3DH never uses
        // them, and v1 hashed them into the initiation ID unauthenticated.
        for (index in listOf(32, 47, 63)) {
            val mutated = message.copy(ephemeralKey = message.ephemeralKey.flipped(index))
            assertFailsWith<ProtocolException.DecryptionFailed> { engine.accept(bob, ALICE, mutated) }
        }
        assertEquals("hi", engine.accept(bob, ALICE, message).plaintext.decodeToString(), "the original still works")
    }

    @Test
    fun f3MutatedSignedPreKeyIdFailsAcceptanceEvenWithTheSameKey() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (_, message) = firstMessage(alice, bob)
        // A receiver holding the same key under another ID: only the transcript tells them apart.
        val sameKeyOtherId = SignedPreKeyPair(SignedPreKeyId(8), bob.signedPreKey.publicKey, bob.signedPreKey.signature, bob.signedPreKey.privateKey)
        val mutated = message.copy(signedPreKeyId = SignedPreKeyId(8))
        assertFailsWith<ProtocolException.DecryptionFailed> {
            engine.acceptSession(bob.identity, BOB, ALICE, sameKeyOtherId, bob.oneTimePreKey(message.oneTimePreKeyId), mutated)
        }
    }

    @Test
    fun f3MutatedOneTimePreKeyIdFailsAcceptanceEvenWithTheSameKey() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (_, message) = firstMessage(alice, bob)
        val original = assertIs<OneTimePreKeyPair>(bob.oneTimePreKey(message.oneTimePreKeyId))
        val sameKeyOtherId = OneTimePreKeyPair(OneTimePreKeyId(original.id.value + 50), original.publicKey, original.privateKey)
        val mutated = message.copy(oneTimePreKeyId = sameKeyOtherId.id)
        assertFailsWith<ProtocolException.DecryptionFailed> {
            engine.acceptSession(bob.identity, BOB, ALICE, bob.signedPreKey, sameKeyOtherId, mutated)
        }
    }

    @Test
    fun f4RewrittenSenderFailsAcceptance() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (_, message) = firstMessage(alice, bob)
        assertFailsWith<ProtocolException.DecryptionFailed> { engine.accept(bob, mallory, message) }
    }

    @Test
    fun f4RewrittenRecipientFailsAcceptance() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (_, message) = firstMessage(alice, bob)
        val otherDevice = DeviceAddress(BOB.userId, DeviceId("phone"))
        assertFailsWith<ProtocolException.DecryptionFailed> {
            engine.acceptSession(bob.identity, otherDevice, ALICE, bob.signedPreKey, bob.oneTimePreKey(message.oneTimePreKeyId), message)
        }
    }

    @Test
    fun versionDowngradeOfTheTypeByteIsRejected() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (_, message) = firstMessage(alice, bob)
        // A relay rewrites wire type 0x03 to 0x02.
        val wire = CiphertextMessageCodec.encode(message).also { it[1] = CiphertextMessageCodec.TYPE_PREKEY_MESSAGE.toByte() }
        val downgraded = assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(wire))
        assertEquals(SessionInitiationVersion.V1, downgraded.initiationVersion)
        assertFailsWith<ProtocolException.InvalidMessage> { engine.accept(bob, ALICE, downgraded) }
        // Even a pre-S1 receiver cannot decrypt it: the associated data differs.
        assertFailsWith<Throwable> { LegacySessions.accept(bob, ALICE, downgraded) }
    }

    @Test
    fun repeatedInitiationWithAnyChangedFieldIsRejectedOnTheSession() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (aliceSession, message) = firstMessage(alice, bob)
        val bobSession = engine.accept(bob, ALICE, message).session
        val second = assertIs<PreKeyMessage>(engine.encrypt(aliceSession, "again".encodeToByteArray()).message)
        val variants = listOf(
            message.copy(ephemeralKey = message.ephemeralKey.flipped(40)),
            message.copy(signedPreKeyId = SignedPreKeyId(9)),
            message.copy(oneTimePreKeyId = null),
            message.copy(initiationVersion = SessionInitiationVersion.V1),
        )
        for (variant in variants) {
            assertFailsWith<ProtocolException.InvalidMessage> { engine.decrypt(bobSession, variant.copy(message = second.message), bob.identity.publicKey) }
        }
        // The unchanged repetition decrypts.
        assertEquals("again", engine.decrypt(bobSession, second, bob.identity.publicKey).plaintext.decodeToString())
    }

    @Test
    fun f9InitiatorNeverAcceptsAPreKeyMessageOnItsOwnSession() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (aliceSession, message) = firstMessage(alice, bob)
        val bobSession = engine.accept(bob, ALICE, message).session
        val reply = assertIs<RatchetMessage>(engine.encrypt(bobSession, "ack".encodeToByteArray()).message)
        // Bob's genuine ratchet message rewrapped with Alice's own header (a reflection).
        val reflected = message.copy(message = reply)
        assertFailsWith<ProtocolException.InvalidMessage> { engine.decrypt(aliceSession, reflected, alice.identity.publicKey) }
    }

    @Test
    fun f9LegacyInitiatorSessionRejectsARewrappedMessageNamingItsOwnIdentity() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        // A pre-S1 session Alice initiated, established (origin unknown: pre-milestone-6 format).
        val first = engine.encrypt(LegacySessions.initiate(alice.identity, bob.bundle()), "hi".encodeToByteArray())
        val bobSession = LegacySessions.accept(bob, ALICE, assertIs<PreKeyMessage>(first.message)).session
        val ack = engine.encrypt(bobSession, "ack".encodeToByteArray())
        val aliceSession = LegacySessions.encode(engine.decrypt(first.updatedSession, ack.message, alice.identity.publicKey).updatedSession, 1)
        assertNull(engine.sessionInfo(aliceSession).initiationId)

        val next = assertIs<RatchetMessage>(engine.encrypt(ack.updatedSession, "next".encodeToByteArray()).message)
        // The attack: wrap Bob's genuine ratchet message into a v1 PreKeyMessage naming Alice's own identity key.
        val wrapped = PreKeyMessage(
            alice.identity.publicKey, ByteArray(64), SignedPreKeyId(1), null, next, SessionInitiationVersion.V1,
        )
        assertFailsWith<ProtocolException.InvalidMessage> { engine.decrypt(aliceSession, wrapped, alice.identity.publicKey) }
        assertEquals("next", engine.decrypt(aliceSession, next, alice.identity.publicKey).plaintext.decodeToString(), "the session still works")
    }

    @Test
    fun sessionRemoteIdentityKeyNeverReturnsTheLocalKey() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        val (aliceSession, message) = firstMessage(alice, bob)
        val bobSession = engine.accept(bob, ALICE, message).session
        assertContentEquals(bob.identity.publicKey, engine.sessionRemoteIdentityKey(aliceSession, alice.identity.publicKey))
        assertContentEquals(alice.identity.publicKey, engine.sessionRemoteIdentityKey(bobSession, bob.identity.publicKey))

        // Legacy sessions in both roles.
        val legacy = engine.encrypt(LegacySessions.initiate(alice.identity, bob.bundle()), "hi".encodeToByteArray())
        val legacyBob = LegacySessions.accept(bob, ALICE, assertIs<PreKeyMessage>(legacy.message)).session
        assertContentEquals(bob.identity.publicKey, engine.sessionRemoteIdentityKey(LegacySessions.encode(legacy.updatedSession, 1), alice.identity.publicKey))
        assertContentEquals(alice.identity.publicKey, engine.sessionRemoteIdentityKey(LegacySessions.encode(legacyBob, 1), bob.identity.publicKey))

        // Neither slot is the local key, or both are: ambiguous, never guessed.
        val carol = engine.party(DeviceAddress(UserId("carol"), DeviceId("tablet")))
        assertNull(engine.sessionRemoteIdentityKey(aliceSession, carol.identity.publicKey))
        val selfSession = engine.encrypt(LegacySessions.initiate(alice.identity, alice.bundle()), "self".encodeToByteArray()).updatedSession
        assertNull(engine.sessionRemoteIdentityKey(selfSession, alice.identity.publicKey))
    }
}
