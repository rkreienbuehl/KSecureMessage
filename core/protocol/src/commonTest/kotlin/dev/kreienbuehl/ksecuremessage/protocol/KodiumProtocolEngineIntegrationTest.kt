package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

internal val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
internal val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))

/** Local key material of one test participant. */
internal class Party(
    val address: DeviceAddress,
    val identity: LocalIdentity,
    val signedPreKey: SignedPreKeyPair,
    val oneTimePreKeys: List<OneTimePreKeyPair>,
) {
    fun bundle(withOneTimePreKey: Boolean = true) = PreKeyBundle(
        address = address,
        identityKey = identity.publicKey,
        signedPreKey = signedPreKey.toPublic(),
        oneTimePreKey = if (withOneTimePreKey) oneTimePreKeys.first().toPublic() else null,
    )

    fun oneTimePreKey(id: OneTimePreKeyId?) = id?.let { wanted -> oneTimePreKeys.single { it.id == wanted } }
}

internal suspend fun ProtocolEngine.party(address: DeviceAddress): Party {
    val identity = createIdentity()
    return Party(
        address = address,
        identity = identity,
        signedPreKey = createSignedPreKey(identity, SignedPreKeyId(1)),
        oneTimePreKeys = createOneTimePreKeys(OneTimePreKeyId(100), 3),
    )
}

internal suspend fun ProtocolEngine.accept(receiver: Party, sender: DeviceAddress, message: PreKeyMessage) =
    acceptSession(
        localIdentity = receiver.identity,
        localAddress = receiver.address,
        remote = sender,
        signedPreKey = receiver.signedPreKey,
        oneTimePreKey = receiver.oneTimePreKey(message.oneTimePreKeyId),
        message = message,
    )

/** Simulates persisting and reloading: only the opaque bytes survive. */
internal fun SecureSession.persistAndRestore(): SecureSession = SecureSession(remote, state.copyOf())

class KodiumProtocolEngineIntegrationTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()

    @Test
    fun aliceAndBobExchangeMessagesAcrossPersistence() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)

        // Alice starts the session from Bob's published bundle.
        var aliceSession = engine.initiateSession(alice.identity, alice.address, bob.bundle())
        val first = engine.encrypt(aliceSession, "Hello Bob".encodeToByteArray())
        aliceSession = first.updatedSession
        val preKeyMessage = assertIs<PreKeyMessage>(first.message)

        // Bob sets up his side from the prekey message.
        val accepted = engine.accept(bob, ALICE, preKeyMessage)
        var bobSession = accepted.session
        assertEquals("Hello Bob", accepted.plaintext.decodeToString())
        assertEquals(bob.oneTimePreKeys.first().id, accepted.consumedOneTimePreKeyId)

        // Bob replies.
        val reply = engine.encrypt(bobSession, "Hello Alice".encodeToByteArray())
        bobSession = reply.updatedSession
        val replyMessage = assertIs<RatchetMessage>(reply.message)
        val replyDecrypted = engine.decrypt(aliceSession, replyMessage, alice.identity.publicKey)
        aliceSession = replyDecrypted.updatedSession
        assertEquals("Hello Alice", replyDecrypted.plaintext.decodeToString())

        // Persist both sessions and continue only from the restored state.
        aliceSession = aliceSession.persistAndRestore()
        bobSession = bobSession.persistAndRestore()

        val third = engine.encrypt(aliceSession, "Still there?".encodeToByteArray())
        aliceSession = third.updatedSession
        val thirdMessage = assertIs<RatchetMessage>(third.message)
        val thirdDecrypted = engine.decrypt(bobSession, thirdMessage, bob.identity.publicKey)
        bobSession = thirdDecrypted.updatedSession
        assertEquals("Still there?", thirdDecrypted.plaintext.decodeToString())

        val fourth = engine.encrypt(bobSession, "Yes!".encodeToByteArray())
        val fourthDecrypted = engine.decrypt(aliceSession, fourth.message, alice.identity.publicKey)
        assertEquals("Yes!", fourthDecrypted.plaintext.decodeToString())
    }

    @Test
    fun pendingPreKeyStateSurvivesPersistenceUntilFirstReply() = runTest {
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)

        var aliceSession = engine.initiateSession(alice.identity, alice.address, bob.bundle())
        val first = engine.encrypt(aliceSession, "one".encodeToByteArray())
        aliceSession = first.updatedSession.persistAndRestore()
        val second = engine.encrypt(aliceSession, "two".encodeToByteArray())
        aliceSession = second.updatedSession

        val firstMessage = assertIs<PreKeyMessage>(first.message)
        val secondMessage = assertIs<PreKeyMessage>(second.message)
        assertEquals(firstMessage.signedPreKeyId, secondMessage.signedPreKeyId)
        assertEquals(firstMessage.oneTimePreKeyId, secondMessage.oneTimePreKeyId)

        val accepted = engine.accept(bob, ALICE, firstMessage)
        assertEquals("one", accepted.plaintext.decodeToString())
        val secondDecrypted = engine.decrypt(accepted.session.persistAndRestore(), secondMessage, bob.identity.publicKey)
        assertEquals("two", secondDecrypted.plaintext.decodeToString())

        val reply = engine.encrypt(secondDecrypted.updatedSession, "ack".encodeToByteArray())
        aliceSession = engine.decrypt(aliceSession, reply.message, alice.identity.publicKey).updatedSession.persistAndRestore()

        assertIs<RatchetMessage>(engine.encrypt(aliceSession, "three".encodeToByteArray()).message)
    }
}
