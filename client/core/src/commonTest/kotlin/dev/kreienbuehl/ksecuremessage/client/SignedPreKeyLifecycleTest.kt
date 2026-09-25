package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.storage.SignedPreKeyInfo
import dev.kreienbuehl.ksecuremessage.storage.inmemory.InMemoryClientStorage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds

/**
 * Milestone 7 signed prekey lifecycle (docs/signed-prekey-lifecycle.md):
 * rotation, grace period, expiry, deletion, pruning of retired initiations,
 * restarts, clock changes and failure atomicity. Time comes from a
 * [ManualClock]; nothing sleeps.
 */
class SignedPreKeyLifecycleTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()
    private val network = FakeNetwork()
    private val clock = ManualClock()
    private val start = clock.now

    private val rotationAge = 7.days
    private val grace = 30.days

    private inner class Device(
        val address: DeviceAddress,
        val configuration: PreKeyConfiguration = PreKeyConfiguration(4, rotationAge, grace),
    ) {
        val storage = InMemoryClientStorage()
        val failing = FailingClientStorage(storage)
        var client = newClient()
            private set

        private fun newClient() = SecureMessageClient(address, failing, engine, network, configuration, clock)

        /** A new client instance on the same storage, like an application restart. */
        fun restart() {
            client = newClient()
        }

        suspend fun publish(withOneTimePreKey: Boolean = true) = network.publish(client, withOneTimePreKey)

        suspend fun send(to: Device, text: String) = client.sendRaw(to.address, text.encodeToByteArray())

        suspend fun receiveOne(): EncryptedEnvelope = network.receive(address).single()

        suspend fun decryptText(envelope: EncryptedEnvelope): String = client.decryptRaw(envelope).decodeToString()

        suspend fun infos(): List<SignedPreKeyInfo> = storage.preKeys.signedPreKeyInfos()

        suspend fun currentId(): Int = assertNotNull(storage.preKeys.currentSignedPreKey()).id.value

        suspend fun hasSignedPreKey(id: Int) = storage.preKeys.signedPreKey(SignedPreKeyId(id)) != null

        suspend fun origin(remote: Device): SessionInitiationId? =
            engine.sessionInfo(assertNotNull(storage.sessions.load(remote.address))).initiationId

        suspend fun isRetired(remote: Device, id: SessionInitiationId) = storage.sessionInitiations.isRetired(remote.address, id)

        suspend fun initiationOf(envelope: EncryptedEnvelope): SessionInitiationId = SessionInitiationId.of(
            assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(envelope.payload)),
            assertNotNull(storage.identity.identity()).publicKey,
        )

        fun healthy() {
            failing.failSignedPreKeyStore = false
            failing.failSignedPreKeyRemoval = false
            failing.failRetiredPrune = false
            failing.failLegacyStamp = false
        }
    }

    private suspend fun device(address: DeviceAddress, configuration: PreKeyConfiguration? = null) =
        (if (configuration == null) Device(address) else Device(address, configuration)).also {
            it.client.initialize()
            it.publish()
        }

    private suspend fun establish(initiator: Device, responder: Device, text: String = "hello") {
        initiator.send(responder, text)
        assertEquals(text, responder.decryptText(responder.receiveOne()))
        responder.send(initiator, "re: $text")
        assertEquals("re: $text", initiator.decryptText(initiator.receiveOne()))
    }

    private suspend fun assertBidirectional(one: Device, other: Device, round: Int) {
        one.send(other, "ping $round")
        assertEquals("ping $round", other.decryptText(other.receiveOne()))
        other.send(one, "pong $round")
        assertEquals("pong $round", one.decryptText(one.receiveOne()))
    }

    /** Everything a rejected message must leave untouched. */
    private class Snapshot(
        val session: ByteArray?,
        val pin: ByteArray?,
        val oneTimePreKeys: List<Int>,
        val signedPreKeys: List<SignedPreKeyInfo>,
    )

    private suspend fun Device.snapshot(remote: Device) = Snapshot(
        session = storage.sessions.load(remote.address)?.state,
        pin = storage.remoteIdentities.identityKey(remote.address),
        oneTimePreKeys = storage.preKeys.publicOneTimePreKeys().map { it.id.value },
        signedPreKeys = infos(),
    )

    private fun assertUnchanged(expected: Snapshot, actual: Snapshot) {
        assertContentEquals(expected.session, actual.session, "session bytes unchanged")
        assertContentEquals(expected.pin, actual.pin, "pin unchanged")
        assertEquals(expected.oneTimePreKeys, actual.oneTimePreKeys, "one-time prekeys unchanged")
        assertEquals(expected.signedPreKeys, actual.signedPreKeys, "signed prekeys unchanged")
    }

    /** Alice's first message to Bob, encrypted with Bob's signed prekey 0 and held back by the network. */
    private suspend fun withheldFirstContact(alice: Device, bob: Device): EncryptedEnvelope {
        assertEquals(0, bob.currentId())
        alice.send(bob, "delayed")
        return bob.receiveOne()
    }

    // Rotation

    @Test
    fun initializeCreatesATimestampedCurrentSignedPreKey() = runTest {
        val bob = device(BOB)
        assertEquals(listOf(SignedPreKeyInfo(SignedPreKeyId(0), true, start, null)), bob.infos())

        clock.advanceBy(1.days)
        bob.client.initialize()
        assertEquals(listOf(SignedPreKeyInfo(SignedPreKeyId(0), true, start, null)), bob.infos(), "nothing is due yet")
    }

    @Test
    fun rotationKeepsThePreviousKeyInGraceAndPublishesOnlyWhenAsked() = runTest {
        val bob = device(BOB)
        clock.advanceBy(1.days)
        val rotated = bob.client.rotateSignedPreKey()

        assertEquals(SignedPreKeyId(1), rotated.id)
        assertEquals(
            listOf(
                SignedPreKeyInfo(SignedPreKeyId(0), false, start, start + 1.days),
                SignedPreKeyInfo(SignedPreKeyId(1), true, start + 1.days, null),
            ),
            bob.infos(),
        )
        assertTrue(bob.hasSignedPreKey(0), "not deleted at rotation")
        assertEquals(rotated.id, bob.client.currentPreKeyBundle().signedPreKey.id)
        assertTrue(network.publications.isEmpty(), "rotation is local only")

        bob.client.publishPreKeys()
        assertEquals(listOf(SignedPreKeyId(1)), network.publications.map { it.signedPreKey.id }, "only the current key is published")
    }

    @Test
    fun initializeRotatesOnceTheCurrentKeyReachesTheRotationAge() = runTest {
        val bob = device(BOB)
        clock.advanceBy(rotationAge - 1.milliseconds)
        bob.client.initialize()
        assertEquals(0, bob.currentId())

        clock.advanceBy(1.milliseconds)
        bob.client.initialize()
        assertEquals(1, bob.currentId())
        assertEquals(start + rotationAge, bob.infos().first().replacedAt)
        assertTrue(network.publications.isEmpty(), "initialize never publishes")

        bob.client.initialize()
        assertEquals(listOf(0, 1), bob.infos().map { it.id.value }, "rotation happens once per age")
    }

    @Test
    fun signedPreKeyIdsAreNeverReused() = runTest {
        val bob = device(BOB)
        bob.client.rotateSignedPreKey()
        bob.client.rotateSignedPreKey()
        clock.advanceBy(grace)
        bob.client.initialize()

        // 0 and 1 expired; 2 was current until the age-based rotation to 3.
        assertEquals(listOf(2, 3), bob.infos().map { it.id.value })
        assertEquals(SignedPreKeyId(3), bob.storage.preKeys.highestSignedPreKeyId())
        assertEquals(SignedPreKeyId(4), bob.client.rotateSignedPreKey().id)
    }

    // Grace period

    @Test
    fun delayedFirstContactIsAcceptedDuringTheGracePeriod() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val delayed = withheldFirstContact(alice, bob)

        bob.client.rotateSignedPreKey()
        bob.publish()
        clock.advanceBy(grace - 1.milliseconds)
        bob.client.initialize()
        assertTrue(bob.hasSignedPreKey(0))

        assertEquals("delayed", bob.decryptText(delayed))
        assertBidirectional(alice, bob, 1)
    }

    @Test
    fun gracePeriodSurvivesARestart() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val delayed = withheldFirstContact(alice, bob)

        bob.client.rotateSignedPreKey()
        clock.advanceBy(grace / 2)
        bob.restart()
        bob.client.initialize()

        assertEquals("delayed", bob.decryptText(delayed))
    }

    @Test
    fun zeroGracePeriodRejectsTheReplacedKeyAtOnce() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB, PreKeyConfiguration(4, rotationAge, Duration.ZERO))
        val delayed = withheldFirstContact(alice, bob)

        bob.client.rotateSignedPreKey()
        assertTrue(bob.hasSignedPreKey(0), "rotation itself never deletes")
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { bob.client.decryptRaw(delayed) }
        bob.client.initialize()
        assertFalse(bob.hasSignedPreKey(0))
    }

    // Expiry

    @Test
    fun delayedFirstContactIsRejectedOnceTheGracePeriodIsOver() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val delayed = withheldFirstContact(alice, bob)
        bob.client.rotateSignedPreKey()
        clock.advanceBy(grace)

        // Refused as soon as the period is over, before maintenance deleted it.
        assertTrue(bob.hasSignedPreKey(0))
        val before = bob.snapshot(alice)
        val error = assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { bob.client.decryptRaw(delayed) }
        assertEquals(ALICE, error.address)
        assertEquals(SignedPreKeyId(0), error.signedPreKeyId)
        assertUnchanged(before, bob.snapshot(alice))

        bob.client.initialize()
        assertFalse(bob.hasSignedPreKey(0), "private key deleted")
        assertNull(bob.storage.sessions.load(ALICE))
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { bob.client.decryptRaw(delayed) }

        // A new initiation from a stale bundle that still names key 0 fails too.
        val carol = device(CAROL)
        val staleBundle = network.bundles.getValue(BOB)
        assertEquals(SignedPreKeyId(0), staleBundle.signedPreKey.id)
        carol.send(bob, "stale bundle")
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { bob.client.decryptRaw(bob.receiveOne()) }

        bob.restart()
        bob.client.initialize()
        assertFalse(bob.hasSignedPreKey(0), "a deleted key does not come back after a restart")
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { bob.client.decryptRaw(delayed) }
    }

    @Test
    fun unknownSignedPreKeyIdIsStillAnInvalidMessage() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        network.bundles[BOB] = network.bundles.getValue(BOB).let {
            it.copy(signedPreKey = it.signedPreKey.copy(id = SignedPreKeyId(9)))
        }
        alice.send(bob, "never issued")
        val error = assertFailsWith<ProtocolException.InvalidMessage> { bob.client.decryptRaw(bob.receiveOne()) }
        assertEquals("Unknown signed prekey", error.message)
    }

    @Test
    fun establishedSessionKeepsWorkingAfterItsSignedPreKeyExpired() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        establish(alice, bob)
        val origin = bob.origin(alice)

        bob.client.rotateSignedPreKey()
        clock.advanceBy(grace + 1.days)
        bob.client.initialize()
        assertFalse(bob.hasSignedPreKey(0))

        assertBidirectional(alice, bob, 1)
        bob.restart()
        bob.client.initialize()
        assertBidirectional(bob, alice, 2)
        assertEquals(origin, bob.origin(alice), "the session is not replaced")
    }

    @Test
    fun repeatedPreKeyMessageOfTheCurrentInitiationIsDecryptedAfterExpiry() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(bob, "one")
        alice.send(bob, "two")
        val (one, two) = network.receive(BOB).also { assertEquals(2, it.size) }
        assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(two.payload))
        assertEquals("one", bob.decryptText(one))

        bob.client.rotateSignedPreKey()
        clock.advanceBy(grace)
        bob.client.initialize()
        assertFalse(bob.hasSignedPreKey(0))

        assertEquals("two", bob.decryptText(two), "no signed prekey needed for the running session")
        assertBidirectional(alice, bob, 1)
    }

    @Test
    fun clockMovingBackwardsNeitherResurrectsNorRotates() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val delayed = withheldFirstContact(alice, bob)
        bob.client.rotateSignedPreKey()
        clock.advanceBy(grace)
        bob.client.initialize()
        assertFalse(bob.hasSignedPreKey(0))
        val after = bob.infos()
        val highest = bob.storage.preKeys.highestSignedPreKeyId()

        clock.now = start - 10.days
        bob.client.initialize()
        assertEquals(after, bob.infos(), "negative ages are never due")
        assertEquals(highest, bob.storage.preKeys.highestSignedPreKeyId())
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { bob.client.decryptRaw(delayed) }
    }

    @Test
    fun clockMovingBackwardsDuringGraceOnlyDelaysExpiry() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val delayed = withheldFirstContact(alice, bob)
        bob.client.rotateSignedPreKey()
        clock.now = start - 1.days
        bob.client.initialize()
        assertTrue(bob.hasSignedPreKey(0))
        assertEquals("delayed", bob.decryptText(delayed))
    }

    @Test
    fun configurationIsValidated() {
        assertFailsWith<IllegalArgumentException> { PreKeyConfiguration(signedPreKeyRotationAge = Duration.ZERO) }
        assertFailsWith<IllegalArgumentException> { PreKeyConfiguration(signedPreKeyRotationAge = (-1).days) }
        assertFailsWith<IllegalArgumentException> { PreKeyConfiguration(signedPreKeyGracePeriod = (-1).milliseconds) }
        PreKeyConfiguration(signedPreKeyGracePeriod = Duration.ZERO)
        PreKeyConfiguration(signedPreKeyRotationAge = Duration.INFINITE, signedPreKeyGracePeriod = Duration.INFINITE)
        assertEquals(7.days, PreKeyConfiguration().signedPreKeyRotationAge)
        assertEquals(30.days, PreKeyConfiguration().signedPreKeyGracePeriod)
    }

    @Test
    fun infiniteDurationsNeverRotateOrExpire() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB, PreKeyConfiguration(4, Duration.INFINITE, Duration.INFINITE))
        val delayed = withheldFirstContact(alice, bob)
        bob.client.rotateSignedPreKey()
        clock.advanceBy(3650.days)
        bob.client.initialize()
        assertEquals(listOf(0, 1), bob.infos().map { it.id.value })
        assertEquals("delayed", bob.decryptText(delayed))
    }

    // Pruning of retired initiations

    /**
     * Bob accepted Alice's first initiation with signed prekey 0, rotated to
     * 1, and then accepted a second initiation from Alice that replaced the
     * first. Returns the first initiation's envelope, for replays.
     */
    private suspend fun replacedInitiation(alice: Device, bob: Device): Pair<EncryptedEnvelope, SessionInitiationId> {
        alice.send(bob, "first")
        val firstEnvelope = bob.receiveOne()
        assertEquals("first", bob.decryptText(firstEnvelope))
        bob.send(alice, "re: first")
        alice.decryptText(alice.receiveOne())
        val first = assertNotNull(bob.origin(alice))

        bob.client.rotateSignedPreKey()
        bob.publish()
        alice.storage.sessions.remove(BOB)
        alice.send(bob, "second")
        assertEquals("second", bob.decryptText(bob.receiveOne()))
        assertTrue(bob.isRetired(alice, first))
        return firstEnvelope to first
    }

    @Test
    fun retiredInitiationIsPrunedOnceItsSignedPreKeyIsDeleted() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val (replay, first) = replacedInitiation(alice, bob)
        val second = bob.origin(alice)
        assertEquals(setOf(SignedPreKeyId(0)), bob.storage.sessionInitiations.retiredSignedPreKeyIds())

        // During grace the entry is needed: key 0 could still accept it.
        clock.advanceBy(grace - 1.milliseconds)
        bob.client.initialize()
        assertTrue(bob.isRetired(alice, first))
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { bob.client.decryptRaw(replay) }

        clock.advanceBy(1.milliseconds)
        bob.client.initialize()
        assertFalse(bob.hasSignedPreKey(0))
        assertFalse(bob.isRetired(alice, first), "pruned together with its signed prekey")

        // Without the entry the replay still cannot become a session.
        val before = bob.snapshot(alice)
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { bob.client.decryptRaw(replay) }
        assertUnchanged(before, bob.snapshot(alice))
        assertEquals(second, bob.origin(alice), "the current session is untouched")
        assertBidirectional(alice, bob, 1)

        bob.restart()
        bob.client.initialize()
        assertFalse(bob.isRetired(alice, first), "stays pruned after a restart")
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { bob.client.decryptRaw(replay) }
        assertBidirectional(bob, alice, 2)
    }

    @Test
    fun retiredInitiationOfALiveSignedPreKeyIsKept() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        establish(alice, bob)
        val first = assertNotNull(bob.origin(alice))
        // Replaced with the same, still current, signed prekey 0.
        alice.storage.sessions.remove(BOB)
        bob.publish()
        alice.send(bob, "second")
        assertEquals("second", bob.decryptText(bob.receiveOne()))

        clock.advanceBy(rotationAge - 1.milliseconds)
        bob.client.initialize()
        assertTrue(bob.hasSignedPreKey(0))
        assertTrue(bob.isRetired(alice, first))
    }

    @Test
    fun retiredInitiationThisDeviceStartedIsNeverPruned() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        // Bob initiates: his session is based on Alice's signed prekey, not his own.
        establish(bob, alice)
        val bobsInitiation = assertNotNull(bob.origin(alice))
        assertNull(engine.sessionInfo(assertNotNull(bob.storage.sessions.load(ALICE))).acceptedSignedPreKeyId)

        alice.storage.sessions.remove(BOB)
        alice.send(bob, "new")
        assertEquals("new", bob.decryptText(bob.receiveOne()))
        assertTrue(bob.isRetired(alice, bobsInitiation))

        bob.client.rotateSignedPreKey()
        clock.advanceBy(grace * 3)
        bob.client.initialize()
        assertFalse(bob.hasSignedPreKey(0))
        assertTrue(bob.isRetired(alice, bobsInitiation), "no local signed prekey to tie it to")
    }

    @Test
    fun collisionLoserIsPrunedOnceTheWinnersSignedPreKeyIsDeleted() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(bob, "from alice")
        bob.send(alice, "from bob")
        val toBob = bob.receiveOne()
        val toAlice = alice.receiveOne()
        val aliceInitiation = bob.initiationOf(toBob)
        val bobInitiation = alice.initiationOf(toAlice)
        // The side whose initiation wins receives the loser's message.
        val (winner, loser, losing) = if (aliceInitiation < bobInitiation) {
            Triple(alice, bob, toAlice)
        } else {
            Triple(bob, alice, toBob)
        }
        val losingId = winner.initiationOf(losing)

        assertFailsWith<SecureMessageClientException.SessionCollision> { winner.client.decryptRaw(losing) }
        assertTrue(winner.isRetired(loser, losingId))
        assertEquals(setOf(SignedPreKeyId(0)), winner.storage.sessionInitiations.retiredSignedPreKeyIds())

        winner.client.rotateSignedPreKey()
        clock.advanceBy(grace)
        winner.client.initialize()
        assertFalse(winner.isRetired(loser, losingId))
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { winner.client.decryptRaw(losing) }
    }

    // Failure atomicity

    @Test
    fun failedRotationLeavesTheCurrentKeyInPlace() = runTest {
        val bob = device(BOB)
        val before = bob.infos()
        bob.failing.failSignedPreKeyStore = true
        assertFailsWith<StorageFailure> { bob.client.rotateSignedPreKey() }
        assertEquals(before, bob.infos())
        assertEquals(0, bob.currentId())
        assertEquals(SignedPreKeyId(0), bob.storage.preKeys.highestSignedPreKeyId())

        // Age-based rotation inside initialize rolls back as a whole.
        clock.advanceBy(rotationAge)
        assertFailsWith<StorageFailure> { bob.client.initialize() }
        assertEquals(before, bob.infos())

        bob.healthy()
        bob.client.initialize()
        assertEquals(1, bob.currentId())
    }

    @Test
    fun failedExpiryOrPruneKeepsKeysAndRetiredInitiations() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val (replay, first) = replacedInitiation(alice, bob)
        clock.advanceBy(grace)
        val before = bob.snapshot(alice)

        for (fail in listOf<Device.() -> Unit>(
            { failing.failSignedPreKeyRemoval = true },
            { failing.failRetiredPrune = true },
            { failing.failLegacyStamp = true },
        )) {
            bob.fail()
            assertFailsWith<StorageFailure> { bob.client.initialize() }
            bob.healthy()
            assertUnchanged(before, bob.snapshot(alice))
            assertTrue(bob.hasSignedPreKey(0))
            assertTrue(bob.isRetired(alice, first))
            assertEquals(1, bob.currentId(), "the age-based rotation rolled back too")
        }

        bob.client.initialize()
        assertFalse(bob.hasSignedPreKey(0))
        assertFalse(bob.isRetired(alice, first))
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { bob.client.decryptRaw(replay) }
        assertBidirectional(alice, bob, 1)
    }
}
