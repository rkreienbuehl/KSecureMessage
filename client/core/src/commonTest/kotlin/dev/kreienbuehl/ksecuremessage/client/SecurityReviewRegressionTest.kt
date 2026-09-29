package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
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
import kotlin.time.Clock

/**
 * Client-side regression tests for the security review findings F3, F4 and
 * F9 (S1, docs/security-review-remediation.md). Each test names the finding
 * it guards; the attacker is a relay that rewrites envelopes or a malicious
 * client.
 */
class SecurityReviewRegressionTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()
    private val network = FakeNetwork()

    private inner class Device(val address: DeviceAddress, val storage: InMemoryClientStorage = InMemoryClientStorage()) {
        val client = SecureMessageClient(address, storage, engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 4))

        suspend fun send(to: DeviceAddress, text: String) = client.sendRaw(to, text.encodeToByteArray())

        suspend fun receiveOne(): EncryptedEnvelope = network.receive(address).single()

        suspend fun decryptText(envelope: EncryptedEnvelope): String = client.decryptRaw(envelope).decodeToString()

        suspend fun session(remote: DeviceAddress): SecureSession? = storage.sessions.load(remote)

        suspend fun pin(remote: DeviceAddress): ByteArray? = storage.remoteIdentities.identityKey(remote)

        suspend fun identityKey(): ByteArray = assertNotNull(storage.identity.identity()).publicKey
    }

    private suspend fun device(address: DeviceAddress) = Device(address).also {
        it.client.initialize()
        network.publish(it.client)
    }

    private suspend fun establish(initiator: Device, responder: Device) {
        initiator.send(responder.address, "hello")
        assertEquals("hello", responder.decryptText(responder.receiveOne()))
        responder.send(initiator.address, "re: hello")
        assertEquals("re: hello", initiator.decryptText(initiator.receiveOne()))
    }

    private fun EncryptedEnvelope.preKeyMessage() = assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(payload))

    private fun EncryptedEnvelope.withPreKeyMessage(message: PreKeyMessage) =
        copy(id = MessageId("rewritten-${id.value}"), payload = CiphertextMessageCodec.encode(message))

    private fun ByteArray.flipped(index: Int) = copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }

    /** Everything a rejected message must leave untouched on [device] for [remote]. */
    private suspend fun snapshot(device: Device, remote: DeviceAddress) = listOf(
        device.session(remote)?.state?.toList(),
        device.pin(remote)?.toList(),
        device.storage.preKeys.publicOneTimePreKeys().map { it.id.value },
    )

    // F3: unauthenticated initiation bytes must not yield a second valid initiation ID.

    @Test
    fun f3MutatedEphemeralSigningHalfCannotBypassRetiredInitiationReplayProtection() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        // Without a one-time prekey nothing but the initiation ID tells a
        // replay apart: exactly the case retired initiations protect.
        network.publish(bob.client, withOneTimePreKey = false)
        alice.send(BOB, "first")
        val firstInitiation = bob.receiveOne()
        assertEquals("first", bob.decryptText(firstInitiation))
        val firstOrigin = SessionInitiationId.v2Of(firstInitiation.preKeyMessage(), ALICE, BOB, bob.identityKey())
        bob.send(ALICE, "ack")
        alice.decryptText(alice.receiveOne())

        // Alice loses her session and starts a new one: Bob replaces and retires the first initiation.
        alice.storage.sessions.remove(BOB)
        network.publish(bob.client, withOneTimePreKey = false)
        alice.send(BOB, "second")
        assertEquals("second", bob.decryptText(bob.receiveOne()))
        assertTrue(bob.storage.sessionInitiations.isRetired(ALICE, firstOrigin))
        val before = snapshot(bob, ALICE)

        // A plain replay of the first initiation is stale.
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { bob.client.decryptRaw(firstInitiation) }
        // The v1 attack: flip bits of the ephemeral key's signing half to get another ID.
        for (index in listOf(32, 50, 63)) {
            val message = firstInitiation.preKeyMessage()
            val mutated = firstInitiation.withPreKeyMessage(message.copy(ephemeralKey = message.ephemeralKey.flipped(index)))
            assertFailsWith<ProtocolException.DecryptionFailed> { bob.client.decryptRaw(mutated) }
        }
        // A changed signed prekey ID as well (Bob still holds only key 1: no other key to try).
        val message = firstInitiation.preKeyMessage()
        assertFailsWith<ProtocolException> {
            bob.client.decryptRaw(firstInitiation.withPreKeyMessage(message.copy(signedPreKeyId = dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId(999))))
        }
        assertEquals(before, snapshot(bob, ALICE), "no session rollback, pin or prekey change")
        assertEquals("still current", run {
            alice.send(BOB, "still current")
            bob.decryptText(bob.receiveOne())
        })
    }

    @Test
    fun f3MutatedFirstContactCreatesNothing() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(BOB, "hi")
        val envelope = bob.receiveOne()
        val message = envelope.preKeyMessage()
        val before = snapshot(bob, ALICE)
        assertFailsWith<ProtocolException.DecryptionFailed> {
            bob.client.decryptRaw(envelope.withPreKeyMessage(message.copy(ephemeralKey = message.ephemeralKey.flipped(40))))
        }
        assertEquals(before, snapshot(bob, ALICE))
        assertNull(bob.pin(ALICE), "no pin")
        assertEquals("hi", bob.decryptText(envelope), "the genuine message still works")
    }

    // F4: the sender address of a first contact is authenticated before the pin is written.

    @Test
    fun f4RelayRewritingTheSenderIsRejectedBeforeAnyPin() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(BOB, "from Alice")
        val envelope = bob.receiveOne()
        val forged = envelope.copy(sender = CAROL)
        assertFailsWith<ProtocolException.DecryptionFailed> { bob.client.decryptRaw(forged) }
        assertNull(bob.pin(CAROL), "Alice's key is never pinned for Carol")
        assertNull(bob.session(CAROL))
        assertEquals("from Alice", bob.decryptText(envelope))
        assertContentEquals(alice.identityKey(), bob.pin(ALICE))
    }

    @Test
    fun f4MaliciousClientClaimingAnotherAddressIsRejectedBeforeAnyPin() = runTest {
        val bob = device(BOB)
        val mallory = device(DeviceAddress(UserId("mallory"), DeviceId("phone")))
        // Mallory's own, valid first contact, relabeled as coming from Alice.
        mallory.send(BOB, "I am Alice")
        val envelope = bob.receiveOne()
        assertFailsWith<ProtocolException.DecryptionFailed> { bob.client.decryptRaw(envelope.copy(sender = ALICE)) }
        assertNull(bob.pin(ALICE), "Alice's pin is not poisoned")
        assertNull(bob.session(ALICE))
    }

    @Test
    fun f4RelayRewritingTheRecipientIsRejected() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        // Another address with Bob's identity and prekeys (for example a copied device).
        val otherAddress = DeviceAddress(BOB.userId, DeviceId("tablet"))
        val copy = InMemoryClientStorage()
        copyKeys(bob.storage, copy)
        val bobTablet = Device(otherAddress, copy)
        alice.send(BOB, "for the laptop")
        val envelope = bob.receiveOne()
        assertFailsWith<ProtocolException.DecryptionFailed> { bobTablet.client.decryptRaw(envelope.copy(recipient = otherAddress)) }
        assertNull(bobTablet.pin(ALICE))
        assertNull(bobTablet.session(ALICE))
    }

    @Test
    fun f4SignedSubmissionStopsAClientSendingAsAnotherDevice() = runTest {
        val server = ServerBackedNetwork()
        val alice = SecureMessageClient(ALICE, InMemoryClientStorage(), engine, server)
        alice.initialize()
        alice.registerDevice()
        val bob = SecureMessageClient(BOB, InMemoryClientStorage(), engine, server)
        bob.initialize()
        bob.registerDevice()
        bob.publishPreKeys()

        // Mallory runs a client that claims Alice's address with her own keys.
        val impostor = SecureMessageClient(ALICE, InMemoryClientStorage(), engine, server)
        impostor.initialize()
        val failure = assertFailsWith<SecureMessageClientException.MessageNotSent> { impostor.send(BOB, "I am Alice".encodeToByteArray()) }
        assertIs<SecureMessageTransportException.AuthenticationFailed>(failure.cause)
        assertTrue(server.receive(BOB).isEmpty(), "nothing queued for Bob")
    }

    // F9: a session never pins the local identity as the remote one.

    private suspend fun legacyDevice(address: DeviceAddress, identity: LocalIdentity, session: SecureSession?, pin: ByteArray? = null): Device {
        val storage = InMemoryClientStorage()
        val deviceKey = engine.createDeviceAuthenticationKey()
        storage.transaction {
            this.identity.store(identity)
            deviceAuthentication.store(deviceKey)
            session?.let { sessions.store(it) }
            pin?.let { remoteIdentities.store(session!!.remote, it) }
        }
        return Device(address, storage).also {
            it.client.initialize()
            network.publish(it.client)
        }
    }

    @Test
    fun f9LocallyInitiatedLegacySessionNeverPinsTheLocalIdentity() = runTest {
        val fixture = LegacySessionFixture
        // Sessions from before identity pinning: no pins on either side.
        val alice = legacyDevice(ALICE, fixture.aliceIdentity, fixture.aliceEstablishedV1)
        val bob = legacyDevice(BOB, fixture.bobIdentity, fixture.bobEstablishedV1)
        bob.send(ALICE, "genuine")
        val genuine = alice.receiveOne()
        val ratchet = assertIs<RatchetMessage>(CiphertextMessageCodec.decode(genuine.payload))

        // The relay rewraps Bob's genuine ratchet message as a version 1
        // PreKeyMessage naming Alice's own identity key.
        val rewrapped = genuine.withPreKeyMessage(
            PreKeyMessage(
                identityKey = fixture.aliceIdentity.publicKey,
                ephemeralKey = ByteArray(64),
                signedPreKeyId = dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId(1),
                oneTimePreKeyId = null,
                message = ratchet,
                initiationVersion = SessionInitiationVersion.V1,
            ),
        )
        val before = snapshot(alice, BOB)
        assertFailsWith<ProtocolException.InvalidMessage> { alice.client.decryptRaw(rewrapped) }
        assertEquals(before, snapshot(alice, BOB))
        assertNull(alice.pin(BOB), "never the local identity as Bob's pin")

        // The genuine message still decrypts, and a ratchet message never pins.
        assertEquals("genuine", alice.decryptText(genuine))
        assertNull(alice.pin(BOB))
    }

    @Test
    fun f9ResponderLegacySessionPinsTheAuthenticatedInitiatorKey() = runTest {
        val fixture = LegacySessionFixture
        val alice = legacyDevice(ALICE, fixture.aliceIdentity, fixture.alicePendingV3)
        val bob = legacyDevice(BOB, fixture.bobIdentity, fixture.bobAcceptedV3)
        assertNull(bob.pin(ALICE))
        alice.send(BOB, "repeat")
        assertEquals("repeat", bob.decryptText(bob.receiveOne()))
        assertContentEquals(fixture.aliceIdentity.publicKey, bob.pin(ALICE), "the session's own initiator key")
    }

    @Test
    fun f9AmbiguousLegacySessionFabricatesNoPin() = runTest {
        val fixture = LegacySessionFixture
        val alice = legacyDevice(ALICE, fixture.aliceIdentity, fixture.alicePendingV3)
        // Bob's storage holds a session that none of its identity keys belongs to.
        val bob = legacyDevice(BOB, engine.createIdentity(), fixture.bobAcceptedV3)
        alice.send(BOB, "whose session?")
        assertFailsWith<ProtocolException.InvalidMessage> { bob.client.decryptRaw(bob.receiveOne()) }
        assertNull(bob.pin(ALICE), "nothing guessed")
    }

    @Test
    fun f9ExistingVerifiedPinIsUnchanged() = runTest {
        val fixture = LegacySessionFixture
        val alice = legacyDevice(ALICE, fixture.aliceIdentity, fixture.alicePendingV3)
        val bob = legacyDevice(BOB, fixture.bobIdentity, fixture.bobAcceptedV3, pin = fixture.aliceIdentity.publicKey)
        bob.storage.remoteIdentities.setVerification(ALICE, fixture.aliceIdentity.publicKey, VerificationState.VERIFIED)

        // A rewrapped message naming Bob's own key is an identity change, refused before any crypto.
        alice.send(BOB, "genuine")
        val genuine = bob.receiveOne()
        val message = genuine.preKeyMessage()
        assertFailsWith<SecureMessageClientException.IdentityChanged> {
            bob.client.decryptRaw(genuine.withPreKeyMessage(message.copy(identityKey = fixture.bobIdentity.publicKey)))
        }
        assertEquals("genuine", bob.decryptText(genuine))
        val record = assertNotNull(bob.storage.remoteIdentities.record(ALICE))
        assertContentEquals(fixture.aliceIdentity.publicKey, record.identityKey)
        assertEquals(VerificationState.VERIFIED, record.verification)
        assertFalse(record.identityKey.contentEquals(fixture.bobIdentity.publicKey))
    }

    private suspend fun copyKeys(source: ClientStorage, target: ClientStorage) {
        target.transaction {
            identity.store(assertNotNull(source.identity.identity()))
            deviceAuthentication.store(assertNotNull(source.deviceAuthentication.keyPair()))
            val signedPreKey = assertNotNull(source.preKeys.currentSignedPreKey())
            preKeys.storeCurrentSignedPreKey(signedPreKey, Clock.System.now())
            preKeys.storeOneTimePreKeys(source.preKeys.publicOneTimePreKeys().map { assertNotNull(source.preKeys.oneTimePreKey(it.id)) })
        }
    }
}
