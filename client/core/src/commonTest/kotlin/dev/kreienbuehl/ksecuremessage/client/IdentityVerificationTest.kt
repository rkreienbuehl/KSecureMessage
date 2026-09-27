package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.PublicIdentityKey
import dev.kreienbuehl.ksecuremessage.protocol.SafetyNumber
import dev.kreienbuehl.ksecuremessage.protocol.SafetyNumberComparison
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

private val BOB_PHONE = DeviceAddress(UserId("bob"), DeviceId("phone"))

/**
 * Safety numbers and manual verification (docs/identity-verification.md):
 * derived from pinned state only, identical on both devices, per device, and
 * a verification is bound to exactly the pinned key.
 */
class IdentityVerificationTest {
    private val network = FlakyNetwork()

    private suspend fun device(address: DeviceAddress) = ReliableDevice(address, network).start()

    private suspend fun ReliableDevice.identityKey() = PublicIdentityKey(assertNotNull(storage.identity.identity()).publicKey)

    private suspend fun ReliableDevice.trust(remote: ReliableDevice) = client.remoteIdentityTrust(remote.address)

    /** A message each way, so both devices pinned each other. */
    private suspend fun introduce(a: ReliableDevice, b: ReliableDevice) {
        a.send(b, "hello")
        b.acceptOne()
        a.receiveOne()
    }

    @Test
    fun firstPinIsUnverifiedAndBothDevicesDeriveTheSameSafetyNumber() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        assertNull(alice.trust(bob))

        introduce(alice, bob)
        assertEquals(RemoteIdentityTrust(BOB, bob.identityKey(), VerificationState.UNVERIFIED), alice.trust(bob))
        assertEquals(RemoteIdentityTrust(ALICE, alice.identityKey(), VerificationState.UNVERIFIED), bob.trust(alice))

        val fromAlice = alice.client.safetyNumber(BOB)
        val fromBob = bob.client.safetyNumber(ALICE)
        assertEquals(fromAlice, fromBob)
        assertEquals(fromAlice.displayString, fromBob.displayString)
        assertEquals(fromAlice.encode().toList(), fromBob.encode().toList())
        assertEquals(SafetyNumber.derive(ALICE, alice.identityKey(), BOB, bob.identityKey()), fromAlice)
    }

    @Test
    fun safetyNumberNeedsAPinAndNeverFetchesABundle() = runTest {
        val alice = device(ALICE)
        // Carol's bundle is not even published: a fetch would fail differently.
        val carol = DeviceAddress(UserId("carol"), DeviceId("tablet"))
        assertFailsWith<SecureMessageClientException.RemoteIdentityNotKnown> { alice.client.safetyNumber(carol) }
        val payload = SafetyNumber.derive(ALICE, alice.identityKey(), carol, alice.identityKey()).encode()
        assertFailsWith<SecureMessageClientException.RemoteIdentityNotKnown> { alice.client.compareSafetyNumber(carol, payload) }
        assertFailsWith<SecureMessageClientException.RemoteIdentityNotKnown> { alice.client.markRemoteIdentityUnverified(carol) }
        val bob = device(BOB)
        // Bob has a published bundle, but nothing is pinned for him yet.
        assertFailsWith<SecureMessageClientException.RemoteIdentityNotKnown> { alice.client.safetyNumber(BOB) }
        assertNull(alice.trust(bob))
        assertNull(alice.storage.sessions.load(BOB))
    }

    @Test
    fun comparisonNeverChangesTrust() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val carol = device(CAROL)
        introduce(alice, bob)
        introduce(alice, carol)

        assertEquals(SafetyNumberComparison.MATCH, alice.client.compareSafetyNumber(BOB, bob.client.safetyNumber(ALICE).encode()))
        assertEquals(VerificationState.UNVERIFIED, alice.trust(bob)?.verification, "a match is not a verification")

        val impostor = SafetyNumber.derive(ALICE, alice.identityKey(), BOB, carol.identityKey())
        assertEquals(SafetyNumberComparison.MISMATCH, alice.client.compareSafetyNumber(BOB, impostor.encode()))
        assertEquals(SafetyNumberComparison.DIFFERENT_DEVICES, alice.client.compareSafetyNumber(BOB, carol.client.safetyNumber(ALICE).encode()))
        assertFailsWith<SecureMessageClientException.InvalidSafetyNumberPayload> { alice.client.compareSafetyNumber(BOB, byteArrayOf(1, 2, 3)) }
        assertFailsWith<SecureMessageClientException.InvalidSafetyNumberPayload> { alice.client.compareSafetyNumber(BOB, byteArrayOf()) }

        assertEquals(RemoteIdentityTrust(BOB, bob.identityKey(), VerificationState.UNVERIFIED), alice.trust(bob))
        assertEquals(VerificationState.UNVERIFIED, alice.trust(carol)?.verification)
    }

    @Test
    fun verificationPersistsAndSurvivesSessionReplacementWithTheSameIdentity() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        introduce(alice, bob)

        alice.client.markRemoteIdentityVerified(alice.client.safetyNumber(BOB))
        assertEquals(VerificationState.VERIFIED, alice.trust(bob)?.verification)
        assertEquals(VerificationState.UNVERIFIED, bob.trust(alice)?.verification, "verification is local")

        alice.restart()
        assertEquals(VerificationState.VERIFIED, alice.trust(bob)?.verification)

        // A new session with the same identity (lost session state) keeps the verification.
        val number = alice.client.safetyNumber(BOB)
        alice.storage.sessions.remove(BOB)
        network.fake.publish(bob.client)
        alice.send(bob, "new session")
        bob.acceptOne()
        alice.receiveOne()
        assertEquals(VerificationState.VERIFIED, alice.trust(bob)?.verification)
        assertEquals(number, alice.client.safetyNumber(BOB))

        alice.client.markRemoteIdentityUnverified(BOB)
        assertEquals(RemoteIdentityTrust(BOB, bob.identityKey(), VerificationState.UNVERIFIED), alice.trust(bob))
        alice.client.markRemoteIdentityVerified(number)
        assertEquals(VerificationState.VERIFIED, alice.trust(bob)?.verification)
    }

    @Test
    fun verificationIsPerDevice() = runTest {
        val alice = device(ALICE)
        val laptop = device(BOB)
        val phone = device(BOB_PHONE)
        introduce(alice, laptop)
        introduce(alice, phone)

        assertNotEquals(alice.client.safetyNumber(BOB), alice.client.safetyNumber(BOB_PHONE))
        alice.client.markRemoteIdentityVerified(alice.client.safetyNumber(BOB))
        assertEquals(VerificationState.VERIFIED, alice.trust(laptop)?.verification)
        assertEquals(VerificationState.UNVERIFIED, alice.trust(phone)?.verification, "another device of the same user")
    }

    @Test
    fun verificationNeedsASafetyNumberOfThisDeviceAndTheCurrentPin() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val carol = device(CAROL)
        introduce(alice, bob)
        introduce(bob, carol)

        // Not about Alice at all.
        assertFailsWith<IllegalArgumentException> { alice.client.markRemoteIdentityVerified(bob.client.safetyNumber(CAROL)) }
        // About Alice and Bob, but for a key that is not pinned.
        val other = SafetyNumber.derive(ALICE, alice.identityKey(), BOB, carol.identityKey())
        assertFailsWith<SecureMessageClientException.RemoteIdentityConflict> { alice.client.markRemoteIdentityVerified(other) }
        assertEquals(VerificationState.UNVERIFIED, alice.trust(bob)?.verification)
    }

    @Test
    fun failedVerificationWriteChangesNothing() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        introduce(alice, bob)

        alice.failing.failVerificationUpdate = true
        assertFailsWith<StorageFailure> { alice.client.markRemoteIdentityVerified(alice.client.safetyNumber(BOB)) }
        assertEquals(VerificationState.UNVERIFIED, alice.trust(bob)?.verification)
        alice.failing.failVerificationUpdate = false
        alice.client.markRemoteIdentityVerified(alice.client.safetyNumber(BOB))
        assertEquals(VerificationState.VERIFIED, alice.trust(bob)?.verification)
    }
}
