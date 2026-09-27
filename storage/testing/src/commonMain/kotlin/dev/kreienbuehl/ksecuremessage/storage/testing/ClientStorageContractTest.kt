package dev.kreienbuehl.ksecuremessage.storage.testing

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.InboundFinalization
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.MessageDiscardReason
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.SignedPreKeyInfo
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Instant

/**
 * Behavior every [ClientStorage] implementation must have. Subclass it in an
 * adapter's tests. Key material is fake: storage never interprets it.
 */
abstract class ClientStorageContractTest {
    /** Returns a new, empty storage. */
    protected abstract suspend fun newStorage(): ClientStorage

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))

    private class Failure : Exception()

    @Test
    fun identityIsStoredOnceAndNeverReplaced() = runTest {
        val storage = newStorage()
        assertNull(storage.identity.identity())

        storage.identity.store(identity(1))
        assertContentEquals(bytes(1), storage.identity.identity()?.publicKey)
        assertContentEquals(bytes(-1), storage.identity.identity()?.privateKey)

        assertFailsWith<IllegalStateException> { storage.identity.store(identity(2)) }
        assertContentEquals(bytes(1), storage.identity.identity()?.publicKey)
    }

    @Test
    fun deviceAuthenticationKeyIsStoredOnceAndNeverReplaced() = runTest {
        val storage = newStorage()
        assertNull(storage.deviceAuthentication.keyPair())
        assertFalse(storage.deviceAuthentication.awaitsUpgradeKey(), "a new storage has no pre-milestone-12 identity")

        storage.deviceAuthentication.store(DeviceAuthenticationKeyPair(bytes(3), bytes(-3)))
        assertContentEquals(bytes(3), storage.deviceAuthentication.keyPair()?.publicKey)
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey)

        assertFailsWith<IllegalStateException> { storage.deviceAuthentication.store(DeviceAuthenticationKeyPair(bytes(4), bytes(-4))) }
        assertFailsWith<IllegalStateException>("an identical key is refused too") {
            storage.deviceAuthentication.store(DeviceAuthenticationKeyPair(bytes(3), bytes(-3)))
        }
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey)
        assertFalse(storage.deviceAuthentication.awaitsUpgradeKey())
    }

    @Test
    fun pendingRecoveryKeyIsSeparateFromTheActiveKey() = runTest {
        val storage = newStorage()
        assertNull(storage.deviceAuthentication.pendingRecoveryKeyPair())
        storage.deviceAuthentication.store(DeviceAuthenticationKeyPair(bytes(3), bytes(-3)))
        storage.deviceAuthentication.storePendingRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(5), bytes(-5)))
        assertContentEquals(bytes(-5), storage.deviceAuthentication.pendingRecoveryKeyPair()?.privateKey)
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey, "the active key is untouched")
        assertFailsWith<IllegalStateException> {
            storage.deviceAuthentication.storePendingRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(6), bytes(-6)))
        }
        assertContentEquals(bytes(-5), storage.deviceAuthentication.pendingRecoveryKeyPair()?.privateKey, "never replaced silently")

        storage.deviceAuthentication.removePendingRecoveryKeyPair()
        assertNull(storage.deviceAuthentication.pendingRecoveryKeyPair())
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey)
        storage.deviceAuthentication.removePendingRecoveryKeyPair() // nothing to remove: harmless
    }

    @Test
    fun promotionReplacesTheActiveKeyAtomically() = runTest {
        val storage = newStorage()
        assertFailsWith<IllegalStateException> { storage.deviceAuthentication.promotePendingRecoveryKeyPair() }
        storage.deviceAuthentication.store(DeviceAuthenticationKeyPair(bytes(3), bytes(-3)))
        storage.deviceAuthentication.storePendingRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(5), bytes(-5)))

        assertFailsWith<Failure> {
            storage.transaction {
                deviceAuthentication.promotePendingRecoveryKeyPair()
                assertContentEquals(bytes(-5), deviceAuthentication.keyPair()?.privateKey, "visible inside the transaction")
                assertNull(deviceAuthentication.pendingRecoveryKeyPair())
                throw Failure()
            }
        }
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey, "rolled back")
        assertContentEquals(bytes(-5), storage.deviceAuthentication.pendingRecoveryKeyPair()?.privateKey, "rolled back")

        storage.deviceAuthentication.promotePendingRecoveryKeyPair()
        assertContentEquals(bytes(5), storage.deviceAuthentication.keyPair()?.publicKey)
        assertContentEquals(bytes(-5), storage.deviceAuthentication.keyPair()?.privateKey)
        assertNull(storage.deviceAuthentication.pendingRecoveryKeyPair())
        assertFalse(storage.deviceAuthentication.awaitsUpgradeKey())
        assertFailsWith<IllegalStateException> { storage.deviceAuthentication.promotePendingRecoveryKeyPair() }
    }

    @Test
    fun promotionInstallsAKeyWhereTheActiveKeyIsMissing() = runTest {
        val storage = newStorage()
        storage.identity.store(identity(1))
        val pending = DeviceAuthenticationKeyPair(bytes(5), bytes(-5))
        storage.deviceAuthentication.storePendingRecoveryKeyPair(pending)
        pending.privateKey.fill(0)
        storage.deviceAuthentication.pendingRecoveryKeyPair()!!.privateKey.fill(0)
        storage.deviceAuthentication.promotePendingRecoveryKeyPair()
        assertContentEquals(bytes(-5), storage.deviceAuthentication.keyPair()?.privateKey, "stored bytes are not aliased")
    }

    @Test
    fun pendingRotationKeyIsSeparateFromTheActiveAndTheRecoveryKey() = runTest {
        val storage = newStorage()
        assertNull(storage.deviceAuthentication.pendingRotationKeyPair())
        storage.deviceAuthentication.store(DeviceAuthenticationKeyPair(bytes(3), bytes(-3)))
        storage.deviceAuthentication.storePendingRotationKeyPair(DeviceAuthenticationKeyPair(bytes(7), bytes(-7)))
        assertContentEquals(bytes(-7), storage.deviceAuthentication.pendingRotationKeyPair()?.privateKey)
        assertNull(storage.deviceAuthentication.pendingRecoveryKeyPair(), "never readable as a recovery key")
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey, "the active key is untouched")
        assertFailsWith<IllegalStateException> {
            storage.deviceAuthentication.storePendingRotationKeyPair(DeviceAuthenticationKeyPair(bytes(8), bytes(-8)))
        }
        assertContentEquals(bytes(-7), storage.deviceAuthentication.pendingRotationKeyPair()?.privateKey, "never replaced silently")
        assertFailsWith<IllegalStateException>("no recovery while a rotation is pending") {
            storage.deviceAuthentication.storePendingRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(5), bytes(-5)))
        }
        assertNull(storage.deviceAuthentication.pendingRecoveryKeyPair())

        storage.deviceAuthentication.removePendingRotationKeyPair()
        assertNull(storage.deviceAuthentication.pendingRotationKeyPair())
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey)
        storage.deviceAuthentication.removePendingRotationKeyPair() // nothing to remove: harmless

        storage.deviceAuthentication.storePendingRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(5), bytes(-5)))
        assertFailsWith<IllegalStateException>("no rotation while a recovery is pending") {
            storage.deviceAuthentication.storePendingRotationKeyPair(DeviceAuthenticationKeyPair(bytes(7), bytes(-7)))
        }
        assertNull(storage.deviceAuthentication.pendingRotationKeyPair())
        storage.deviceAuthentication.removePendingRotationKeyPair()
        assertContentEquals(bytes(-5), storage.deviceAuthentication.pendingRecoveryKeyPair()?.privateKey, "removing a rotation keeps a recovery")
    }

    @Test
    fun rotationPromotionReplacesTheActiveKeyAtomically() = runTest {
        val storage = newStorage()
        assertFailsWith<IllegalStateException> { storage.deviceAuthentication.promotePendingRotationKeyPair() }
        storage.deviceAuthentication.store(DeviceAuthenticationKeyPair(bytes(3), bytes(-3)))
        storage.deviceAuthentication.storePendingRotationKeyPair(DeviceAuthenticationKeyPair(bytes(7), bytes(-7)))

        assertFailsWith<Failure> {
            storage.transaction {
                deviceAuthentication.promotePendingRotationKeyPair()
                assertContentEquals(bytes(-7), deviceAuthentication.keyPair()?.privateKey, "visible inside the transaction")
                assertNull(deviceAuthentication.pendingRotationKeyPair())
                throw Failure()
            }
        }
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey, "rolled back")
        assertContentEquals(bytes(-7), storage.deviceAuthentication.pendingRotationKeyPair()?.privateKey, "rolled back")

        storage.deviceAuthentication.promotePendingRotationKeyPair()
        assertContentEquals(bytes(7), storage.deviceAuthentication.keyPair()?.publicKey)
        assertContentEquals(bytes(-7), storage.deviceAuthentication.keyPair()?.privateKey)
        assertNull(storage.deviceAuthentication.pendingRotationKeyPair())
        assertNull(storage.deviceAuthentication.pendingRecoveryKeyPair())
        assertFalse(storage.deviceAuthentication.awaitsUpgradeKey())
        assertFailsWith<IllegalStateException> { storage.deviceAuthentication.promotePendingRotationKeyPair() }
        assertFailsWith<IllegalStateException> { storage.deviceAuthentication.promotePendingRecoveryKeyPair() }
    }

    @Test
    fun pendingRotationKeyIsCopied() = runTest {
        val storage = newStorage()
        storage.identity.store(identity(1))
        val pending = DeviceAuthenticationKeyPair(bytes(7), bytes(-7))
        storage.deviceAuthentication.storePendingRotationKeyPair(pending)
        pending.privateKey.fill(0)
        storage.deviceAuthentication.pendingRotationKeyPair()!!.privateKey.fill(0)
        storage.deviceAuthentication.promotePendingRotationKeyPair()
        assertContentEquals(bytes(-7), storage.deviceAuthentication.keyPair()?.privateKey, "stored bytes are not aliased")
    }

    @Test
    fun pendingLastDeviceRecoveryKeyIsSeparateFromEveryOtherSlot() = runTest {
        val storage = newStorage()
        val auth = storage.deviceAuthentication
        assertNull(auth.pendingLastDeviceRecoveryKeyPair())
        auth.storePendingLastDeviceRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(9), bytes(-9)))
        assertContentEquals(bytes(-9), auth.pendingLastDeviceRecoveryKeyPair()?.privateKey)
        assertNull(auth.keyPair(), "no active key needed: the device lost it")
        assertNull(auth.pendingRecoveryKeyPair(), "never readable as a device recovery key")
        assertNull(auth.pendingRotationKeyPair(), "never readable as a rotation key")
        assertFailsWith<IllegalStateException> { auth.storePendingLastDeviceRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(8), bytes(-8))) }
        assertContentEquals(bytes(-9), auth.pendingLastDeviceRecoveryKeyPair()?.privateKey, "never replaced silently")
        assertFailsWith<IllegalStateException>("no device recovery while a last-device recovery is pending") {
            auth.storePendingRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(5), bytes(-5)))
        }
        assertFailsWith<IllegalStateException>("no rotation while a last-device recovery is pending") {
            auth.storePendingRotationKeyPair(DeviceAuthenticationKeyPair(bytes(7), bytes(-7)))
        }
        assertNull(auth.pendingRecoveryKeyPair())
        assertNull(auth.pendingRotationKeyPair())
        auth.removePendingRecoveryKeyPair()
        auth.removePendingRotationKeyPair()
        assertContentEquals(bytes(-9), auth.pendingLastDeviceRecoveryKeyPair()?.privateKey, "removing other slots keeps it")

        auth.removePendingLastDeviceRecoveryKeyPair()
        assertNull(auth.pendingLastDeviceRecoveryKeyPair())
        auth.removePendingLastDeviceRecoveryKeyPair() // nothing to remove: harmless

        auth.storePendingRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(5), bytes(-5)))
        assertFailsWith<IllegalStateException>("no last-device recovery while a device recovery is pending") {
            auth.storePendingLastDeviceRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(9), bytes(-9)))
        }
        auth.removePendingRecoveryKeyPair()
        auth.storePendingRotationKeyPair(DeviceAuthenticationKeyPair(bytes(7), bytes(-7)))
        assertFailsWith<IllegalStateException>("no last-device recovery while a rotation is pending") {
            auth.storePendingLastDeviceRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(9), bytes(-9)))
        }
        assertNull(auth.pendingLastDeviceRecoveryKeyPair())
        auth.removePendingLastDeviceRecoveryKeyPair()
        assertContentEquals(bytes(-7), auth.pendingRotationKeyPair()?.privateKey, "removing it keeps a rotation")
    }

    @Test
    fun lastDeviceRecoveryPromotionInstallsOrReplacesTheActiveKeyAtomically() = runTest {
        val storage = newStorage()
        val auth = storage.deviceAuthentication
        assertFailsWith<IllegalStateException> { auth.promotePendingLastDeviceRecoveryKeyPair() }
        auth.storePendingLastDeviceRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(9), bytes(-9)))

        assertFailsWith<Failure> {
            storage.transaction {
                deviceAuthentication.promotePendingLastDeviceRecoveryKeyPair()
                assertContentEquals(bytes(-9), deviceAuthentication.keyPair()?.privateKey, "visible inside the transaction")
                assertNull(deviceAuthentication.pendingLastDeviceRecoveryKeyPair())
                throw Failure()
            }
        }
        assertNull(auth.keyPair(), "rolled back")
        assertContentEquals(bytes(-9), auth.pendingLastDeviceRecoveryKeyPair()?.privateKey, "rolled back")

        // Installs the key although no active key exists (the lost-key case).
        auth.promotePendingLastDeviceRecoveryKeyPair()
        assertContentEquals(bytes(9), auth.keyPair()?.publicKey)
        assertContentEquals(bytes(-9), auth.keyPair()?.privateKey)
        assertNull(auth.pendingLastDeviceRecoveryKeyPair())
        assertFalse(auth.awaitsUpgradeKey())
        assertFailsWith<IllegalStateException> { auth.promotePendingLastDeviceRecoveryKeyPair() }

        // Replaces an existing active key.
        auth.storePendingLastDeviceRecoveryKeyPair(DeviceAuthenticationKeyPair(bytes(10), bytes(-10)))
        auth.promotePendingLastDeviceRecoveryKeyPair()
        assertContentEquals(bytes(-10), auth.keyPair()?.privateKey)
    }

    @Test
    fun pendingLastDeviceRecoveryKeyIsCopied() = runTest {
        val storage = newStorage()
        storage.identity.store(identity(1))
        val pending = DeviceAuthenticationKeyPair(bytes(9), bytes(-9))
        storage.deviceAuthentication.storePendingLastDeviceRecoveryKeyPair(pending)
        pending.privateKey.fill(0)
        storage.deviceAuthentication.pendingLastDeviceRecoveryKeyPair()!!.privateKey.fill(0)
        storage.deviceAuthentication.promotePendingLastDeviceRecoveryKeyPair()
        assertContentEquals(bytes(-9), storage.deviceAuthentication.keyPair()?.privateKey, "stored bytes are not aliased")
    }

    @Test
    fun deviceAuthenticationKeyIsCopiedAndRolledBack() = runTest {
        val storage = newStorage()
        val keyPair = DeviceAuthenticationKeyPair(bytes(3), bytes(-3))
        assertFailsWith<Failure> {
            storage.transaction {
                identity.store(identity(1))
                deviceAuthentication.store(keyPair)
                assertContentEquals(bytes(-3), deviceAuthentication.keyPair()?.privateKey, "visible inside the transaction")
                throw Failure()
            }
        }
        assertNull(storage.deviceAuthentication.keyPair())
        assertNull(storage.identity.identity())

        storage.transaction {
            identity.store(identity(1))
            deviceAuthentication.store(keyPair)
        }
        keyPair.privateKey.fill(0)
        storage.deviceAuthentication.keyPair()!!.privateKey.fill(0)
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey, "stored bytes are not aliased")
    }

    @Test
    fun remoteIdentityIsPinnedOnceAndNeverReplaced() = runTest {
        val storage = newStorage()
        assertNull(storage.remoteIdentities.identityKey(alice))

        storage.remoteIdentities.store(alice, bytes(1))
        assertContentEquals(bytes(1), storage.remoteIdentities.identityKey(alice))

        storage.remoteIdentities.store(alice, bytes(1))
        assertContentEquals(bytes(1), storage.remoteIdentities.identityKey(alice), "same key again is a no-op")

        assertFailsWith<IllegalStateException> { storage.remoteIdentities.store(alice, bytes(2)) }
        assertContentEquals(bytes(1), storage.remoteIdentities.identityKey(alice))
    }

    @Test
    fun remoteIdentitiesArePerDevice() = runTest {
        val storage = newStorage()
        val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
        storage.remoteIdentities.store(bob, bytes(1))
        storage.remoteIdentities.store(bobPhone, bytes(2))

        assertContentEquals(bytes(1), storage.remoteIdentities.identityKey(bob))
        assertContentEquals(bytes(2), storage.remoteIdentities.identityKey(bobPhone))
        assertNull(storage.remoteIdentities.identityKey(alice))
    }

    @Test
    fun rolledBackTransactionLeavesNoPin() = runTest {
        val storage = newStorage()
        assertFailsWith<Failure> {
            storage.transaction {
                remoteIdentities.store(alice, bytes(1))
                assertContentEquals(bytes(1), remoteIdentities.identityKey(alice))
                throw Failure()
            }
        }
        assertNull(storage.remoteIdentities.identityKey(alice))

        // Not pinned, so a different key can still be the first one.
        storage.remoteIdentities.store(alice, bytes(2))
        assertContentEquals(bytes(2), storage.remoteIdentities.identityKey(alice))
    }

    @Test
    fun newPinIsUnverifiedAndVerificationRoundTrips() = runTest {
        val storage = newStorage()
        assertNull(storage.remoteIdentities.record(alice))
        storage.remoteIdentities.store(alice, bytes(1))
        assertRecord(storage, alice, bytes(1), VerificationState.UNVERIFIED)

        storage.remoteIdentities.setVerification(alice, bytes(1), VerificationState.VERIFIED)
        assertRecord(storage, alice, bytes(1), VerificationState.VERIFIED)
        storage.remoteIdentities.store(alice, bytes(1))
        assertRecord(storage, alice, bytes(1), VerificationState.VERIFIED, "storing the same key again keeps its verification")

        storage.remoteIdentities.setVerification(alice, bytes(1), VerificationState.UNVERIFIED)
        assertRecord(storage, alice, bytes(1), VerificationState.UNVERIFIED)
    }

    @Test
    fun verificationIsBoundToThePinnedKey() = runTest {
        val storage = newStorage()
        assertFailsWith<IllegalStateException> { storage.remoteIdentities.setVerification(alice, bytes(1), VerificationState.VERIFIED) }
        assertNull(storage.remoteIdentities.record(alice), "no pin is created")

        storage.remoteIdentities.store(alice, bytes(1))
        assertFailsWith<IllegalStateException> { storage.remoteIdentities.setVerification(alice, bytes(2), VerificationState.VERIFIED) }
        assertRecord(storage, alice, bytes(1), VerificationState.UNVERIFIED)
    }

    @Test
    fun verificationIsPerDevice() = runTest {
        val storage = newStorage()
        val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
        storage.remoteIdentities.store(bob, bytes(1))
        storage.remoteIdentities.store(bobPhone, bytes(2))
        storage.remoteIdentities.setVerification(bob, bytes(1), VerificationState.VERIFIED)
        assertRecord(storage, bob, bytes(1), VerificationState.VERIFIED)
        assertRecord(storage, bobPhone, bytes(2), VerificationState.UNVERIFIED)
    }

    @Test
    fun replacedPinStartsUnverified() = runTest {
        val storage = newStorage()
        storage.remoteIdentities.store(alice, bytes(1))
        storage.remoteIdentities.store(bob, bytes(5))
        storage.remoteIdentities.setVerification(alice, bytes(1), VerificationState.VERIFIED)
        storage.remoteIdentities.setVerification(bob, bytes(5), VerificationState.VERIFIED)

        storage.remoteIdentities.replace(alice, bytes(1), bytes(2))
        assertRecord(storage, alice, bytes(2), VerificationState.UNVERIFIED, "verification never moves to the new key")
        assertContentEquals(bytes(2), storage.remoteIdentities.identityKey(alice))
        assertRecord(storage, bob, bytes(5), VerificationState.VERIFIED, "other devices are not touched")

        // The old key is gone: verifying it or storing it fails.
        assertFailsWith<IllegalStateException> { storage.remoteIdentities.setVerification(alice, bytes(1), VerificationState.VERIFIED) }
        assertFailsWith<IllegalStateException> { storage.remoteIdentities.store(alice, bytes(1)) }
        storage.remoteIdentities.setVerification(alice, bytes(2), VerificationState.VERIFIED)
        assertRecord(storage, alice, bytes(2), VerificationState.VERIFIED)
    }

    @Test
    fun replaceIsACompareAndSet() = runTest {
        val storage = newStorage()
        assertFailsWith<IllegalStateException> { storage.remoteIdentities.replace(alice, bytes(1), bytes(2)) }
        assertNull(storage.remoteIdentities.record(alice), "replace never creates a pin")

        storage.remoteIdentities.store(alice, bytes(1))
        storage.remoteIdentities.setVerification(alice, bytes(1), VerificationState.VERIFIED)
        storage.remoteIdentities.replace(alice, bytes(1), bytes(2))
        // A second change based on the old pin loses.
        assertFailsWith<IllegalStateException> { storage.remoteIdentities.replace(alice, bytes(1), bytes(3)) }
        assertRecord(storage, alice, bytes(2), VerificationState.UNVERIFIED)
        assertFailsWith<IllegalArgumentException> { storage.remoteIdentities.replace(alice, bytes(2), bytes(2)) }
        assertRecord(storage, alice, bytes(2), VerificationState.UNVERIFIED)
    }

    @Test
    fun remoteIdentityBytesAreCopied() = runTest {
        val storage = newStorage()
        val key = bytes(1)
        storage.remoteIdentities.store(alice, key)
        key[0] = 99
        assertContentEquals(bytes(1), storage.remoteIdentities.record(alice)?.identityKey)
        storage.remoteIdentities.record(alice)!!.identityKey[0] = 99
        storage.remoteIdentities.identityKey(alice)!![0] = 99
        assertContentEquals(bytes(1), storage.remoteIdentities.identityKey(alice))

        val replacement = bytes(2)
        storage.remoteIdentities.replace(alice, bytes(1), replacement)
        replacement[0] = 99
        assertContentEquals(bytes(2), storage.remoteIdentities.identityKey(alice))
    }

    @Test
    fun rolledBackTransactionKeepsPinAndVerification() = runTest {
        val storage = newStorage()
        storage.remoteIdentities.store(alice, bytes(1))
        storage.remoteIdentities.setVerification(alice, bytes(1), VerificationState.VERIFIED)
        assertFailsWith<Failure> {
            storage.transaction {
                remoteIdentities.replace(alice, bytes(1), bytes(2))
                assertRecord(this, alice, bytes(2), VerificationState.UNVERIFIED)
                throw Failure()
            }
        }
        assertRecord(storage, alice, bytes(1), VerificationState.VERIFIED)

        assertFailsWith<Failure> {
            storage.transaction {
                remoteIdentities.setVerification(alice, bytes(1), VerificationState.UNVERIFIED)
                throw Failure()
            }
        }
        assertRecord(storage, alice, bytes(1), VerificationState.VERIFIED)
    }

    @Test
    fun sessionInitiationsAreRetiredPerDevice() = runTest {
        val storage = newStorage()
        val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
        assertFalse(storage.sessionInitiations.isRetired(bob, initiation(1)))

        storage.sessionInitiations.retire(bob, initiation(1), null)
        storage.sessionInitiations.retire(bob, initiation(1), null)
        storage.sessionInitiations.retire(bob, initiation(2), SignedPreKeyId(3))

        assertTrue(storage.sessionInitiations.isRetired(bob, initiation(1)))
        assertTrue(storage.sessionInitiations.isRetired(bob, SessionInitiationId(bytes(1))), "compared by content")
        assertTrue(storage.sessionInitiations.isRetired(bob, initiation(2)))
        assertFalse(storage.sessionInitiations.isRetired(bob, initiation(3)))
        assertFalse(storage.sessionInitiations.isRetired(bobPhone, initiation(1)))
        assertFalse(storage.sessionInitiations.isRetired(alice, initiation(1)))
    }

    @Test
    fun rolledBackTransactionRetiresNothing() = runTest {
        val storage = newStorage()
        assertFailsWith<Failure> {
            storage.transaction {
                sessionInitiations.retire(alice, initiation(1), SignedPreKeyId(1))
                sessions.store(SecureSession(alice, bytes(1)))
                assertTrue(sessionInitiations.isRetired(alice, initiation(1)))
                throw Failure()
            }
        }
        assertFalse(storage.sessionInitiations.isRetired(alice, initiation(1)))
        assertNull(storage.sessions.load(alice))
    }

    @Test
    fun sessionsAreStoredReplacedAndRemoved() = runTest {
        val storage = newStorage()
        storage.sessions.store(SecureSession(alice, bytes(1)))
        storage.sessions.store(SecureSession(bob, bytes(2)))
        storage.sessions.store(SecureSession(alice, bytes(3)))

        assertContentEquals(bytes(3), storage.sessions.load(alice)?.state)
        assertContentEquals(bytes(2), storage.sessions.load(bob)?.state)

        storage.sessions.remove(alice)
        assertNull(storage.sessions.load(alice))
        assertNotNull(storage.sessions.load(bob))
    }

    @Test
    fun replacedSignedPreKeysStayAvailableById() = runTest {
        val storage = newStorage()
        assertNull(storage.preKeys.currentSignedPreKey())
        assertNull(storage.preKeys.highestSignedPreKeyId())

        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(1))

        val current = assertNotNull(storage.preKeys.currentSignedPreKey())
        assertEquals(SignedPreKeyId(1), current.id)
        assertContentEquals(bytes(12), current.signature)
        assertContentEquals(bytes(-1), current.privateKey)
        assertContentEquals(bytes(0), storage.preKeys.signedPreKey(SignedPreKeyId(0))?.publicKey)
        assertEquals(SignedPreKeyId(1), storage.preKeys.highestSignedPreKeyId())
    }

    @Test
    fun signedPreKeyIdsCannotBeReused() = runTest {
        val storage = newStorage()
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(5), at(5))

        assertFailsWith<IllegalArgumentException> { storage.preKeys.storeCurrentSignedPreKey(signedPreKey(5), at(5)) }
        assertFailsWith<IllegalArgumentException> { storage.preKeys.storeCurrentSignedPreKey(signedPreKey(4), at(4)) }
        assertEquals(SignedPreKeyId(5), storage.preKeys.currentSignedPreKey()?.id)
    }

    @Test
    fun signedPreKeyLifecycleTimestampsAreRecorded() = runTest {
        val storage = newStorage()
        assertEquals(emptyList(), storage.preKeys.signedPreKeyInfos())

        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(10))
        assertEquals(listOf(SignedPreKeyInfo(SignedPreKeyId(0), true, at(10), null)), storage.preKeys.signedPreKeyInfos())

        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(20))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(2), at(30))
        assertEquals(
            listOf(
                SignedPreKeyInfo(SignedPreKeyId(0), false, at(10), at(20)),
                SignedPreKeyInfo(SignedPreKeyId(1), false, at(20), at(30)),
                SignedPreKeyInfo(SignedPreKeyId(2), true, at(30), null),
            ),
            storage.preKeys.signedPreKeyInfos(),
        )
        assertEquals(SignedPreKeyInfo(SignedPreKeyId(1), false, at(20), at(30)), storage.preKeys.signedPreKeyInfo(SignedPreKeyId(1)))
        assertNull(storage.preKeys.signedPreKeyInfo(SignedPreKeyId(3)))
    }

    @Test
    fun stampingDoesNotChangeKeysThatHaveTimestamps() = runTest {
        val storage = newStorage()
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(10))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(20))
        val before = storage.preKeys.signedPreKeyInfos()

        storage.preKeys.stampLegacySignedPreKeys(at(99))
        assertEquals(before, storage.preKeys.signedPreKeyInfos())
    }

    @Test
    fun removedSignedPreKeyIsGoneButItsIdStaysUsed() = runTest {
        val storage = newStorage()
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(1))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(2), at(2))

        assertFailsWith<IllegalArgumentException> { storage.preKeys.removeSignedPreKey(SignedPreKeyId(2)) }
        assertNotNull(storage.preKeys.signedPreKey(SignedPreKeyId(2)))

        storage.preKeys.removeSignedPreKey(SignedPreKeyId(0))
        storage.preKeys.removeSignedPreKey(SignedPreKeyId(0))
        storage.preKeys.removeSignedPreKey(SignedPreKeyId(7))
        assertNull(storage.preKeys.signedPreKey(SignedPreKeyId(0)))
        assertNull(storage.preKeys.signedPreKeyInfo(SignedPreKeyId(0)))
        assertEquals(listOf(1, 2), storage.preKeys.signedPreKeyInfos().map { it.id.value })
        assertNotNull(storage.preKeys.signedPreKey(SignedPreKeyId(1)))
        assertEquals(SignedPreKeyId(2), storage.preKeys.highestSignedPreKeyId())
        assertEquals(SignedPreKeyId(2), storage.preKeys.currentSignedPreKey()?.id)

        assertFailsWith<IllegalArgumentException> { storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(3)) }
        assertNull(storage.preKeys.signedPreKey(SignedPreKeyId(0)), "a deleted ID is never stored again")
    }

    @Test
    fun retiredInitiationsArePrunedPerSignedPreKey() = runTest {
        val storage = newStorage()
        val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
        storage.sessionInitiations.retire(alice, initiation(1), SignedPreKeyId(1))
        storage.sessionInitiations.retire(bob, initiation(2), SignedPreKeyId(1))
        storage.sessionInitiations.retire(bobPhone, initiation(3), SignedPreKeyId(2))
        storage.sessionInitiations.retire(bob, initiation(4), null)
        // Retiring again keeps the first entry.
        storage.sessionInitiations.retire(bob, initiation(4), SignedPreKeyId(1))
        assertEquals(setOf(SignedPreKeyId(1), SignedPreKeyId(2)), storage.sessionInitiations.retiredSignedPreKeyIds())

        storage.sessionInitiations.removeRetiredFor(SignedPreKeyId(1))

        assertFalse(storage.sessionInitiations.isRetired(alice, initiation(1)))
        assertFalse(storage.sessionInitiations.isRetired(bob, initiation(2)))
        assertTrue(storage.sessionInitiations.isRetired(bobPhone, initiation(3)))
        assertTrue(storage.sessionInitiations.isRetired(bob, initiation(4)), "entries without a signed prekey are kept")
        assertEquals(setOf(SignedPreKeyId(2)), storage.sessionInitiations.retiredSignedPreKeyIds())
    }

    @Test
    fun rolledBackTransactionKeepsSignedPreKeysAndRetiredInitiations() = runTest {
        val storage = newStorage()
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(1))
        storage.sessionInitiations.retire(alice, initiation(1), SignedPreKeyId(0))
        val before = storage.preKeys.signedPreKeyInfos()

        assertFailsWith<Failure> {
            storage.transaction {
                preKeys.removeSignedPreKey(SignedPreKeyId(0))
                sessionInitiations.removeRetiredFor(SignedPreKeyId(0))
                preKeys.storeCurrentSignedPreKey(signedPreKey(2), at(2))
                preKeys.stampLegacySignedPreKeys(at(3))
                throw Failure()
            }
        }
        assertEquals(before, storage.preKeys.signedPreKeyInfos())
        assertNotNull(storage.preKeys.signedPreKey(SignedPreKeyId(0)))
        assertEquals(SignedPreKeyId(1), storage.preKeys.highestSignedPreKeyId())
        assertTrue(storage.sessionInitiations.isRetired(alice, initiation(1)))
    }

    @Test
    fun oneTimePreKeysAreListedCountedAndRemoved() = runTest {
        val storage = newStorage()
        assertEquals(0, storage.preKeys.oneTimePreKeyCount())
        assertNull(storage.preKeys.highestOneTimePreKeyId())

        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(2), oneTimePreKey(0), oneTimePreKey(1)))
        assertEquals(3, storage.preKeys.oneTimePreKeyCount())
        val published = storage.preKeys.publicOneTimePreKeys()
        assertEquals(listOf(0, 1, 2), published.map { it.id.value })
        assertContentEquals(bytes(1), published[1].publicKey)
        assertContentEquals(bytes(-1), storage.preKeys.oneTimePreKey(OneTimePreKeyId(1))?.privateKey)

        storage.preKeys.removeOneTimePreKey(OneTimePreKeyId(1))
        assertNull(storage.preKeys.oneTimePreKey(OneTimePreKeyId(1)))
        assertEquals(2, storage.preKeys.oneTimePreKeyCount())
        assertEquals(OneTimePreKeyId(2), storage.preKeys.highestOneTimePreKeyId(), "removal keeps the high-water mark")
    }

    @Test
    fun oneTimePreKeyIdsCannotBeReused() = runTest {
        val storage = newStorage()
        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0), oneTimePreKey(1)))
        storage.preKeys.removeOneTimePreKey(OneTimePreKeyId(1))

        assertFailsWith<IllegalArgumentException> { storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(1))) }
        assertFailsWith<IllegalArgumentException> {
            storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(3), oneTimePreKey(3)))
        }
        assertEquals(1, storage.preKeys.oneTimePreKeyCount())
        assertEquals(OneTimePreKeyId(1), storage.preKeys.highestOneTimePreKeyId())

        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(2)))
        assertEquals(OneTimePreKeyId(2), storage.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun maxIdIsAccepted() = runTest {
        val storage = newStorage()
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(Int.MAX_VALUE), at(0))
        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(Int.MAX_VALUE)))

        assertEquals(SignedPreKeyId(Int.MAX_VALUE), storage.preKeys.highestSignedPreKeyId())
        assertEquals(OneTimePreKeyId(Int.MAX_VALUE), storage.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun successfulTransactionCommitsAllWrites() = runTest {
        val storage = newStorage()
        val result = storage.transaction {
            identity.store(identity(1))
            sessions.store(SecureSession(alice, bytes(1)))
            preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
            preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))
            "done"
        }

        assertEquals("done", result)
        assertNotNull(storage.identity.identity())
        assertNotNull(storage.sessions.load(alice))
        assertNotNull(storage.preKeys.currentSignedPreKey())
        assertEquals(1, storage.preKeys.oneTimePreKeyCount())
    }

    @Test
    fun failedTransactionOnEmptyStorageLeavesItEmpty() = runTest {
        val storage = newStorage()
        assertFailsWith<Failure> {
            storage.transaction {
                identity.store(identity(1))
                sessions.store(SecureSession(alice, bytes(1)))
                preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
                preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))
                throw Failure()
            }
        }

        assertNull(storage.identity.identity())
        assertNull(storage.sessions.load(alice))
        assertNull(storage.preKeys.currentSignedPreKey())
        assertNull(storage.preKeys.signedPreKey(SignedPreKeyId(0)))
        assertNull(storage.preKeys.highestSignedPreKeyId())
        assertEquals(0, storage.preKeys.oneTimePreKeyCount())
        assertNull(storage.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun failedTransactionRollsBackEveryKindOfChange() = runTest {
        val storage = newStorage()
        storage.transaction {
            identity.store(identity(1))
            sessions.store(SecureSession(alice, bytes(1)))
            sessions.store(SecureSession(bob, bytes(2)))
            preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
            preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0), oneTimePreKey(1)))
        }

        assertFailsWith<Failure> {
            storage.transaction {
                sessions.store(SecureSession(alice, bytes(9)))
                sessions.remove(bob)
                preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(1))
                preKeys.removeOneTimePreKey(OneTimePreKeyId(0))
                preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(2)))
                throw Failure()
            }
        }

        assertContentEquals(bytes(1), storage.identity.identity()?.publicKey)
        assertContentEquals(bytes(1), storage.sessions.load(alice)?.state)
        assertContentEquals(bytes(2), storage.sessions.load(bob)?.state)
        assertEquals(SignedPreKeyId(0), storage.preKeys.currentSignedPreKey()?.id)
        assertNull(storage.preKeys.signedPreKey(SignedPreKeyId(1)))
        assertEquals(SignedPreKeyId(0), storage.preKeys.highestSignedPreKeyId())
        assertNotNull(storage.preKeys.oneTimePreKey(OneTimePreKeyId(0)))
        assertNull(storage.preKeys.oneTimePreKey(OneTimePreKeyId(2)))
        assertEquals(2, storage.preKeys.oneTimePreKeyCount())
        assertEquals(OneTimePreKeyId(1), storage.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun rejectedWriteInsideTransactionRollsBackEarlierWrites() = runTest {
        val storage = newStorage()
        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))

        assertFailsWith<IllegalArgumentException> {
            storage.transaction {
                sessions.store(SecureSession(alice, bytes(1)))
                preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))
            }
        }
        assertNull(storage.sessions.load(alice))
    }

    @Test
    fun writesAreVisibleInsideTheTransaction() = runTest {
        val storage = newStorage()
        storage.transaction {
            preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))
            assertEquals(1, preKeys.oneTimePreKeyCount())
            preKeys.removeOneTimePreKey(OneTimePreKeyId(0))
            assertNull(preKeys.oneTimePreKey(OneTimePreKeyId(0)))
        }
        assertEquals(0, storage.preKeys.oneTimePreKeyCount())
    }

    @Test
    fun nestedTransactionsJoinTheOuterOne() = runTest {
        val storage = newStorage()
        assertFailsWith<Failure> {
            storage.transaction {
                transaction { sessions.store(SecureSession(alice, bytes(1))) }
                // The storage object itself also joins instead of deadlocking.
                storage.sessions.store(SecureSession(bob, bytes(2)))
                assertNotNull(storage.sessions.load(alice))
                throw Failure()
            }
        }
        assertNull(storage.sessions.load(alice))
        assertNull(storage.sessions.load(bob))
    }

    @Test
    fun storedBytesAreNotAliased() = runTest {
        val storage = newStorage()
        val identity = identity(1)
        val session = SecureSession(alice, bytes(1))
        val oneTimePreKey = oneTimePreKey(0)
        storage.identity.store(identity)
        storage.sessions.store(session)
        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey))

        identity.privateKey.fill(0)
        session.state.fill(0)
        oneTimePreKey.privateKey.fill(0)
        assertContentEquals(bytes(-1), storage.identity.identity()?.privateKey)
        assertContentEquals(bytes(1), storage.sessions.load(alice)?.state)
        assertContentEquals(bytes(-1), storage.preKeys.oneTimePreKey(OneTimePreKeyId(0))?.privateKey)

        val remoteKey = bytes(5)
        storage.remoteIdentities.store(bob, remoteKey)
        remoteKey.fill(0)
        assertContentEquals(bytes(5), storage.remoteIdentities.identityKey(bob))
        storage.remoteIdentities.identityKey(bob)!!.fill(0)
        assertContentEquals(bytes(5), storage.remoteIdentities.identityKey(bob))

        storage.identity.identity()!!.privateKey.fill(0)
        storage.sessions.load(alice)!!.state.fill(0)
        storage.preKeys.oneTimePreKey(OneTimePreKeyId(0))!!.privateKey.fill(0)
        assertContentEquals(bytes(-1), storage.identity.identity()?.privateKey)
        assertContentEquals(bytes(1), storage.sessions.load(alice)?.state)
        assertContentEquals(bytes(-1), storage.preKeys.oneTimePreKey(OneTimePreKeyId(0))?.privateKey)
    }

    // Message reliability state (docs/message-reliability.md)

    @Test
    fun pendingMessagesAreListedInSendOrderPerRecipient() = runTest {
        val storage = newStorage()
        val first = storage.pendingOutbound.store(bob, messageId(3), bytes(3))
        val other = storage.pendingOutbound.store(alice, messageId(1), bytes(1))
        val second = storage.pendingOutbound.store(bob, messageId(1), bytes(1))
        val third = storage.pendingOutbound.store(bob, messageId(2), bytes(2))

        assertTrue(first < other && other < second && second < third)
        // Send order, not ID order.
        assertEquals(listOf(messageId(3), messageId(1), messageId(2)), storage.pendingOutbound.list(bob).map { it.id })
        assertEquals(listOf(first, second, third), storage.pendingOutbound.list(bob).map { it.sequence })
        assertEquals(listOf(messageId(1)), storage.pendingOutbound.list(alice).map { it.id })
        val loaded = assertNotNull(storage.pendingOutbound.get(bob, messageId(1)))
        assertEquals(bob, loaded.recipient)
        assertEquals(second, loaded.sequence)
        assertContentEquals(bytes(1), loaded.frame)
    }

    @Test
    fun pendingMessagesAreScopedByRecipient() = runTest {
        val storage = newStorage()
        storage.pendingOutbound.store(alice, messageId(1), bytes(1))
        storage.pendingOutbound.store(bob, messageId(1), bytes(2))

        assertNull(storage.pendingOutbound.get(DeviceAddress(UserId("bob"), DeviceId("phone")), messageId(1)))
        assertTrue(storage.pendingOutbound.remove(bob, messageId(1)))
        assertNull(storage.pendingOutbound.get(bob, messageId(1)))
        assertContentEquals(bytes(1), storage.pendingOutbound.get(alice, messageId(1))?.frame)
    }

    @Test
    fun pendingMessageIsStoredOncePerRecipient() = runTest {
        val storage = newStorage()
        storage.pendingOutbound.store(bob, messageId(1), bytes(1))
        assertFailsWith<IllegalArgumentException> { storage.pendingOutbound.store(bob, messageId(1), bytes(2)) }
        assertContentEquals(bytes(1), storage.pendingOutbound.get(bob, messageId(1))?.frame)
        assertEquals(1, storage.pendingOutbound.list(bob).size)
    }

    @Test
    fun removingAPendingMessageIsIdempotentAndSequencesAreNotReused() = runTest {
        val storage = newStorage()
        val first = storage.pendingOutbound.store(bob, messageId(1), bytes(1))
        val second = storage.pendingOutbound.store(bob, messageId(2), bytes(2))

        assertTrue(storage.pendingOutbound.remove(bob, messageId(2)))
        assertFalse(storage.pendingOutbound.remove(bob, messageId(2)))
        assertFalse(storage.pendingOutbound.remove(bob, messageId(9)))
        val third = storage.pendingOutbound.store(bob, messageId(3), bytes(3))

        assertTrue(third > second)
        assertEquals(listOf(first, third), storage.pendingOutbound.list(bob).map { it.sequence })
        // The same ID may become pending again once removed.
        storage.pendingOutbound.store(bob, messageId(2), bytes(4))
        assertEquals(listOf(messageId(1), messageId(3), messageId(2)), storage.pendingOutbound.list(bob).map { it.id })
    }

    @Test
    fun processedMessagesAreScopedBySenderAndRecordedOnce() = runTest {
        val storage = newStorage()
        assertFalse(storage.processedInbound.isProcessed(alice, messageId(1)))
        assertNull(storage.processedInbound.get(alice, messageId(1)))

        storage.processedInbound.markCommitted(alice, messageId(1), bytes(1), at(1))
        assertFailsWith<IllegalArgumentException> { storage.processedInbound.markCommitted(alice, messageId(1), bytes(2), at(2)) }

        assertTrue(storage.processedInbound.isProcessed(alice, messageId(1)))
        assertFalse(storage.processedInbound.isProcessed(bob, messageId(1)))
        assertFalse(storage.processedInbound.isProcessed(alice, messageId(2)))
        val entry = assertNotNull(storage.processedInbound.get(alice, messageId(1)))
        assertEquals(alice, entry.sender)
        assertEquals(messageId(1), entry.id)
        assertContentEquals(bytes(1), entry.digest, "the first entry is kept")
        assertEquals(at(1), entry.finalizedAt)
    }

    @Test
    fun processedDigestsAreNotAliased() = runTest {
        val storage = newStorage()
        val digest = bytes(1)
        storage.processedInbound.markCommitted(alice, messageId(1), digest, at(1))
        digest.fill(0)
        storage.processedInbound.get(alice, messageId(1))!!.digest!!.fill(0)
        assertContentEquals(bytes(1), storage.processedInbound.get(alice, messageId(1))?.digest)
    }

    @Test
    fun pruningRemovesEntriesCommittedAtOrBeforeTheCutoffOnly() = runTest {
        val storage = newStorage()
        storage.processedInbound.markCommitted(alice, messageId(1), bytes(1), at(10))
        storage.processedInbound.markCommitted(bob, messageId(2), bytes(2), at(20))
        storage.processedInbound.markCommitted(alice, messageId(3), bytes(3), at(30))
        storage.pendingInbound.store(alice, messageId(4), bytes(4), at(0))

        assertEquals(0, storage.processedInbound.pruneFinalizedAtOrBefore(at(10) - 1.milliseconds))
        assertEquals(2, storage.processedInbound.pruneFinalizedAtOrBefore(at(20)), "the cutoff itself is included")
        assertFalse(storage.processedInbound.isProcessed(alice, messageId(1)))
        assertFalse(storage.processedInbound.isProcessed(bob, messageId(2)))
        assertTrue(storage.processedInbound.isProcessed(alice, messageId(3)))
        assertEquals(0, storage.processedInbound.pruneFinalizedAtOrBefore(at(20)))
        assertEquals(1, storage.processedInbound.pruneFinalizedAtOrBefore(at(1_000)))
        assertTrue(storage.pendingInbound.contains(alice, messageId(4)), "pending messages are never pruned")
    }

    @Test
    fun stampingLegacyCommitTimesNeverChangesAStampedTime() = runTest {
        val storage = newStorage()
        storage.processedInbound.markCommitted(alice, messageId(1), bytes(1), at(10))
        // New entries always have a time; adapters with legacy rows test them separately.
        assertEquals(0, storage.processedInbound.stampLegacyCommitTimes(at(99)))
        assertEquals(at(10), storage.processedInbound.get(alice, messageId(1))?.finalizedAt)
    }

    @Test
    fun pendingInboundMessagesAreListedInAcceptanceOrder() = runTest {
        val storage = newStorage()
        val first = storage.pendingInbound.store(bob, messageId(3), bytes(3), at(3))
        val other = storage.pendingInbound.store(alice, messageId(1), bytes(1), at(1))
        val second = storage.pendingInbound.store(bob, messageId(1), bytes(5), at(5))

        assertTrue(first < other && other < second)
        assertEquals(listOf(bob to messageId(3), alice to messageId(1), bob to messageId(1)), storage.pendingInbound.page(0, 1_000).map { it.sender to it.id })
        assertEquals(listOf(messageId(3), messageId(1)), storage.pendingInbound.page(0, 1_000, bob).map { it.id })
        assertEquals(listOf(first, second), storage.pendingInbound.page(0, 1_000, bob).map { it.sequence })
        val loaded = assertNotNull(storage.pendingInbound.get(bob, messageId(1)))
        assertEquals(bob, loaded.sender)
        assertEquals(second, loaded.sequence)
        assertEquals(at(5), loaded.receivedAt)
        assertContentEquals(bytes(5), loaded.frame)
        assertTrue(storage.pendingInbound.contains(bob, messageId(1)))
        assertFalse(storage.pendingInbound.contains(DeviceAddress(UserId("bob"), DeviceId("phone")), messageId(1)))
    }

    @Test
    fun pendingInboundMessageIsStoredOncePerSender() = runTest {
        val storage = newStorage()
        storage.pendingInbound.store(bob, messageId(1), bytes(1), at(1))
        assertFailsWith<IllegalArgumentException> { storage.pendingInbound.store(bob, messageId(1), bytes(2), at(2)) }
        val kept = assertNotNull(storage.pendingInbound.get(bob, messageId(1)))
        assertContentEquals(bytes(1), kept.frame)
        assertEquals(at(1), kept.receivedAt)
        assertEquals(1, storage.pendingInbound.page(0, 1_000).size)
        // Another sender with the same ID is another message.
        storage.pendingInbound.store(alice, messageId(1), bytes(2), at(2))
        assertEquals(2, storage.pendingInbound.page(0, 1_000).size)
    }

    @Test
    fun removingAPendingInboundMessageIsIdempotentAndSequencesAreNotReused() = runTest {
        val storage = newStorage()
        val first = storage.pendingInbound.store(bob, messageId(1), bytes(1), at(1))
        val second = storage.pendingInbound.store(bob, messageId(2), bytes(2), at(2))
        assertTrue(storage.pendingInbound.remove(bob, messageId(2)))
        assertFalse(storage.pendingInbound.remove(bob, messageId(2)))
        assertFalse(storage.pendingInbound.remove(alice, messageId(1)))
        val third = storage.pendingInbound.store(bob, messageId(3), bytes(3), at(3))
        assertTrue(third > second)
        assertEquals(listOf(first, third), storage.pendingInbound.page(0, 1_000).map { it.sequence })
        // Pending inbound and outbound sequences are independent stores.
        storage.pendingOutbound.store(bob, messageId(1), bytes(1))
        assertTrue(storage.pendingInbound.store(bob, messageId(4), bytes(4), at(4)) > third)
    }

    @Test
    fun pendingInboundFramesAreNotAliased() = runTest {
        val storage = newStorage()
        val frame = bytes(1)
        storage.pendingInbound.store(bob, messageId(1), frame, at(1))
        frame.fill(0)
        storage.pendingInbound.get(bob, messageId(1))!!.frame.fill(0)
        storage.pendingInbound.page(0, 1_000).single().frame.fill(0)
        storage.pendingInbound.page(0, 1_000, bob).single().frame.fill(0)
        assertContentEquals(bytes(1), storage.pendingInbound.get(bob, messageId(1))?.frame)
    }

    @Test
    fun pendingInboundPagesFollowTheSequenceCursor() = runTest {
        val storage = newStorage()
        val sequences = (1..7).map { storage.pendingInbound.store(if (it % 2 == 0) alice else bob, messageId(it), bytes(it), at(it)) }

        val first = storage.pendingInbound.page(0, 3)
        assertEquals(sequences.take(3), first.map { it.sequence })
        val second = storage.pendingInbound.page(first.last().sequence, 3)
        assertEquals(sequences.subList(3, 6), second.map { it.sequence }, "strictly after the cursor: the last row is not repeated")
        assertEquals(sequences.drop(6), storage.pendingInbound.page(second.last().sequence, 3).map { it.sequence })
        assertEquals(emptyList(), storage.pendingInbound.page(sequences.last(), 3))
        assertEquals(sequences, storage.pendingInbound.page(0, 7).map { it.sequence }, "ascending order")
        assertEquals(1, storage.pendingInbound.page(0, 1).size, "the limit is honored")
        assertEquals(listOf(messageId(2)), storage.pendingInbound.page(0, 1, alice).map { it.id })
        assertEquals(bytes(4).toList(), storage.pendingInbound.page(sequences[1], 1, alice).single().frame.toList())
        assertEquals(7L, storage.pendingInbound.count())
        assertEquals(3L, storage.pendingInbound.count(alice))
        assertEquals(4L, storage.pendingInbound.count(bob))
        assertEquals(0L, storage.pendingInbound.count(DeviceAddress(UserId("carol"), DeviceId("phone"))))
    }

    @Test
    fun pendingInboundPagesRejectInvalidBounds() = runTest {
        val storage = newStorage()
        storage.pendingInbound.store(bob, messageId(1), bytes(1), at(1))
        assertFailsWith<IllegalArgumentException> { storage.pendingInbound.page(0, 0) }
        assertFailsWith<IllegalArgumentException> { storage.pendingInbound.page(0, -1) }
        assertFailsWith<IllegalArgumentException> { storage.pendingInbound.page(-1, 1) }
    }

    @Test
    fun pendingInboundPagesAreStableWhenEntriesDisappearOrArrive() = runTest {
        val storage = newStorage()
        val sequences = (1..10).map { storage.pendingInbound.store(bob, messageId(it), bytes(it), at(it)) }
        val first = storage.pendingInbound.page(0, 4)
        assertEquals(sequences.take(4), first.map { it.sequence })
        // Finalized between pages: one already returned, two not yet returned.
        storage.pendingInbound.remove(bob, messageId(2))
        storage.pendingInbound.remove(bob, messageId(5))
        storage.pendingInbound.remove(bob, messageId(6))
        val arrived = storage.pendingInbound.store(alice, messageId(11), bytes(11), at(11))

        val rest = storage.pendingInbound.page(first.last().sequence, 100)
        assertEquals(listOf(sequences[6], sequences[7], sequences[8], sequences[9], arrived), rest.map { it.sequence })
        assertEquals(listOf(sequences[6], sequences[7], sequences[8], sequences[9]), storage.pendingInbound.page(first.last().sequence, 100, bob).map { it.sequence })
        val seen = (first + rest).map { it.sequence }
        assertEquals(seen.distinct(), seen, "no message twice")
    }

    @Test
    fun discardedMessagesKeepTheirReasonAndOutcome() = runTest {
        val storage = newStorage()
        storage.processedInbound.markDiscarded(alice, messageId(1), bytes(1), at(10), MessageDiscardReason.POLICY_REJECTED)
        storage.processedInbound.markCommitted(alice, messageId(2), bytes(2), at(20))

        val discarded = assertNotNull(storage.processedInbound.get(alice, messageId(1)))
        assertEquals(InboundFinalization.DISCARDED, discarded.finalization)
        assertEquals(MessageDiscardReason.POLICY_REJECTED, discarded.discardReason)
        assertEquals(at(10), discarded.finalizedAt)
        assertContentEquals(bytes(1), discarded.digest)
        assertTrue(storage.processedInbound.isProcessed(alice, messageId(1)))
        assertFalse(storage.processedInbound.isProcessed(bob, messageId(1)))

        val committed = assertNotNull(storage.processedInbound.get(alice, messageId(2)))
        assertEquals(InboundFinalization.COMMITTED, committed.finalization)
        assertNull(committed.discardReason)

        for (reason in MessageDiscardReason.entries) {
            storage.processedInbound.markDiscarded(bob, messageId(100 + reason.ordinal), bytes(3), at(30), reason)
            assertEquals(reason, storage.processedInbound.get(bob, messageId(100 + reason.ordinal))?.discardReason)
        }
    }

    @Test
    fun terminalOutcomeIsNeverReplaced() = runTest {
        val storage = newStorage()
        storage.processedInbound.markDiscarded(alice, messageId(1), bytes(1), at(10), MessageDiscardReason.USER_REJECTED)
        storage.processedInbound.markCommitted(alice, messageId(2), bytes(2), at(20))

        assertFailsWith<IllegalArgumentException> { storage.processedInbound.markCommitted(alice, messageId(1), bytes(1), at(11)) }
        assertFailsWith<IllegalArgumentException> {
            storage.processedInbound.markDiscarded(alice, messageId(1), bytes(1), at(11), MessageDiscardReason.OTHER)
        }
        assertFailsWith<IllegalArgumentException> {
            storage.processedInbound.markDiscarded(alice, messageId(2), bytes(2), at(21), MessageDiscardReason.OTHER)
        }

        val discarded = assertNotNull(storage.processedInbound.get(alice, messageId(1)))
        assertEquals(InboundFinalization.DISCARDED, discarded.finalization)
        assertEquals(MessageDiscardReason.USER_REJECTED, discarded.discardReason)
        assertEquals(at(10), discarded.finalizedAt)
        val committed = assertNotNull(storage.processedInbound.get(alice, messageId(2)))
        assertEquals(InboundFinalization.COMMITTED, committed.finalization)
        assertNull(committed.discardReason)
        assertEquals(at(20), committed.finalizedAt)
    }

    @Test
    fun pruningRemovesDiscardedAndCommittedEntriesAlikeButNeverPending() = runTest {
        val storage = newStorage()
        storage.processedInbound.markDiscarded(alice, messageId(1), bytes(1), at(10), MessageDiscardReason.OTHER)
        storage.processedInbound.markCommitted(alice, messageId(2), bytes(2), at(10))
        storage.processedInbound.markDiscarded(alice, messageId(3), bytes(3), at(11), MessageDiscardReason.OTHER)
        storage.pendingInbound.store(alice, messageId(4), bytes(4), at(0))

        assertEquals(0, storage.processedInbound.pruneFinalizedAtOrBefore(at(10) - 1.milliseconds))
        assertEquals(2, storage.processedInbound.pruneFinalizedAtOrBefore(at(10)), "the cutoff itself is included")
        assertFalse(storage.processedInbound.isProcessed(alice, messageId(1)))
        assertFalse(storage.processedInbound.isProcessed(alice, messageId(2)))
        assertTrue(storage.processedInbound.isProcessed(alice, messageId(3)))
        assertEquals(1, storage.processedInbound.pruneFinalizedAtOrBefore(at(1_000)))
        assertTrue(storage.pendingInbound.contains(alice, messageId(4)), "pending messages are never pruned")
        assertEquals(1L, storage.pendingInbound.count())
    }

    @Test
    fun rolledBackDiscardKeepsThePendingMessage() = runTest {
        val storage = newStorage()
        storage.pendingInbound.store(bob, messageId(1), bytes(1), at(1))

        assertFailsWith<Failure> {
            storage.transaction {
                assertTrue(pendingInbound.remove(bob, messageId(1)))
                processedInbound.markDiscarded(bob, messageId(1), bytes(1), at(2), MessageDiscardReason.OTHER)
                throw Failure()
            }
        }
        assertTrue(storage.pendingInbound.contains(bob, messageId(1)))
        assertContentEquals(bytes(1), storage.pendingInbound.get(bob, messageId(1))?.frame)
        assertFalse(storage.processedInbound.isProcessed(bob, messageId(1)))
        assertNull(storage.processedInbound.get(bob, messageId(1)))
    }

    @Test
    fun rolledBackTransactionLeavesNoReliabilityState() = runTest {
        val storage = newStorage()
        storage.pendingOutbound.store(bob, messageId(1), bytes(1))
        storage.processedInbound.markCommitted(bob, messageId(1), bytes(1), at(1))
        val pending = storage.pendingInbound.store(bob, messageId(3), bytes(3), at(3))

        assertFailsWith<Failure> {
            storage.transaction {
                pendingOutbound.store(bob, messageId(2), bytes(2))
                assertTrue(pendingOutbound.remove(bob, messageId(1)))
                processedInbound.markCommitted(bob, messageId(2), bytes(2), at(2))
                assertTrue(processedInbound.isProcessed(bob, messageId(2)))
                // A commit: pending inbound to processed.
                assertTrue(pendingInbound.remove(bob, messageId(3)))
                processedInbound.markCommitted(bob, messageId(3), bytes(3), at(4))
                pendingInbound.store(bob, messageId(5), bytes(5), at(5))
                assertEquals(1, processedInbound.pruneFinalizedAtOrBefore(at(1)))
                throw Failure()
            }
        }

        assertEquals(listOf(messageId(1)), storage.pendingOutbound.list(bob).map { it.id })
        assertTrue(storage.processedInbound.isProcessed(bob, messageId(1)))
        assertFalse(storage.processedInbound.isProcessed(bob, messageId(2)))
        assertFalse(storage.processedInbound.isProcessed(bob, messageId(3)))
        assertEquals(listOf(pending), storage.pendingInbound.page(0, 1_000).map { it.sequence })
        assertContentEquals(bytes(3), storage.pendingInbound.get(bob, messageId(3))?.frame)
    }

    @Test
    fun pendingFramesAreNotAliased() = runTest {
        val storage = newStorage()
        val frame = bytes(1)
        storage.pendingOutbound.store(bob, messageId(1), frame)
        frame.fill(0)
        assertContentEquals(bytes(1), storage.pendingOutbound.get(bob, messageId(1))?.frame)

        storage.pendingOutbound.get(bob, messageId(1))!!.frame.fill(0)
        storage.pendingOutbound.list(bob).single().frame.fill(0)
        assertContentEquals(bytes(1), storage.pendingOutbound.get(bob, messageId(1))?.frame)
    }

    companion object {
        /** 32 fake key bytes derived from [seed]. Negative seeds stand for private keys. */
        suspend fun assertRecord(
            storage: ClientStorage,
            address: DeviceAddress,
            key: ByteArray,
            verification: VerificationState,
            message: String? = null,
        ) {
            val record = assertNotNull(storage.remoteIdentities.record(address), message)
            assertContentEquals(key, record.identityKey, message)
            assertEquals(verification, record.verification, message)
        }

        fun bytes(seed: Int): ByteArray = ByteArray(32) { (seed * 31 + it).toByte() }

        fun identity(seed: Int) = LocalIdentity(publicKey = bytes(seed), privateKey = bytes(-seed))

        fun signedPreKey(id: Int) = SignedPreKeyPair(SignedPreKeyId(id), bytes(id), bytes(id + 11), bytes(-1))

        fun oneTimePreKey(id: Int) = OneTimePreKeyPair(OneTimePreKeyId(id), bytes(id), bytes(-1))

        fun initiation(seed: Int) = SessionInitiationId(bytes(seed))

        fun messageId(seed: Int) = LogicalMessageId.fromByteArray(ByteArray(LogicalMessageId.SIZE) { (seed + it).toByte() })

        /** Whole milliseconds: adapters may store timestamps at that precision. */
        fun at(seconds: Int): Instant = Instant.fromEpochMilliseconds(1_700_000_000_000L + seconds * 1_000L)
    }
}
