package dev.kreienbuehl.ksecuremessage.storage.rotation

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationState.Migrating
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationState.Preparing
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationState.Retiring
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationState.Stable
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The state machine alone, over [FakeRotationBackend] and [RecordingKeyProvider]. */
class StorageKeyRotationManagerTest {
    private val log = mutableListOf<String>()
    private val backend = FakeRotationBackend(log)
    private val keys = RecordingKeyProvider(log)
    private val manager = StorageKeyRotationManager(backend, keys)

    private suspend fun finish(maxRecords: Int = 100) {
        completeStorageKeyRotation { manager.resume(maxRecords) }
    }

    @Test
    fun stableStatus() = runTest {
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.STABLE, K1, null, null, 0), manager.status())
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.STABLE, K1, null, null, 0), manager.resume())
        assertTrue(log.isEmpty(), "resume in STABLE does nothing")
    }

    @Test
    fun rotateAllocatesBeforeTheProviderAndActivatesAfterTheReadBack() = runTest {
        assertEquals(K2, manager.rotate())
        assertEquals(listOf("prepare 2", "createKey 2", "key 2", "activate 2"), log)
        assertEquals(Migrating(K2, K2, K1), backend.state)
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.MIGRATING, K2, null, K1, 5), manager.status())
    }

    @Test
    fun fullRotationRetiresTheOldKeyLast() = runTest {
        manager.rotate()
        finish()
        assertEquals(
            listOf("prepare 2", "createKey 2", "key 2", "activate 2", "migrate 5", "retiring 1", "removeKey 1 true", "complete"),
            log,
        )
        assertEquals(Stable(K2, K2), backend.state)
        assertEquals(setOf(K2), keys.keys.keys)
        assertEquals(List(5) { K2 }, backend.records)
    }

    @Test
    fun batchesAreBoundedAndReportProgress() = runTest {
        manager.rotate()
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.MIGRATING, K2, null, K1, 3), manager.resume(2))
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.MIGRATING, K2, null, K1, 1), manager.resume(2))
        // The last record: the batch leaves none, so the same call proves and retires.
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.STABLE, K2, null, null, 0), manager.resume(2))
        assertEquals(listOf("migrate 2", "migrate 2", "migrate 1", "retiring 1", "removeKey 1 true", "complete"), log.drop(4))
    }

    @Test
    fun nonProgressingMigrationFailsTheHarnessAfterTheStepBound() = runTest {
        manager.rotate()
        backend.stallMigration = true
        val failure = assertFailsWith<AssertionError> { completeStorageKeyRotation(maxSteps = 7) { manager.resume(2) } }
        val message = assertNotNull(failure.message)
        assertTrue("did not converge after 7 resume steps" in message, message)
        assertTrue("phase=MIGRATING, currentKeyId=2, nextKeyId=null, retiringKeyId=1, remainingRecords=5" in message, message)
        // Exactly the bound: seven batches, none retired anything.
        assertEquals(List(7) { "migrate 0" }, log.drop(4))
        assertEquals(Migrating(K2, K2, K1), backend.state)
        assertEquals(setOf(K1, K2), keys.keys.keys)
    }

    @Test
    fun maxRecordsMustBePositive() = runTest {
        assertFailsWith<IllegalArgumentException> { manager.resume(0) }
        assertTrue(log.isEmpty())
    }

    @Test
    fun crashAfterPrepareReusesTheAllocatedId() = runTest {
        backend.crashAfter += "prepare"
        assertFailsWith<InjectedCrash> { manager.rotate() }
        assertEquals(Preparing(K1, K2, K2), backend.state)
        assertEquals(listOf("prepare 2"), log, "no provider call in the crashed start")
        backend.crashAfter.clear()

        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.PREPARING, K1, K2, null, 0), manager.status())
        assertEquals(K2, manager.rotate())
        assertEquals(listOf("prepare 2", "createKey 2", "key 2", "activate 2"), log, "no second allocation")
    }

    @Test
    fun crashAfterProviderCreationResumesWithTheSameKey() = runTest {
        keys.crashAfterCreate = true
        // A provider failure that is not a StorageEncryptionException is reported as KeyUnavailable.
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { manager.rotate() }
        assertEquals(Preparing(K1, K2, K2), backend.state)
        val created = keys.keys.getValue(K2)
        keys.crashAfterCreate = false

        assertEquals(StorageKeyRotationPhase.MIGRATING, manager.resume().phase)
        assertEquals(listOf("prepare 2", "createKey 2", "createKey 2", "key 2", "activate 2"), log)
        assertTrue(created === keys.keys.getValue(K2), "the existing key is used")
    }

    @Test
    fun providerFailureLeavesThePreparedRotation() = runTest {
        keys.failCreate = true
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { manager.rotate() }
        assertEquals(Preparing(K1, K2, K2), backend.state)
        assertEquals(listOf("prepare 2"), log)

        keys.failCreate = false
        assertEquals(K2, manager.rotate())
        assertEquals(K2, backend.state.highestKeyId)
    }

    @Test
    fun keyMissingOnReadBackIsNotActivated() = runTest {
        keys.loseOnRead = true
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { manager.rotate() }
        assertEquals(Preparing(K1, K2, K2), backend.state)
        assertFalse(log.any { it.startsWith("activate") })
    }

    @Test
    fun otherKeyOnReadBackIsNotActivated() = runTest {
        keys.returnOtherKey = true
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { manager.rotate() }
        assertEquals(Preparing(K1, K2, K2), backend.state)
        assertFalse(log.any { it.startsWith("activate") })
    }

    @Test
    fun rotateWhileMigratingOrRetiringIsRefused() = runTest {
        manager.rotate()
        val migrating = assertFailsWith<StorageKeyRotationInProgressException> { manager.rotate() }
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.MIGRATING, K2, null, K1, 5), migrating.status)

        backend.crashAfter += "retiring"
        assertFailsWith<InjectedCrash> { manager.resume(100) }
        val retiring = assertFailsWith<StorageKeyRotationInProgressException> { manager.rotate() }
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.RETIRING, K2, null, K1, 0), retiring.status)
        assertEquals(K2, backend.state.highestKeyId, "nothing allocated")
    }

    @Test
    fun migratingKeepsTheNewKeyCurrent() = runTest {
        manager.rotate()
        manager.resume(1)
        backend.records += K2 // a record written during the migration
        assertEquals(K2, manager.status().currentKeyId)
        finish(1)
        assertEquals(List(6) { K2 }, backend.records)
    }

    @Test
    fun lingeringReferenceBlocksRetirement() = runTest {
        manager.rotate()
        // A sealed value of the old key that the batches do not select.
        backend.otherSealedValues += K1
        assertFailsWith<IllegalStateException> { manager.resume(100) }
        assertEquals(Migrating(K2, K2, K1), backend.state, "RETIRING was rolled back")
        assertEquals(setOf(K1, K2), keys.keys.keys, "the old key is kept")
        assertFalse(log.any { it.startsWith("removeKey") })
    }

    @Test
    fun recordOfAnUnknownKeyStopsTheMigration() = runTest {
        manager.rotate()
        backend.records += K3
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { manager.resume(100) }
        assertEquals(Migrating(K2, K2, K1), backend.state)
        assertEquals(List(5) { K1 } + K3, backend.records, "the failed batch rolled back")
        assertEquals(setOf(K1, K2), keys.keys.keys)
    }

    @Test
    fun retirementWaitsForTheLastBatch() = runTest {
        manager.rotate()
        manager.resume(4)
        assertEquals(StorageKeyRotationPhase.MIGRATING, backend.state.phase)
        assertFalse(log.any { it.startsWith("retiring") || it.startsWith("removeKey") })
    }

    @Test
    fun crashAfterRetiringIsCommittedRemovesTheKeyOnResume() = runTest {
        manager.rotate()
        backend.crashAfter += "retiring"
        assertFailsWith<InjectedCrash> { manager.resume(100) }
        assertEquals(Retiring(K2, K2, K1), backend.state)
        assertEquals(setOf(K1, K2), keys.keys.keys)
        backend.crashAfter.clear()

        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.STABLE, K2, null, null, 0), manager.resume())
        assertEquals(setOf(K2), keys.keys.keys)
    }

    @Test
    fun alreadyRemovedKeyIsAcceptedWhileRetiring() = runTest {
        manager.rotate()
        keys.crashAfterRemove = true
        assertFailsWith<InjectedCrash> { manager.resume(100) }
        assertEquals(Retiring(K2, K2, K1), backend.state)
        keys.crashAfterRemove = false

        assertEquals(StorageKeyRotationPhase.STABLE, manager.resume().phase)
        assertEquals(listOf("removeKey 1 true", "removeKey 1 false", "complete"), log.filter { it.startsWith("removeKey") || it == "complete" })
    }

    @Test
    fun retiringRescansBeforeRemovingTheKey() = runTest {
        manager.rotate()
        backend.crashAfter += "retiring"
        assertFailsWith<InjectedCrash> { manager.resume(100) }
        backend.crashAfter.clear()
        backend.otherSealedValues += K1 // a value of the retiring key appeared after the proof
        assertFailsWith<IllegalStateException> { manager.resume() }
        assertEquals(Retiring(K2, K2, K1), backend.state)
        assertEquals(setOf(K1, K2), keys.keys.keys)
        assertFalse(log.any { it.startsWith("removeKey") })
    }

    @Test
    fun keyIdsAreNeverReused() = runTest {
        manager.rotate()
        finish()
        assertEquals(K3, manager.rotate())
        finish()
        assertEquals(Stable(K3, K3), backend.state)
        assertEquals(setOf(K3), keys.keys.keys)
    }

    @Test
    fun allocationContinuesAboveTheHighWaterMark() = runTest {
        backend.state = Stable(K1, StorageKeyId(7))
        assertEquals(StorageKeyId(8), manager.rotate())
    }

    @Test
    fun exhaustedKeyIdsChangeNothing() = runTest {
        val exhausted = Stable(K1, StorageKeyId(Int.MAX_VALUE))
        backend.state = exhausted
        assertFailsWith<StorageEncryptionException.KeyIdsExhausted> { manager.rotate() }
        assertEquals(exhausted, backend.state)
        assertTrue(log.isEmpty(), "no allocation, no provider call")
    }

    @Test
    fun staleTransitionChangesNothing() = runTest {
        val stale = FakeRotationBackend(log)
        stale.state = Preparing(K1, K2, K2)
        assertFailsWith<IllegalStateException> { stale.exclusive { stale.prepare(Stable(K1, K1), K2) } }
        assertEquals(Preparing(K1, K2, K2), stale.state)
    }
}
