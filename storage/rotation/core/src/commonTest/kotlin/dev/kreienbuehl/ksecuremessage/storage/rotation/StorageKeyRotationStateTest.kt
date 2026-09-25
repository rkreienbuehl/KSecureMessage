package dev.kreienbuehl.ksecuremessage.storage.rotation

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationPhase.MIGRATING
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationPhase.PREPARING
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationPhase.RETIRING
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationPhase.STABLE
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationState.Migrating
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationState.Preparing
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationState.Retiring
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationState.Stable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class StorageKeyRotationStateTest {
    @Test
    fun validStates() {
        assertEquals(Stable(K1, K1), StorageKeyRotationState.of(STABLE, K1, K1, null, null))
        assertEquals(Stable(K2, K3), StorageKeyRotationState.of(STABLE, K2, K3, null, null))
        assertEquals(Preparing(K1, K2, K2), StorageKeyRotationState.of(PREPARING, K1, K2, K2, null))
        assertEquals(Migrating(K2, K2, K1), StorageKeyRotationState.of(MIGRATING, K2, K2, null, K1))
        assertEquals(Retiring(K2, K2, K1), StorageKeyRotationState.of(RETIRING, K2, K2, null, K1))
    }

    @Test
    fun missingHighWaterMarkIsTheHighestGivenId() {
        assertEquals(Stable(K1, K1), StorageKeyRotationState.of(STABLE, K1, null, null, null))
        assertEquals(Preparing(K1, K2, K2), StorageKeyRotationState.of(PREPARING, K1, null, K2, null))
        assertEquals(Migrating(K1, K2, K2), StorageKeyRotationState.of(MIGRATING, K1, null, null, K2))
    }

    @Test
    fun inconsistentStatesAreMalformed() {
        val invalid = listOf(
            { StorageKeyRotationState.of(STABLE, K1, K1, K2, null) },
            { StorageKeyRotationState.of(STABLE, K1, K1, null, K2) },
            { StorageKeyRotationState.of(STABLE, K2, K1, null, null) },
            { StorageKeyRotationState.of(PREPARING, K1, K2, null, null) },
            { StorageKeyRotationState.of(PREPARING, K2, K2, K1, null) },
            { StorageKeyRotationState.of(PREPARING, K2, K2, K2, null) },
            { StorageKeyRotationState.of(PREPARING, K1, K1, K2, null) },
            { StorageKeyRotationState.of(PREPARING, K1, K2, K2, K1) },
            { StorageKeyRotationState.of(MIGRATING, K2, K2, null, null) },
            { StorageKeyRotationState.of(MIGRATING, K2, K2, null, K2) },
            { StorageKeyRotationState.of(MIGRATING, K2, K2, K3, K1) },
            { StorageKeyRotationState.of(MIGRATING, K2, K1, null, K1) },
            { StorageKeyRotationState.of(RETIRING, K2, K2, null, null) },
            { StorageKeyRotationState.of(RETIRING, K2, K2, null, K2) },
            { StorageKeyRotationState.of(RETIRING, K2, K2, null, K3) },
        )
        for ((index, state) in invalid.withIndex()) {
            assertFailsWith<StorageEncryptionException.MalformedRecord>("case $index") { state() }
        }
    }

    @Test
    fun requiredKeysArePerPhase() {
        assertEquals(setOf(K1), Stable(K1, K1).requiredKeyIds)
        assertEquals(setOf(K1), Preparing(K1, K2, K2).requiredKeyIds)
        assertEquals(setOf(K2, K1), Migrating(K2, K2, K1).requiredKeyIds)
        assertEquals(setOf(K2), Retiring(K2, K2, K1).requiredKeyIds)
    }

    @Test
    fun nextKeyIdIsAboveTheHighWaterMarkWithoutWraparound() {
        assertEquals(K2, Stable(K1, K1).nextKeyId())
        assertEquals(StorageKeyId(Int.MAX_VALUE), Stable(K1, StorageKeyId(Int.MAX_VALUE - 1)).nextKeyId())
        assertFailsWith<StorageEncryptionException.KeyIdsExhausted> { Stable(K1, StorageKeyId(Int.MAX_VALUE)).nextKeyId() }
    }
}
