package dev.kreienbuehl.ksecuremessage.storage.rotation

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId

/**
 * State of storage key rotation. Key IDs only, never key material.
 * [remainingRecords] counts the records not yet sealed with [currentKeyId];
 * it is 0 outside [StorageKeyRotationPhase.MIGRATING].
 */
data class StorageKeyRotationStatus(
    val phase: StorageKeyRotationPhase,
    val currentKeyId: StorageKeyId,
    val nextKeyId: StorageKeyId?,
    val retiringKeyId: StorageKeyId?,
    val remainingRecords: Long,
)

/**
 * [StorageKeyRotationManager.rotate] was called while a rotation is already
 * migrating or retiring. Finish it with [StorageKeyRotationManager.resume]
 * first.
 */
class StorageKeyRotationInProgressException(val status: StorageKeyRotationStatus) :
    IllegalStateException("A storage key rotation is already in progress (${status.phase}, key ${status.currentKeyId.value})")
