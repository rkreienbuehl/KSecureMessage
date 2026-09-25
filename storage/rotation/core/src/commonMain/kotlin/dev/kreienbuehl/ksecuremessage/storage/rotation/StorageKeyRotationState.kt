package dev.kreienbuehl.ksecuremessage.storage.rotation

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId

/**
 * The persisted storage key rotation state of one storage, validated. Key IDs
 * only. Each phase carries exactly the key IDs it needs, so an inconsistent
 * combination cannot be represented. [highestKeyId] is the key ID high-water
 * mark: IDs are allocated above it, never reused and never wrapped around.
 */
sealed class StorageKeyRotationState {
    abstract val phase: StorageKeyRotationPhase

    /** The key that seals every new record. */
    abstract val currentKeyId: StorageKeyId
    abstract val highestKeyId: StorageKeyId

    /** The keys storage must load (and prove) to open in this state. */
    open val requiredKeyIds: Set<StorageKeyId> get() = setOf(currentKeyId)

    /** One key: every record uses [currentKeyId]. */
    data class Stable(override val currentKeyId: StorageKeyId, override val highestKeyId: StorageKeyId) : StorageKeyRotationState() {
        override val phase get() = StorageKeyRotationPhase.STABLE

        init {
            require(highestKeyId.value >= currentKeyId.value) { "Invalid storage key rotation state" }
        }

        /**
         * The ID a new rotation allocates: one above [highestKeyId]. Throws
         * [StorageEncryptionException.KeyIdsExhausted] when none is left.
         */
        fun nextKeyId(): StorageKeyId {
            if (highestKeyId.value >= Int.MAX_VALUE) throw StorageEncryptionException.KeyIdsExhausted("No storage key ID is left")
            return StorageKeyId(highestKeyId.value + 1)
        }
    }

    /** [nextKeyId] is allocated; the provider key may not exist yet. [currentKeyId] is unchanged. */
    data class Preparing(
        override val currentKeyId: StorageKeyId,
        override val highestKeyId: StorageKeyId,
        val nextKeyId: StorageKeyId,
    ) : StorageKeyRotationState() {
        override val phase get() = StorageKeyRotationPhase.PREPARING

        init {
            require(nextKeyId.value > currentKeyId.value && highestKeyId.value >= nextKeyId.value) { "Invalid storage key rotation state" }
        }
    }

    /** [currentKeyId] seals new records; records of [retiringKeyId] are re-encrypted. Both keys are needed. */
    data class Migrating(
        override val currentKeyId: StorageKeyId,
        override val highestKeyId: StorageKeyId,
        val retiringKeyId: StorageKeyId,
    ) : StorageKeyRotationState() {
        override val phase get() = StorageKeyRotationPhase.MIGRATING
        override val requiredKeyIds: Set<StorageKeyId> get() = setOf(currentKeyId, retiringKeyId)

        init {
            require(retiringKeyId != currentKeyId && highestKeyId.value >= maxOf(currentKeyId.value, retiringKeyId.value)) {
                "Invalid storage key rotation state"
            }
        }
    }

    /** No record uses [retiringKeyId] (proven); its provider key may already be gone. */
    data class Retiring(
        override val currentKeyId: StorageKeyId,
        override val highestKeyId: StorageKeyId,
        val retiringKeyId: StorageKeyId,
    ) : StorageKeyRotationState() {
        override val phase get() = StorageKeyRotationPhase.RETIRING

        init {
            require(retiringKeyId != currentKeyId && highestKeyId.value >= maxOf(currentKeyId.value, retiringKeyId.value)) {
                "Invalid storage key rotation state"
            }
        }
    }

    companion object {
        /**
         * Validates the rotation state a backend read from storage. A
         * [highestKeyId] of `null` (not recorded) counts as the highest of the
         * given IDs. Throws [StorageEncryptionException.MalformedRecord] for any
         * inconsistent combination: storage in that state fails closed.
         */
        fun of(
            phase: StorageKeyRotationPhase,
            currentKeyId: StorageKeyId,
            highestKeyId: StorageKeyId?,
            nextKeyId: StorageKeyId?,
            retiringKeyId: StorageKeyId?,
        ): StorageKeyRotationState {
            val highest = highestKeyId
                ?: listOfNotNull(currentKeyId, nextKeyId, retiringKeyId).maxBy { it.value }
            return try {
                when (phase) {
                    StorageKeyRotationPhase.STABLE -> {
                        valid(nextKeyId == null && retiringKeyId == null)
                        Stable(currentKeyId, highest)
                    }
                    StorageKeyRotationPhase.PREPARING -> {
                        valid(nextKeyId != null && retiringKeyId == null)
                        Preparing(currentKeyId, highest, nextKeyId!!)
                    }
                    StorageKeyRotationPhase.MIGRATING -> {
                        valid(nextKeyId == null && retiringKeyId != null)
                        Migrating(currentKeyId, highest, retiringKeyId!!)
                    }
                    StorageKeyRotationPhase.RETIRING -> {
                        valid(nextKeyId == null && retiringKeyId != null)
                        Retiring(currentKeyId, highest, retiringKeyId!!)
                    }
                }
            } catch (e: IllegalArgumentException) {
                throw StorageEncryptionException.MalformedRecord("Invalid storage key rotation state")
            }
        }

        private fun valid(condition: Boolean) = require(condition) { "Invalid storage key rotation state" }
    }
}
