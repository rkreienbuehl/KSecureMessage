package dev.kreienbuehl.ksecuremessage.storage.rotation

/**
 * Phase of a storage key rotation (docs/storage-key-rotation.md). Storage key
 * rotation replaces the key that encrypts client storage records; it is
 * unrelated to signed prekey rotation.
 */
enum class StorageKeyRotationPhase {
    /** One key: every record uses the current key. */
    STABLE,

    /**
     * A new key ID is allocated, but the provider key may not exist yet and
     * the current key is unchanged. Only the current key is needed to open.
     */
    PREPARING,

    /**
     * The new key is current and seals every new record; records of the
     * retiring key are re-encrypted in batches. Both keys are needed to open.
     */
    MIGRATING,

    /**
     * No record uses the retiring key any more (proven by a full scan); its
     * provider key is being removed. Only the current key is needed to open.
     */
    RETIRING,
}
