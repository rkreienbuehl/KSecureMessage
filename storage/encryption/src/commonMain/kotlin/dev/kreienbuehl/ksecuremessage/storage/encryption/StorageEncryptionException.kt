package dev.kreienbuehl.ksecuremessage.storage.encryption

/**
 * Encrypted client storage cannot be read or written. Storage fails closed:
 * an unreadable record is never reported as missing, replaced, or read as
 * plaintext. Messages never contain key bytes, plaintext or ciphertext.
 */
sealed class StorageEncryptionException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /**
     * The storage key is not available: the [StorageKeyProvider] failed or
     * does not have the key, or a record names a key this storage does not
     * use.
     */
    class KeyUnavailable(message: String, cause: Throwable? = null) : StorageEncryptionException(message, cause)

    /**
     * A record did not authenticate: wrong key, modified bytes, or a record
     * copied from another row or record type.
     */
    class AuthenticationFailed(message: String) : StorageEncryptionException(message)

    /** The record or database uses an unknown encryption format, version or algorithm. */
    class UnsupportedFormat(message: String) : StorageEncryptionException(message)

    /** The record is truncated or its structure is invalid. */
    class MalformedRecord(message: String) : StorageEncryptionException(message)
}
