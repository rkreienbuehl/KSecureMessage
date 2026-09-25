package dev.kreienbuehl.ksecuremessage.storage.encryption

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.random.CryptographyRandom
import kotlin.coroutines.cancellation.CancellationException

// The only file that uses cryptography-kotlin. Everything else in storage
// encryption goes through these functions.

/** AES-256-GCM with a 96-bit nonce and a 128-bit tag, from the platform provider. */
internal object AesGcm {
    const val NONCE_SIZE: Int = 12
    const val TAG_SIZE: Int = 16

    // The nonce is chosen by the caller (EncryptedRecordFormat) so the record
    // format stores it explicitly. Production nonces come from secureRandomBytes.
    @OptIn(DelicateCryptographyApi::class)
    suspend fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        require(nonce.size == NONCE_SIZE) { "Invalid nonce size" }
        return decodeKey(key).cipher().encryptWithIv(nonce, plaintext, associatedData)
    }

    /** `null` if [ciphertextAndTag] does not authenticate under [key], [nonce] and [associatedData]. */
    @OptIn(DelicateCryptographyApi::class)
    suspend fun decrypt(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, associatedData: ByteArray): ByteArray? {
        require(nonce.size == NONCE_SIZE) { "Invalid nonce size" }
        require(ciphertextAndTag.size >= TAG_SIZE) { "Truncated ciphertext" }
        val gcmKey = decodeKey(key)
        return try {
            gcmKey.cipher().decryptWithIv(nonce, ciphertextAndTag, associatedData)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // Providers signal a tag mismatch with their own exception types.
            null
        }
    }

    private suspend fun decodeKey(key: ByteArray): AES.GCM.Key {
        require(key.size == StorageEncryptionKey.SIZE) { "Invalid key size" }
        return CryptographyProvider.Default.get(AES.GCM).keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, key)
    }
}

/** Bytes from the platform's cryptographically secure random source. */
internal fun secureRandomBytes(size: Int): ByteArray = CryptographyRandom.nextBytes(size)
