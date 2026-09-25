package dev.kreienbuehl.ksecuremessage.storage.keyprovider.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.cancellation.CancellationException

/**
 * A [StorageKeyProvider] that protects the storage key with the Android
 * Keystore (docs/storage-key-providers.md).
 *
 * The 32-byte storage key is wrapped with AES-256-GCM under a non-exportable
 * Keystore key (alias `dev.kreienbuehl.ksecuremessage.storage.v1.<namespace>`)
 * and only the wrapped form is written, to
 * `noBackupFilesDir/ksecuremessage/storage-key-<namespace>.bin`. Whether the
 * Keystore key is hardware-backed depends on the device. The Keystore key
 * needs no user authentication, so background work can open storage.
 *
 * [namespace] separates the keys of different databases, accounts or
 * profiles of one application (letters, digits, `.`, `_`, `-`; at most 64).
 *
 * The file holds one entry per storage key (several during a storage key
 * rotation, docs/storage-key-rotation.md), all wrapped by the same Keystore
 * key. [createKey] and [removeKey] rewrite the file atomically and keep every
 * other entry byte for byte.
 *
 * The first key is created only if there is no wrapped key file. If the file
 * exists but the Keystore key is gone or the file is damaged, every call
 * fails with [StorageEncryptionException.KeyUnavailable]; nothing is
 * regenerated or overwritten. A damaged entry fails only for its own key ID.
 */
class AndroidStorageKeyProvider(context: Context, private val namespace: String = DEFAULT_NAMESPACE) : StorageKeyProvider {
    init {
        require(NAMESPACE.matches(namespace)) { "Invalid storage key namespace" }
    }

    internal val alias: String = ALIAS_PREFIX + namespace
    internal val file: File = File(File(context.applicationContext.noBackupFilesDir, DIRECTORY), "storage-key-$namespace.bin")
    private val lockFile = File(file.parentFile, "storage-key-$namespace.lock")

    override suspend fun loadOrCreateKey(): StorageEncryptionKey = locked {
        val state = readState()
        when {
            state == null -> create()
            state.entries.size == 1 -> unwrap(state, state.entries.single().keyId)
            else -> throw unavailable("More than one storage key in the wrapped key file; the storage key is chosen by the database")
        }
    }

    override suspend fun key(id: StorageKeyId): StorageEncryptionKey? = locked {
        val state = readState()
        if (state?.entry(id) == null) null else unwrap(state, id)
    }

    override suspend fun createKey(id: StorageKeyId): StorageEncryptionKey = locked {
        val state = readState() ?: throw unavailable("No storage key has been provisioned; a rotation key needs an existing key")
        if (state.alias != alias) throw unavailable("Wrapped storage key belongs to another Keystore alias")
        if (state.entry(id) != null) {
            unwrap(state, id)
        } else {
            // Rotation keys are wrapped by the same Keystore key. It must exist:
            // a new one could not unwrap the entries already in the file.
            val wrappingKey = keyStore().getKey(alias, null) as SecretKey?
                ?: throw unavailable("Keystore wrapping key is missing; the storage key cannot be recovered")
            val bytes = StorageEncryptionKey.generate(id).copyBytes()
            try {
                // Existing entries are copied unchanged, damaged ones included.
                writeEntries(state.entries + wrap(wrappingKey, id, bytes))
                verifyPersisted(id, bytes)
            } finally {
                bytes.fill(0)
            }
        }
    }

    override suspend fun removeKey(id: StorageKeyId): Boolean = locked {
        val state = readState() ?: return@locked false
        if (state.alias != alias) throw unavailable("Wrapped storage key belongs to another Keystore alias")
        if (state.entry(id) == null) return@locked false
        if (state.entries.size == 1) throw LastKeyRemoval()
        writeEntries(state.entries.filter { it.keyId != id })
        if (readState()?.entry(id) != null) throw unavailable("Storage key ${id.value} was not removed")
        true
    }

    private fun create(): StorageEncryptionKey {
        // A Keystore key without a wrapped key file is left from an interrupted
        // creation. It never protected a key that was handed out, so it is reused.
        val wrappingKey = keyStore().getKey(alias, null) as SecretKey? ?: generateWrappingKey()
        val id = INITIAL_KEY_ID
        val bytes = StorageEncryptionKey.generate(id).copyBytes()
        try {
            writeEntries(listOf(wrap(wrappingKey, id, bytes)))
            return verifyPersisted(id, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun wrap(wrappingKey: SecretKey, id: StorageKeyId, bytes: ByteArray): WrappedKeyFile.Entry {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // The Keystore picks a fresh random IV for every encryption.
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey)
        cipher.updateAAD(associatedData(id))
        return WrappedKeyFile.Entry(id, cipher.iv, cipher.doFinal(bytes))
    }

    /**
     * Writes [entries] as the new file. The file's current key ID is only
     * the lowest entry: which key is current is recorded in the database.
     */
    private fun writeEntries(entries: List<WrappedKeyFile.Entry>) {
        writeAtomically(WrappedKeyFile(alias, entries.minBy { it.keyId.value }.keyId, entries).encode())
    }

    /** Only a key that can be read back after a restart is returned. */
    private fun verifyPersisted(id: StorageKeyId, bytes: ByteArray): StorageEncryptionKey {
        val stored = readState() ?: throw unavailable("Wrapped storage key was not persisted")
        val key = unwrap(stored, id)
        val check = key.copyBytes()
        try {
            if (!check.contentEquals(bytes)) throw unavailable("Persisted storage key does not match")
        } finally {
            check.fill(0)
        }
        return key
    }

    private fun unwrap(state: WrappedKeyFile, id: StorageKeyId): StorageEncryptionKey {
        if (state.alias != alias) throw unavailable("Wrapped storage key belongs to another Keystore alias")
        val entry = state.entry(id) ?: throw unavailable("Wrapped storage key file has no key ${id.value}")
        val wrappingKey = keyStore().getKey(alias, null) as SecretKey?
            ?: throw unavailable("Keystore wrapping key is missing; the storage key cannot be recovered")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey, GCMParameterSpec(WrappedKeyFile.TAG_SIZE * 8, entry.iv))
        cipher.updateAAD(associatedData(id))
        val bytes = cipher.doFinal(entry.ciphertext)
        try {
            if (bytes.size != StorageEncryptionKey.SIZE) throw unavailable("Unwrapped storage key has an invalid size")
            return StorageEncryptionKey(id, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    /** The persisted state, or `null` only if the file certainly does not exist. */
    private fun readState(): WrappedKeyFile? {
        val path = file.toPath()
        if (Files.notExists(path)) return null
        return WrappedKeyFile.decode(Files.readAllBytes(path))
    }

    /** Writes a new file, synced, then renames it into place: a crash leaves no or the complete file. */
    private fun writeAtomically(bytes: ByteArray) {
        val target = file.toPath()
        val temporary = File(file.parentFile, file.name + ".tmp").toPath()
        FileChannel.open(temporary, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
        Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE)
        // Make the rename durable too, where the platform allows syncing a directory.
        try {
            FileChannel.open(file.parentFile!!.toPath(), StandardOpenOption.READ).use { it.force(true) }
        } catch (_: java.io.IOException) {
        }
    }

    private fun generateWrappingKey(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).apply { init(spec) }.generateKey()
    }

    /** Binds a wrapped key to its namespace and key ID, so a file copied elsewhere does not unwrap. */
    private fun associatedData(id: StorageKeyId): ByteArray {
        val name = namespace.encodeToByteArray()
        return ByteBuffer.allocate(WRAP_DOMAIN.size + 2 + name.size + 4)
            .put(WRAP_DOMAIN).putShort(name.size.toShort()).put(name).putInt(id.value)
            .array()
    }

    /**
     * Runs [block] on the IO dispatcher, serialized within the process and,
     * through a file lock, with other processes of the application.
     */
    private suspend fun <T> locked(block: () -> T): T = withContext(Dispatchers.IO) {
        processLock.withLock {
            try {
                file.parentFile!!.mkdirs()
                RandomAccessFile(lockFile, "rw").use { lock ->
                    lock.channel.lock().use { block() }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: StorageEncryptionException) {
                throw e
            } catch (e: LastKeyRemoval) {
                throw e
            } catch (e: MalformedWrappedKeyFile) {
                throw StorageEncryptionException.KeyUnavailable("Wrapped storage key file is damaged: ${e.message}", e)
            } catch (e: Exception) {
                // Keystore, cipher (tag mismatch) and file errors. Never create a key here.
                throw StorageEncryptionException.KeyUnavailable("Android Keystore storage key is not available", e)
            }
        }
    }

    companion object {
        const val DEFAULT_NAMESPACE: String = "default"

        internal const val ALIAS_PREFIX = "dev.kreienbuehl.ksecuremessage.storage.v1."
        internal const val DIRECTORY = "ksecuremessage"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private val WRAP_DOMAIN = "KSecureMessage-StorageKeyWrap-v1".encodeToByteArray()
        private val NAMESPACE = Regex("[A-Za-z0-9._-]{1,64}")
        private val INITIAL_KEY_ID = StorageKeyId(1)

        // One lock for all namespaces: provider calls are rare. The file lock
        // alone would throw for two threads of one process.
        private val processLock = Mutex()

        private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

        private fun unavailable(message: String) = StorageEncryptionException.KeyUnavailable(message)
    }

    /** [removeKey] of the last entry. Passed through [locked] unwrapped. */
    private class LastKeyRemoval : IllegalStateException("The provider's last storage key cannot be removed")
}
