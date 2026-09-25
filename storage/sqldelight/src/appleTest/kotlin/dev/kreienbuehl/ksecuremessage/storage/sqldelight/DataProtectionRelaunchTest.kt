package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple.AppleStorageKeyProvider
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import kotlinx.coroutines.test.runTest
import platform.posix.getenv
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

private val RELAUNCH_PUBLIC = ByteArray(32) { 0x31 }
private val RELAUNCH_SECRET = ByteArray(32) { 0x6B }

/**
 * Persistence across processes on the data protection keychain. The signed
 * host launches this test three times with `KSM_RELAUNCH_PHASE` =
 * `create`, `verify`, `cleanup` and one `KSM_RELAUNCH_NAMESPACE`:
 * - create: a new database gets a new Keychain key and stores a known identity;
 * - verify (another process): a new provider opens the database, and the
 *   identity decrypts, which only the same key can do; key bytes are never
 *   printed or compared outside the process;
 * - cleanup: deletes the item and the database.
 * Without the environment it fails: it is never skipped.
 */
@OptIn(ExperimentalForeignApi::class)
class DataProtectionRelaunchTest {
    private fun env(name: String): String = getenv(name)?.toKString()?.takeIf { it.isNotEmpty() } ?: error("$name is not set: run through appleKeychainHostTest")

    @Test
    fun keyPersistsAcrossProcesses() = runTest {
        val namespace = env("KSM_RELAUNCH_NAMESPACE")
        require(namespace.startsWith("relaunch-"))
        val databaseName = "ksecuremessage-$namespace.db"
        val provider = AppleStorageKeyProvider(namespace)

        when (val phase = env("KSM_RELAUNCH_PHASE")) {
            "create" -> {
                deleteTestDatabase(databaseName)
                assertNull(provider.key(StorageKeyId(1)), "fresh namespace")
                val driver = openTestDriver(databaseName)
                SqlDelightClientStorage.open(driver, provider).identity.store(LocalIdentity(RELAUNCH_PUBLIC, RELAUNCH_SECRET))
                driver.close()
                assertNotNull(AppleStorageKeyProvider(namespace).key(StorageKeyId(1)))
            }
            "verify" -> {
                val driver = openTestDriver(databaseName)
                val boundKeyId = driver.longs("SELECT key_id FROM storage_encryption").single()
                assertEquals(1L, boundKeyId)
                val identity = assertNotNull(SqlDelightClientStorage.open(driver, provider).identity.identity())
                assertContentEquals(RELAUNCH_SECRET, identity.privateKey)
                assertContentEquals(RELAUNCH_PUBLIC, identity.publicKey)
                driver.close()
            }
            "cleanup" -> {
                TestKeychain(dataProtection = true).deleteOrFail(namespace)
                deleteTestDatabase(databaseName)
                assertNull(AppleStorageKeyProvider(namespace).key(StorageKeyId(1)))
            }
            else -> error("unknown KSM_RELAUNCH_PHASE $phase")
        }
    }
}
