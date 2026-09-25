package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSString
import platform.Foundation.create
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecUseDataProtectionKeychain
import platform.Security.kSecValueData

/**
 * Direct Keychain access to the provider's items, by their documented names
 * (docs/storage-key-providers.md), to simulate loss and damage. Tests only.
 */
@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
class TestKeychain(private val dataProtection: Boolean) {
    private fun service(namespace: String) = "dev.kreienbuehl.ksecuremessage.storage.$namespace"

    /** OSStatus of deleting every item of [namespace]; not found counts as success. */
    fun delete(namespace: String): Int = query(namespace, null) { SecItemDelete(it) }.let { if (it == errSecItemNotFound) errSecSuccess else it }

    fun deleteOrFail(namespace: String) {
        val status = delete(namespace)
        check(status == errSecSuccess) { "Keychain delete failed with OSStatus $status" }
    }

    /** Replaces the data of key 1 of [namespace] with 31 bytes. */
    fun truncateKey(namespace: String) {
        val bytes = ByteArray(31) { 7 }
        val data = bytes.usePinned { CFDataCreate(null, it.addressOf(0).reinterpret(), bytes.size.convert()) }
        val changes = CFDictionaryCreateMutable(null, 1, kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)
        CFDictionaryAddValue(changes, kSecValueData, data)
        val status = query(namespace, "v1/1") { SecItemUpdate(it, changes) }
        CFRelease(changes)
        CFRelease(data)
        check(status == errSecSuccess) { "Keychain update failed with OSStatus $status" }
    }

    private fun query(namespace: String, account: String?, block: (CFDictionaryRef?) -> Int): Int {
        val service = CFBridgingRetain(NSString.create(string = service(namespace)))
        val accountValue = account?.let { CFBridgingRetain(NSString.create(string = it)) }
        val query = CFDictionaryCreateMutable(null, 4, kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)
        try {
            CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
            CFDictionaryAddValue(query, kSecAttrService, service)
            if (accountValue != null) CFDictionaryAddValue(query, kSecAttrAccount, accountValue)
            if (dataProtection) CFDictionaryAddValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue)
            return block(query)
        } finally {
            CFRelease(query)
            CFRelease(service)
            accountValue?.let { CFRelease(it) }
        }
    }
}

abstract class KeychainStorageTest(private val dataProtection: Boolean) : PlatformKeyProviderStorageTest() {
    private val keychain = TestKeychain(dataProtection)

    override fun loseBackingKey(namespace: String) = keychain.deleteOrFail(namespace)

    override fun corruptState(namespace: String) = keychain.truncateKey(namespace)

    override fun deleteProviderState(namespace: String) = keychain.deleteOrFail(namespace)

    // A write shows whether this process may use the keychain; a lookup may not.
    override fun unavailableReason(): String? =
        keychain.delete("availability-probe").takeIf { it != errSecSuccess }?.let { "keychain not usable by this test process (OSStatus $it)" }
}
