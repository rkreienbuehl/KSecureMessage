package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFArrayGetCount
import platform.CoreFoundation.CFArrayGetValueAtIndex
import platform.CoreFoundation.CFArrayRef
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionaryGetValue
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFRetain
import platform.CoreFoundation.CFStringRef
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFBooleanFalse
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSString
import platform.Foundation.create
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.errSecDuplicateItem
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccessGroup
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecAttrSynchronizable
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitAll
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecReturnAttributes
import platform.Security.kSecReturnData
import platform.Security.kSecUseDataProtectionKeychain
import platform.Security.kSecValueData

/** A Keychain call failed with [status] (an OSStatus). Never carries item data. */
internal class KeychainException(val status: Int, operation: String) : Exception("Keychain $operation failed with OSStatus $status")

/**
 * Generic password items of one [service]. Blocking calls; synchronization
 * is the caller's job. [dataProtection] selects the data protection keychain
 * (on iOS it always is; on macOS the alternative is the file-based keychain).
 */
@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
internal class Keychain(
    private val service: String,
    private val accessGroup: String?,
    private val dataProtection: Boolean,
) {
    /** The item's data, or `null` if there is no item [account]. */
    fun read(account: String): ByteArray? = memScoped {
        val result = alloc<CFTypeRefVar>()
        val status = withQuery(account, kSecReturnData to kCFBooleanTrue, kSecMatchLimit to kSecMatchLimitOne) { SecItemCopyMatching(it, result.ptr) }
        when (status) {
            errSecSuccess -> {
                val data = result.value ?: throw KeychainException(status, "read")
                try {
                    val cfData: CFDataRef = data.reinterpret()
                    val length = CFDataGetLength(cfData).toInt()
                    if (length == 0) ByteArray(0) else CFDataGetBytePtr(cfData)!!.reinterpret<ByteVar>().readBytes(length)
                } finally {
                    CFRelease(data)
                }
            }
            errSecItemNotFound -> null
            else -> throw KeychainException(status, "read")
        }
    }

    /** Accounts of all items of the service. */
    fun accounts(): List<String> = memScoped {
        val result = alloc<CFTypeRefVar>()
        val status = withQuery(null, kSecReturnAttributes to kCFBooleanTrue, kSecMatchLimit to kSecMatchLimitAll) { SecItemCopyMatching(it, result.ptr) }
        when (status) {
            errSecSuccess -> {
                val array = result.value ?: throw KeychainException(status, "list")
                try {
                    val items: CFArrayRef = array.reinterpret()
                    (0 until CFArrayGetCount(items).toInt()).map { index ->
                        val attributes: CFDictionaryRef = CFArrayGetValueAtIndex(items, index.convert())!!.reinterpret()
                        val account = CFDictionaryGetValue(attributes, kSecAttrAccount) ?: throw KeychainException(status, "list")
                        CFBridgingRelease(CFRetain(account)) as? String ?: throw KeychainException(status, "list")
                    }
                } finally {
                    CFRelease(array)
                }
            }
            errSecItemNotFound -> emptyList()
            else -> throw KeychainException(status, "list")
        }
    }

    /** Adds item [account]; `false` if it already exists (then nothing changed). */
    fun add(account: String, data: ByteArray): Boolean {
        val accessibility = if (dataProtection) arrayOf<Pair<CFStringRef?, CFTypeRef?>>(kSecAttrAccessible to kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly) else emptyArray()
        val status = withData(data) { value -> withQuery(account, kSecValueData to value, *accessibility) { SecItemAdd(it, null) } }
        return when (status) {
            errSecSuccess -> true
            errSecDuplicateItem -> false
            else -> throw KeychainException(status, "add")
        }
    }

    /** Replaces the data of item [account]. Tests only: providers never overwrite a key. */
    fun update(account: String, data: ByteArray) {
        val status = withData(data) { value ->
            withDictionary(arrayOf(kSecValueData to value)) { changes -> withQuery(account) { SecItemUpdate(it, changes) } }
        }
        if (status != errSecSuccess) throw KeychainException(status, "update")
    }

    /** Deletes item [account], or every item of the service. Tests only. */
    fun delete(account: String? = null) {
        val status = withQuery(account) { SecItemDelete(it) }
        if (status != errSecSuccess && status != errSecItemNotFound) throw KeychainException(status, "delete")
    }

    private fun <T> withQuery(account: String?, vararg extra: Pair<CFStringRef?, CFTypeRef?>, block: (CFDictionaryRef?) -> T): T {
        val owned = mutableListOf<CFTypeRef?>()
        try {
            val entries = mutableListOf<Pair<CFStringRef?, CFTypeRef?>>(
                kSecClass to kSecClassGenericPassword,
                kSecAttrService to cfString(service).also { owned += it },
                kSecAttrSynchronizable to kCFBooleanFalse,
            )
            if (account != null) entries += kSecAttrAccount to cfString(account).also { owned += it }
            if (accessGroup != null) entries += kSecAttrAccessGroup to cfString(accessGroup).also { owned += it }
            if (dataProtection) entries += kSecUseDataProtectionKeychain to kCFBooleanTrue
            entries += extra
            return withDictionary(entries.toTypedArray(), block)
        } finally {
            owned.forEach { CFRelease(it) }
        }
    }

    private fun <T> withDictionary(entries: Array<Pair<CFStringRef?, CFTypeRef?>>, block: (CFDictionaryRef?) -> T): T {
        val dictionary = CFDictionaryCreateMutable(null, entries.size.convert(), kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)
        try {
            entries.forEach { (key, value) -> CFDictionaryAddValue(dictionary, key, value) }
            return block(dictionary)
        } finally {
            CFRelease(dictionary)
        }
    }

    private fun <T> withData(data: ByteArray, block: (CFTypeRef?) -> T): T {
        val value = data.usePinned { CFDataCreate(null, if (data.isEmpty()) null else it.addressOf(0).reinterpret(), data.size.convert()) }
        try {
            return block(value)
        } finally {
            CFRelease(value)
        }
    }

    private fun cfString(value: String): CFTypeRef? = CFBridgingRetain(NSString.create(string = value))
}
