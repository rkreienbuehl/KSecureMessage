package dev.kreienbuehl.ksecuremessage.storage.encryption

internal fun testKey(id: Int, seed: Int) = StorageEncryptionKey(StorageKeyId(id), ByteArray(32) { (seed + it).toByte() })

internal fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

internal fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

internal fun ByteArray.flipped(index: Int): ByteArray = copyOf().also { it[index] = (it[index].toInt() xor 0x01).toByte() }
