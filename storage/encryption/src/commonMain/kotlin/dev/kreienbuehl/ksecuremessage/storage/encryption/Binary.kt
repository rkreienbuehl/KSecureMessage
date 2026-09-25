package dev.kreienbuehl.ksecuremessage.storage.encryption

// Big-endian framing for the local storage formats. Same conventions as the
// protocol codecs, but a separate copy: storage formats are versioned on
// their own. RecordReader throws MalformedRecord on invalid input.

internal class RecordWriter {
    private val parts = mutableListOf<ByteArray>()

    fun byte(value: Byte) {
        parts += byteArrayOf(value)
    }

    /** 32-bit big-endian. */
    fun int(value: Int) {
        parts += intBytes(value)
    }

    fun fixed(value: ByteArray) {
        parts += value
    }

    /** 32-bit big-endian length followed by the bytes. */
    fun bytes(value: ByteArray) {
        int(value.size)
        parts += value
    }

    fun toByteArray(): ByteArray {
        val result = ByteArray(parts.sumOf { it.size })
        var offset = 0
        for (part in parts) {
            part.copyInto(result, offset)
            offset += part.size
        }
        return result
    }
}

internal class RecordReader(private val data: ByteArray) {
    private var position = 0

    private val remaining: Int get() = data.size - position

    fun byte(): Byte {
        check(1)
        return data[position++]
    }

    fun int(): Int {
        check(4)
        var value = 0
        repeat(4) { value = (value shl 8) or (data[position++].toInt() and 0xFF) }
        return value
    }

    fun fixed(size: Int): ByteArray {
        if (size < 0) throw StorageEncryptionException.MalformedRecord("Invalid field length")
        check(size)
        return data.copyOfRange(position, position + size).also { position += size }
    }

    fun bytes(): ByteArray = fixed(int())

    fun requireEnd() {
        if (remaining != 0) throw StorageEncryptionException.MalformedRecord("Trailing data in storage record")
    }

    private fun check(size: Int) {
        if (size > remaining) throw StorageEncryptionException.MalformedRecord("Truncated storage record")
    }
}

internal fun intBytes(value: Int): ByteArray =
    byteArrayOf((value shr 24).toByte(), (value shr 16).toByte(), (value shr 8).toByte(), value.toByte())
