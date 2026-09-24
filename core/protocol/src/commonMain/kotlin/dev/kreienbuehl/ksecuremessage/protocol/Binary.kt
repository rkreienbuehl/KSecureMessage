package dev.kreienbuehl.ksecuremessage.protocol

// Minimal big-endian framing helpers shared by SessionState and
// CiphertextMessageCodec. Pure Kotlin so every target produces identical
// bytes. BinaryReader throws IllegalArgumentException on malformed input;
// callers map it to a ProtocolException.

internal class BinaryWriter {
    private val parts = mutableListOf<ByteArray>()

    fun byte(value: Byte) {
        parts += byteArrayOf(value)
    }

    /** 32-bit big-endian. */
    fun int(value: Int) {
        parts += byteArrayOf((value shr 24).toByte(), (value shr 16).toByte(), (value shr 8).toByte(), value.toByte())
    }

    /** Raw bytes without a length prefix. */
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

internal class BinaryReader(private val data: ByteArray) {
    private var position = 0

    val remaining: Int get() = data.size - position

    fun byte(): Byte {
        require(remaining >= 1) { "Truncated input" }
        return data[position++]
    }

    /** 32-bit big-endian. */
    fun int(): Int {
        require(remaining >= 4) { "Truncated input" }
        var value = 0
        repeat(4) { value = (value shl 8) or (data[position++].toInt() and 0xFF) }
        return value
    }

    /** Exactly [size] bytes. Checked against the input before allocating. */
    fun fixed(size: Int): ByteArray {
        require(size in 0..remaining) { "Truncated input" }
        return data.copyOfRange(position, position + size).also { position += size }
    }

    /** Length-prefixed bytes, see [BinaryWriter.bytes]. */
    fun bytes(): ByteArray = fixed(int())

    fun requireEnd() {
        require(remaining == 0) { "Trailing data" }
    }
}
