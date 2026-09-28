package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.InternalKSecureMessageApi
import org.kotlincrypto.hash.sha2.SHA256

/**
 * Content commitment of an application message body, version 1
 * (docs/application-delivery.md). A client keeps it with a committed inbound
 * message so that a later message with the same logical ID but another body
 * is detected instead of acknowledged. Local storage only: it is never sent
 * and is not part of any wire format.
 *
 * ```
 * SHA-256( u32 length of domain | domain (UTF-8, ProtocolConstants.PROCESSED_MESSAGE_DOMAIN)
 *        | u32 length of body | body )
 * ```
 *
 * Integers are unsigned 32-bit big-endian. Frozen: the vectors in
 * `ApplicationMessageDigestTest` must never change.
 */
@InternalKSecureMessageApi
object ApplicationMessageDigest {
    const val SIZE: Int = 32

    fun of(body: ByteArray): ByteArray {
        val out = BinaryWriter()
        out.bytes(DOMAIN)
        out.bytes(body)
        val input = out.toByteArray()
        return try {
            SHA256().digest(input)
        } finally {
            input.fill(0)
        }
    }

    private val DOMAIN = ProtocolConstants.PROCESSED_MESSAGE_DOMAIN.encodeToByteArray()
}
