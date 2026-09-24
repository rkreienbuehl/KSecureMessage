package dev.kreienbuehl.ksecuremessage.storage

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession

interface SessionStore {
    suspend fun load(address: DeviceAddress): SecureSession?
    suspend fun store(session: SecureSession)
    suspend fun remove(address: DeviceAddress)
}

/**
 * Client storage boundary. The transaction method is intentionally explicit:
 * ratchet state must be updated atomically with successful encrypt/decrypt work.
 */
interface ClientStorage {
    val sessions: SessionStore

    suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T
}
