package dev.kreienbuehl.ksecuremessage.sample.smoke

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import dev.kreienbuehl.ksecuremessage.storage.client.sqldelight.SqlDelightClientStorage
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider

// Compile-only: public client API from common code, resolved per target from
// the published artifacts.

fun inMemoryClient(address: DeviceAddress, transport: SecureMessageTransport): SecureMessageClient =
    SecureMessageClient(address, InMemoryClientStorage(), KodiumProtocolEngine(), transport)

suspend fun persistentClient(
    address: DeviceAddress,
    driver: SqlDriver,
    keys: StorageKeyProvider,
    transport: SecureMessageTransport,
): SecureMessageClient = SecureMessageClient(address, SqlDelightClientStorage.open(driver, keys), KodiumProtocolEngine(), transport)
