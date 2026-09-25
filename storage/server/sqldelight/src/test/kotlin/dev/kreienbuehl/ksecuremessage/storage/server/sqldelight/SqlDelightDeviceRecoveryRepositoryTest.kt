package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.DeviceRecoveryRepositoryContractTest
import kotlin.test.AfterTest

/** The shared recovery contract on SQLite (one in-memory database per storage). */
class SqlDelightDeviceRecoveryRepositoryTest : DeviceRecoveryRepositoryContractTest() {
    private val drivers = mutableListOf<SqlDriver>()

    override suspend fun newStorage(): ServerStorage = SqlDelightServerStorage.open(inMemoryDriver().also { drivers += it })

    @AfterTest
    fun closeDrivers() = drivers.forEach { it.close() }
}
