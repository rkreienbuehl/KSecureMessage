package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.DeviceAuthenticationRotationRepositoryContractTest
import kotlin.test.AfterTest

/** The shared rotation contract on SQLite (one in-memory database per storage). */
class SqlDelightDeviceAuthenticationRotationRepositoryTest : DeviceAuthenticationRotationRepositoryContractTest() {
    private val drivers = mutableMapOf<ServerStorage, SqlDriver>()

    override suspend fun newStorage(): ServerStorage {
        val driver = inMemoryDriver()
        return SqlDelightServerStorage.open(driver).also { drivers[it] = driver }
    }

    override suspend fun setAuthEpoch(storage: ServerStorage, address: DeviceAddress, authEpoch: Long) =
        drivers.getValue(storage).setAuthEpoch(address, authEpoch)

    @AfterTest
    fun closeDrivers() = drivers.values.forEach { it.close() }
}
