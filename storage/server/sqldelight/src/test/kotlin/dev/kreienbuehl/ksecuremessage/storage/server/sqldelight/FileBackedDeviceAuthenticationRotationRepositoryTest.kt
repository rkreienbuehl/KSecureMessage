package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.DeviceAuthenticationRotationRepositoryContractTest
import kotlin.test.AfterTest

/**
 * The shared rotation contract, including its races, on file-backed SQLite
 * (one JDBC connection per thread, real SQLite transactions).
 */
class FileBackedDeviceAuthenticationRotationRepositoryTest : DeviceAuthenticationRotationRepositoryContractTest() {
    private val databases = mutableListOf<TempDatabase>()
    private val drivers = mutableMapOf<ServerStorage, SqlDriver>()

    override suspend fun newStorage(): ServerStorage {
        val driver = TempDatabase().also { databases += it }.driver()
        return SqlDelightServerStorage.open(driver).also { drivers[it] = driver }
    }

    override suspend fun setAuthEpoch(storage: ServerStorage, address: DeviceAddress, authEpoch: Long) =
        drivers.getValue(storage).setAuthEpoch(address, authEpoch)

    @AfterTest
    fun deleteDatabases() = databases.forEach { it.close() }
}
