package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.DeviceRecoveryRepositoryContractTest
import kotlin.test.AfterTest

/**
 * The shared recovery contract, including its races, on file-backed SQLite
 * (one JDBC connection per thread, real SQLite transactions).
 */
class FileBackedDeviceRecoveryRepositoryTest : DeviceRecoveryRepositoryContractTest() {
    private val databases = mutableListOf<TempDatabase>()

    override suspend fun newStorage(): ServerStorage = SqlDelightServerStorage.open(TempDatabase().also { databases += it }.driver())

    @AfterTest
    fun deleteDatabases() = databases.forEach { it.close() }
}
