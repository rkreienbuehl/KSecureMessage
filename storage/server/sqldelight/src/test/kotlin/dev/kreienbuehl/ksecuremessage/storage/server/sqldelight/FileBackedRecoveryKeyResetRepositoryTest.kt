package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.RecoveryKeyResetRepositoryContractTest
import kotlin.test.AfterTest

/**
 * The shared delayed recovery key reset contract, including its races, on file-backed SQLite
 * (one JDBC connection per thread, real SQLite transactions).
 */
class FileBackedRecoveryKeyResetRepositoryTest : RecoveryKeyResetRepositoryContractTest() {
    private val databases = mutableListOf<TempDatabase>()
    private val drivers = mutableMapOf<ServerStorage, SqlDriver>()

    override suspend fun newStorage(): ServerStorage {
        val driver = TempDatabase().also { databases += it }.driver()
        return SqlDelightServerStorage.open(driver).also { drivers[it] = driver }
    }

    override suspend fun setRecoveryKeyEpoch(storage: ServerStorage, userId: UserId, epoch: Long) =
        drivers.getValue(storage).setRecoveryKeyEpoch(userId, epoch)

    @AfterTest
    fun deleteDatabases() = databases.forEach { it.close() }
}
