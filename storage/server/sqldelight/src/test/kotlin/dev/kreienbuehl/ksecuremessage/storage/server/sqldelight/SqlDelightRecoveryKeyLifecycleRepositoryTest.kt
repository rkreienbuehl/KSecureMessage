package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.RecoveryKeyLifecycleRepositoryContractTest
import kotlin.test.AfterTest

/** The shared recovery key lifecycle contract on SQLite (one in-memory database per storage). */
class SqlDelightRecoveryKeyLifecycleRepositoryTest : RecoveryKeyLifecycleRepositoryContractTest() {
    private val drivers = mutableMapOf<ServerStorage, SqlDriver>()

    override suspend fun newStorage(): ServerStorage {
        val driver = inMemoryDriver()
        return SqlDelightServerStorage.open(driver).also { drivers[it] = driver }
    }

    override suspend fun setRecoveryKeyEpoch(storage: ServerStorage, userId: UserId, epoch: Long) =
        drivers.getValue(storage).setRecoveryKeyEpoch(userId, epoch)

    @AfterTest
    fun closeDrivers() = drivers.values.forEach { it.close() }
}
