package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.PreKeyRepositoryContractTest
import kotlin.test.AfterTest

/** The shared contract on SQLite (one in-memory database per repository). */
class SqlDelightPreKeyRepositoryTest : PreKeyRepositoryContractTest() {
    private val drivers = mutableListOf<SqlDriver>()

    override suspend fun newRepository(): PreKeyRepository =
        SqlDelightServerStorage.open(inMemoryDriver().also { drivers += it }).preKeys

    @AfterTest
    fun closeDrivers() = drivers.forEach { it.close() }
}
