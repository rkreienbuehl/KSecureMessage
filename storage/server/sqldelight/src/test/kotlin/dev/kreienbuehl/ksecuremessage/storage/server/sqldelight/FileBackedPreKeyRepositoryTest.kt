package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.PreKeyRepositoryContractTest
import kotlin.test.AfterTest

/**
 * The shared contract, including its concurrency tests, on file-backed
 * SQLite: the JDBC driver opens one connection per thread there, so the races
 * run through real SQLite transactions on several connections.
 */
class FileBackedPreKeyRepositoryTest : PreKeyRepositoryContractTest() {
    private val databases = mutableListOf<TempDatabase>()

    override suspend fun newRepository(): PreKeyRepository =
        SqlDelightServerStorage.open(TempDatabase().also { databases += it }.driver()).preKeys

    @AfterTest
    fun deleteDatabases() = databases.forEach { it.close() }
}
