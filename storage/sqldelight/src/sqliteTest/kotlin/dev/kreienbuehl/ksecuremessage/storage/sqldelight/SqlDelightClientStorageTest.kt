package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest
import kotlin.test.AfterTest

class SqlDelightClientStorageTest : ClientStorageContractTest() {
    private val databases = mutableListOf<TestDatabase>()

    override suspend fun newStorage(): ClientStorage =
        SqlDelightClientStorage(TestDatabase().also { databases += it }.open())

    @AfterTest
    fun closeDatabases() {
        databases.forEach { it.close() }
    }
}
