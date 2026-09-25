package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.DeviceRegistrationRepositoryContractTest
import kotlin.test.AfterTest

/**
 * The shared contract, including its concurrency tests, on file-backed
 * SQLite: the JDBC driver opens one connection per thread there, so the races
 * run through real SQLite transactions on several connections.
 */
class FileBackedDeviceRegistrationRepositoryTest : DeviceRegistrationRepositoryContractTest() {
    private val databases = mutableListOf<TempDatabase>()

    override suspend fun newRepository(): DeviceRegistrationRepository =
        SqlDelightServerStorage.open(TempDatabase().also { databases += it }.driver()).devices

    @AfterTest
    fun deleteDatabases() = databases.forEach { it.close() }
}
