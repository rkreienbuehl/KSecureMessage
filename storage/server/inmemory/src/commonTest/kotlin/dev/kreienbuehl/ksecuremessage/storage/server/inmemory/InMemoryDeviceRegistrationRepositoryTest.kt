package dev.kreienbuehl.ksecuremessage.storage.server.inmemory

import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.DeviceRegistrationRepositoryContractTest

class InMemoryDeviceRegistrationRepositoryTest : DeviceRegistrationRepositoryContractTest() {
    override suspend fun newRepository(): DeviceRegistrationRepository = InMemoryServerStorage().devices
}
