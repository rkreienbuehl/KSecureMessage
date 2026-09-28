package dev.kreienbuehl.ksecuremessage.sample.smoke

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple.AppleStorageKeyProvider

fun appleKeys(): StorageKeyProvider = AppleStorageKeyProvider()
