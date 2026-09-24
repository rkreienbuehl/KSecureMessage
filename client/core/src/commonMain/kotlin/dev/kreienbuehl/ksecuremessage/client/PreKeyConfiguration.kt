package dev.kreienbuehl.ksecuremessage.client

/**
 * Local prekey inventory settings.
 *
 * [oneTimePreKeyTarget] is the number of unused one-time prekeys
 * [SecureMessageClient.initialize] keeps in storage. Consumed keys are
 * replaced with new ones on the next initialization.
 */
data class PreKeyConfiguration(
    val oneTimePreKeyTarget: Int = 100,
) {
    init {
        require(oneTimePreKeyTarget >= 0) { "oneTimePreKeyTarget must not be negative" }
    }
}
