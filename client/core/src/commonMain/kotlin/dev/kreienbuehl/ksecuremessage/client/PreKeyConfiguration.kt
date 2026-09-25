package dev.kreienbuehl.ksecuremessage.client

import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

/**
 * Local prekey inventory and signed prekey lifecycle settings, see
 * docs/signed-prekey-lifecycle.md.
 *
 * [oneTimePreKeyTarget] is the number of unused one-time prekeys
 * [SecureMessageClient.initialize] keeps in storage. Consumed keys are
 * replaced with new ones on the next initialization.
 *
 * [signedPreKeyRotationAge] is the age at which [SecureMessageClient.initialize]
 * replaces the current signed prekey with a new one. Must be positive;
 * [Duration.INFINITE] turns age-based rotation off.
 *
 * [signedPreKeyGracePeriod] is how long a replaced signed prekey keeps its
 * private key, so delayed first-contact messages that name it can still be
 * accepted. After that, initiations that name it are rejected and
 * [SecureMessageClient.initialize] deletes it. It also bounds how long a
 * withheld initiation can be accepted. Must not be negative. Zero means a
 * replaced key is rejected at once and deleted on the next initialization, so
 * every first-contact message still in flight at rotation fails.
 * [Duration.INFINITE] keeps replaced keys forever (the behavior before
 * milestone 7).
 *
 * The defaults are this project's conservative starting values, easy to
 * change per client. They are not taken from Signal or another protocol.
 */
data class PreKeyConfiguration(
    val oneTimePreKeyTarget: Int = 100,
    val signedPreKeyRotationAge: Duration = 7.days,
    val signedPreKeyGracePeriod: Duration = 30.days,
) {
    init {
        require(oneTimePreKeyTarget >= 0) { "oneTimePreKeyTarget must not be negative" }
        require(signedPreKeyRotationAge.isPositive()) { "signedPreKeyRotationAge must be positive" }
        require(!signedPreKeyGracePeriod.isNegative()) { "signedPreKeyGracePeriod must not be negative" }
    }
}
