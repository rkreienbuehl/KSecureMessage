package dev.kreienbuehl.ksecuremessage.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Instant

/** The pure policy semantics (docs/device-authentication-rotation.md): due at `age >= maxKeyAge`, age never negative. */
class DeviceAuthenticationRotationPolicyTest {
    private val installedAt = Instant.parse("2026-01-01T00:00:00Z")
    private val policy = DeviceAuthenticationRotationPolicy(30.days)

    private fun status(now: Instant) = DeviceAuthenticationRotationStatus(
        authEpoch = 1,
        authKeyInstalledAt = installedAt,
        evaluatedAt = now,
        pendingRotation = false,
        pendingRecovery = false,
    )

    @Test
    fun dueExactlyFromTheMaximumAge() {
        assertFalse(policy.isDue(30.days - 1.nanoseconds), "below")
        assertTrue(policy.isDue(30.days), "exactly at the boundary")
        assertTrue(policy.isDue(30.days + 1.milliseconds), "above")
        assertFalse(policy.isDue(Duration.ZERO))
    }

    @Test
    fun ageIsTheClientTimeSinceTheServerInstallationTime() {
        assertEquals(29.days, status(installedAt + 29.days).age)
        assertFalse(policy.isDue(status(installedAt + 29.days).age))
        assertTrue(policy.isDue(status(installedAt + 30.days).age))
        assertEquals(Duration.ZERO, status(installedAt).age)
    }

    @Test
    fun aClockBehindTheInstallationTimeGivesAgeZero() {
        val behind = status(installedAt - 400.days)
        assertEquals(Duration.ZERO, behind.age, "clamped, never negative")
        assertFalse(DeviceAuthenticationRotationPolicy(1.nanoseconds).isDue(behind.age), "a backwards clock never makes a key due")
    }

    @Test
    fun infiniteMaximumAgeIsNeverDue() {
        val never = DeviceAuthenticationRotationPolicy(Duration.INFINITE)
        assertFalse(never.isDue(status(installedAt + 100_000.days).age))
        assertFalse(never.isDue(status(Instant.DISTANT_FUTURE).age))
    }

    @Test
    fun zeroAndNegativeMaximumAgesAreRejected() {
        assertFailsWith<IllegalArgumentException> { DeviceAuthenticationRotationPolicy(Duration.ZERO) }
        assertFailsWith<IllegalArgumentException> { DeviceAuthenticationRotationPolicy((-1).days) }
        assertFailsWith<IllegalArgumentException> { DeviceAuthenticationRotationPolicy(-Duration.INFINITE) }
        assertEquals(1.nanoseconds, DeviceAuthenticationRotationPolicy(1.nanoseconds).maxKeyAge)
    }
}
