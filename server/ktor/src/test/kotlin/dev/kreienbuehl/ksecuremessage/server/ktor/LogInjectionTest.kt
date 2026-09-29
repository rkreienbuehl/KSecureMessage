package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.server.SecureMessageServer
import dev.kreienbuehl.ksecuremessage.storage.server.inmemory.InMemoryServerStorage
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.testApplication
import org.slf4j.Marker
import org.slf4j.event.Level
import org.slf4j.helpers.LegacyAbstractLogger
import org.slf4j.helpers.MessageFormatter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation

/**
 * Log injection through request-supplied identifiers (S1, findings F5/F6;
 * docs/security-review-remediation.md): an identifier may contain any UTF-8,
 * so a raw CR/LF could end a log line and forge the next one.
 */
class LogInjectionTest {
    /** Records every formatted log event. */
    private class RecordingLogger : LegacyAbstractLogger() {
        val events = mutableListOf<String>()

        override fun getName() = "recording"
        override fun isTraceEnabled() = true
        override fun isDebugEnabled() = true
        override fun isInfoEnabled() = true
        override fun isWarnEnabled() = true
        override fun isErrorEnabled() = true
        override fun getFullyQualifiedCallerName(): String? = null

        override fun handleNormalizedLoggingCall(level: Level, marker: Marker?, pattern: String?, arguments: Array<out Any?>?, throwable: Throwable?) {
            synchronized(events) { events += MessageFormatter.basicArrayFormat(pattern, arguments) }
        }
    }

    private val hostile = listOf(
        "evil\nINFO forged line",
        "evil\rERROR forged",
        "evil\r\nWARN forged",
        "evil forged",
        "evil forged",
        "evil\u0085forged",
        "tab\there",
        "nul\u0000byte",
    )

    @Test
    fun logSafeEscapesEveryLineBreakAndControl() {
        assertEquals("\"alice\"", logSafe("alice"))
        assertEquals("\"a\\nb\"", logSafe("a\nb"))
        assertEquals("\"a\\rb\"", logSafe("a\rb"))
        assertEquals("\"a\\r\\nb\"", logSafe("a\r\nb"))
        assertEquals("\"a\\tb\"", logSafe("a\tb"))
        assertEquals("\"a\\u2028b\\u2029c\\u0085d\\u0000e\\u007Ff\"", logSafe("a b c\u0085d\u0000e\u007Ff"))
        assertEquals("\"q\\\"b\\\\s\"", logSafe("q\"b\\s"), "quotes and backslashes cannot fake the framing")
        assertEquals("\"zoë 📱 Бob\"", logSafe("zoë 📱 Бob"), "ordinary UTF-8 stays readable")
        assertEquals("user=\"a\\nb\" device=\"c\"", DeviceAddress(UserId("a\nb"), DeviceId("c")).forLog())
        for (value in hostile) {
            val escaped = logSafe(value)
            assertFalse(escaped.any { it == '\n' || it == '\r' || it == ' ' || it == ' ' || it == '\u0085' || it.code < 0x20 }, value)
        }
    }

    @Test
    fun hostileAddressesOnPublicRoutesLogOneLineEachAndAreProcessedUnchanged() {
        val logger = RecordingLogger()
        val storage = InMemoryServerStorage()
        testApplication {
            environment { log = logger }
            install(ServerContentNegotiation) { json() }
            routing { kSecureMessageRoutes(SecureMessageServer(storage, ManualClock(), TestDeviceRegistrationAuthorizer.allowAll())) }
            val http = createClient { }
            for (value in hostile) {
                val target = DeviceAddress(UserId(value), DeviceId(value))
                // Public, unauthenticated routes that log the address from the path.
                val challenge = http.raw(HttpMethod.Post, ServerApiPaths.device(target, ServerApiPaths.LAST_DEVICE_RECOVERY_CHALLENGE), null, null)
                assertEquals(HttpStatusCode.NotFound, challenge.status, value)
                val status = http.raw(
                    HttpMethod.Post,
                    ServerApiPaths.user(target.userId, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET_STATUS),
                    "{}".encodeToByteArray(),
                    null,
                )
                assertTrue(status.status.value in 400..499, value)
            }
        }
        val events = synchronized(logger.events) { logger.events.toList() }
        assertTrue(events.isNotEmpty(), "the routes did log")
        for (event in events) {
            assertFalse(event.contains('\n') || event.contains('\r') || event.contains(' ') || event.contains(' ') || event.contains('\u0085'), event)
            assertFalse(event.lines().drop(1).any { it.startsWith("INFO") || it.startsWith("ERROR") || it.startsWith("WARN") }, event)
        }
        // The identifier is escaped in the log only; the escaped form names it completely.
        assertTrue(events.any { it.contains("user=\"evil\\nINFO forged line\"") }, events.toString())
    }
}
