package dev.gvpn

import org.junit.Assert.assertTrue
import org.junit.Test

class SmokeTest {
    @Test
    fun harnessRuns() {
        assertTrue("unit-test harness wired", 1 + 1 == 2)
    }
}
