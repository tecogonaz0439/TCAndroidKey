// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.session

import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AuthorizationRequest
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AuthorizationResult
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.CtapOperation
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.CtapStatus
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.KeepAlive
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.CancellableKeepAlive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class AuthorizationGateTest {

    private var now = 1_000L
    private var oneTime = true
    private val gate = AuthorizationGate(elapsed = { now }, wallClock = { 42L }, oneTime = { oneTime })

    private val request = AuthorizationRequest(CtapOperation.GET_ASSERTION, "example.com", null, true, true)

    private fun authorize(keepAlive: KeepAlive = KeepAlive.NONE, onNeed: () -> Unit = {}) =
        gate.authorize(request, keepAlive, blocking = false, onVerificationNeeded = onNeed)

    private fun granted(r: AuthorizationResult) = r as AuthorizationResult.Granted

    private fun assertDenied(r: AuthorizationResult, status: Int = CtapStatus.ERR_OPERATION_DENIED) {
        assertTrue("expected Denied but was $r", r is AuthorizationResult.Denied)
        assertEquals(status, (r as AuthorizationResult.Denied).status)
    }

    @Test
    fun deniedWhenNotForegroundOrNotVerified() {
        assertDenied(authorize())
        gate.setForeground(true)
        var asked = 0
        assertDenied(authorize { asked++ })
        assertEquals("verification is requested when not armed", 1, asked)
        gate.arm(60_000)
        granted(authorize())
    }

    @Test
    fun armExpiresWithTime() {
        gate.setForeground(true)
        gate.arm(1_000)
        now += 1_000
        assertDenied(authorize())
    }

    @Test
    fun oneTimeReservesTheWindowForASingleOperation() {
        gate.setForeground(true)
        gate.arm(60_000)
        val first = granted(authorize())
        var asked = 0
        val second = authorize { asked++ }
        assertDenied(second)
        assertTrue((second as AuthorizationResult.Denied).reason.contains("another operation"))
        assertEquals("busy is not a reason to ask for verification", 0, asked)
        first.lease.complete(consumed = true)
        assertFalse(gate.isArmed())
        assertDenied(authorize())
        assertEquals(42L, gate.snapshot.lastAuthenticationAtMillis)
    }

    @Test
    fun failedOperationReleasesTheReservationWithoutConsuming() {
        gate.setForeground(true)
        gate.arm(60_000)
        granted(authorize()).lease.complete(consumed = false)
        assertTrue(gate.isArmed())
        granted(authorize())
    }

    @Test
    fun completeIsIdempotent() {
        gate.setForeground(true)
        gate.arm(60_000)
        val lease = granted(authorize()).lease
        lease.complete(consumed = false)
        val second = granted(authorize())
        lease.complete(consumed = true) // 既に完了済みの Lease は何もしない
        assertTrue(gate.isArmed())
        assertDenied(authorize()) // second が予約中
        second.lease.complete(consumed = true)
        assertFalse(gate.isArmed())
    }

    @Test
    fun withoutOneTimeConcurrentOperationsAreAllowed() {
        oneTime = false
        gate.setForeground(true)
        gate.arm(60_000)
        val a = granted(authorize())
        val b = granted(authorize())
        a.lease.complete(true)
        b.lease.complete(true)
        assertTrue(gate.isArmed())
    }

    @Test
    fun concurrentRequestsGetAtMostOneGrant() {
        gate.setForeground(true)
        gate.arm(60_000)
        val threads = 8
        val barrier = CyclicBarrier(threads)
        val grants = AtomicInteger()
        val pool = Executors.newFixedThreadPool(threads)
        repeat(threads) {
            pool.execute {
                barrier.await()
                if (authorize() is AuthorizationResult.Granted) grants.incrementAndGet()
            }
        }
        pool.shutdown()
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS))
        assertEquals(1, grants.get())
    }

    @Test
    fun explicitStopAndBackgroundRevokeLeasesButConsumptionDoesNot() {
        gate.setForeground(true)
        gate.arm(60_000)
        val a = granted(authorize()).lease
        a.complete(consumed = true)
        assertTrue("consumption keeps the operation (GetNextAssertion) valid", a.isValid())

        gate.arm(60_000)
        val b = granted(authorize()).lease
        gate.disarm()
        assertFalse(b.isValid())
        assertFalse(a.isValid())

        gate.arm(60_000)
        val c = granted(authorize()).lease
        gate.setForeground(false)
        assertFalse(c.isValid())
        gate.setForeground(true)
        assertFalse("returning to foreground does not revive old leases", c.isValid())
    }

    @Test
    fun stopReleasesTheReservation() {
        gate.setForeground(true)
        gate.arm(60_000)
        granted(authorize())
        gate.disarm()
        gate.arm(60_000)
        granted(authorize())
    }

    @Test
    fun staleCompletionDoesNotEndANewerWindow() {
        gate.setForeground(true)
        gate.arm(60_000)
        val old = granted(authorize()).lease
        gate.arm(60_000) // 再度の本人確認 (予約は維持される)
        old.complete(consumed = true)
        assertTrue("completion of an operation granted by an older arm keeps the new window", gate.isArmed())
    }

    @Test
    fun cancelledRequestIsDeniedEvenWhenArmed() {
        gate.setForeground(true)
        gate.arm(60_000)
        val ka = CancellableKeepAlive().apply { cancelled = true }
        assertDenied(authorize(ka), CtapStatus.ERR_KEEPALIVE_CANCEL)
        granted(authorize())
    }

    // ------------------------------------------------------------------ blocking (Bluetooth)

    private val realGate = AuthorizationGate(
        elapsed = { System.nanoTime() / 1_000_000 },
        oneTime = { true },
        waitTimeoutMillis = 5_000
    )

    private fun authorizeAsync(keepAlive: KeepAlive, onNeed: () -> Unit = {}): Pair<CountDownLatch, AtomicReference<AuthorizationResult>> {
        val done = CountDownLatch(1)
        val result = AtomicReference<AuthorizationResult>()
        Thread {
            result.set(realGate.authorize(request, keepAlive, blocking = true, onVerificationNeeded = onNeed))
            done.countDown()
        }.start()
        return done to result
    }

    @Test
    fun blockingWaitsForVerification() {
        realGate.setForeground(true)
        val asked = CountDownLatch(1)
        val (done, result) = authorizeAsync(KeepAlive.NONE) { asked.countDown() }
        assertTrue(asked.await(2, TimeUnit.SECONDS))
        realGate.arm(60_000)
        assertTrue(done.await(2, TimeUnit.SECONDS))
        assertTrue(result.get() is AuthorizationResult.Granted)
    }

    @Test
    fun blockingWaitsForTheReservationToBeReleased() {
        realGate.setForeground(true)
        realGate.arm(60_000)
        val first = realGate.authorize(request, KeepAlive.NONE, blocking = false) as AuthorizationResult.Granted
        val (done, result) = authorizeAsync(KeepAlive.NONE)
        assertFalse(done.await(300, TimeUnit.MILLISECONDS))
        first.lease.complete(consumed = false)
        assertTrue(done.await(2, TimeUnit.SECONDS))
        assertTrue(result.get() is AuthorizationResult.Granted)
    }

    @Test
    fun blockingStopsOnCancelAndOnLeavingForeground() {
        realGate.setForeground(true)
        val ka = CancellableKeepAlive()
        val (done, result) = authorizeAsync(ka)
        Thread.sleep(150)
        ka.cancelled = true
        assertTrue(done.await(2, TimeUnit.SECONDS))
        assertEquals(CtapStatus.ERR_KEEPALIVE_CANCEL, (result.get() as AuthorizationResult.Denied).status)

        val (done2, result2) = authorizeAsync(KeepAlive.NONE)
        Thread.sleep(150)
        realGate.setForeground(false)
        assertTrue(done2.await(2, TimeUnit.SECONDS))
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, (result2.get() as AuthorizationResult.Denied).status)
    }

    @Test
    fun cancelBeforeTheWaitStartsIsNotLost() {
        realGate.setForeground(true)
        val ka = CancellableKeepAlive().apply { cancelled = true }
        val r = realGate.authorize(request, ka, blocking = true)
        assertEquals(CtapStatus.ERR_KEEPALIVE_CANCEL, (r as AuthorizationResult.Denied).status)
    }

    @Test
    fun blockingTimesOut() {
        val g = AuthorizationGate(elapsed = { System.nanoTime() / 1_000_000 }, waitTimeoutMillis = 200)
        g.setForeground(true)
        val r = g.authorize(request, KeepAlive.NONE, blocking = true)
        assertEquals(CtapStatus.ERR_USER_ACTION_TIMEOUT, (r as AuthorizationResult.Denied).status)
    }

    @Test
    fun stateChangesAreReported() {
        val states = mutableListOf<SessionState>()
        val consumed = mutableListOf<String?>()
        val g = AuthorizationGate(
            elapsed = { now },
            listener = object : AuthorizationGate.Listener {
                override fun onStateChanged(state: SessionState) { states += state }
                override fun onConsumed(rpId: String?) { consumed += rpId }
            }
        )
        g.setForeground(true)
        g.arm(10_000)
        (g.authorize(request, KeepAlive.NONE, false) as AuthorizationResult.Granted).lease.complete(true)
        assertNotNull(states.last().lastAuthenticationAtMillis)
        assertEquals(null, states.last().armedUntilElapsed)
        assertEquals(listOf<String?>("example.com"), consumed)
    }
}
