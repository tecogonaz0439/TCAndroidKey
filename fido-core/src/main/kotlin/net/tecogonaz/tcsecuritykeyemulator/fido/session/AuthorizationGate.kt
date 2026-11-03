// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.session

import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AuthorizationLease
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AuthorizationRequest
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AuthorizationResult
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.CtapStatus
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.KeepAlive
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** 認証の受付状態 (UI 表示用のスナップショット)。 */
data class SessionState(
    /** アプリ画面が前面に表示されているか (= 認証を受け付ける前提条件)。 */
    val foreground: Boolean = false,
    /** 本人確認による受付の期限 (単調時計基準)。null は未確認・受付終了。 */
    val armedUntilElapsed: Long? = null,
    /** 受付期間の長さ (ms)。プログレス表示用。 */
    val armedDurationMillis: Long = 0,
    /** 最後に認証 (登録/署名) を実行した時刻 (wall clock)。 */
    val lastAuthenticationAtMillis: Long? = null,
    val lastAuthenticationRpId: String? = null
) {
    fun isArmed(nowElapsed: Long): Boolean =
        foreground && armedUntilElapsed != null && nowElapsed < armedUntilElapsed

    fun remainingMillis(nowElapsed: Long): Long =
        if (armedUntilElapsed == null) 0 else (armedUntilElapsed - nowElapsed).coerceAtLeast(0)
}

/**
 * 「アプリ前面表示中のみ」「本人確認後の一定時間のみ」「ワンタイム」の認可を、全トランスポートで共有して判定する。
 *
 * 状態はすべて 1 つのロックで保護し、受付状態の判定とワンタイム枠の予約を原子的に行う。
 *
 * - **予約**: ワンタイム設定時は、許可した操作が [AuthorizationLease.complete] されるまで、
 *   他の操作には許可を出さない (NFC と Bluetooth の同時要求で 2 つの操作に許可を出さない)。
 * - **消費**: 成功した操作の complete(consumed = true) で受付を終了する。ただし、その操作を許可した時点の
 *   受付 (arm) に対してのみ効く (古い操作の完了で、新たに開始した受付を終了させない)。
 * - **失効**: 明示的な停止 ([disarm]) と前面離脱 ([setForeground] false) で世代 (epoch) を進め、
 *   発行済みのすべての Lease を無効にする。消費では失効させない (同一操作の GetNextAssertion を継続できる)。
 *
 * Android には依存しない (時計は注入する)。
 */
class AuthorizationGate(
    private val elapsed: () -> Long,
    private val wallClock: () -> Long = System::currentTimeMillis,
    private val oneTime: () -> Boolean = { true },
    private val waitTimeoutMillis: Long = WAIT_TIMEOUT_MS,
    private val listener: Listener = Listener.NONE
) {
    interface Listener {
        /** 状態が変わったときに呼ばれる (ロック保持中に呼ばれるため、ブロックしないこと)。 */
        fun onStateChanged(state: SessionState) {}

        /** ワンタイム認可が消費されたときに呼ばれる。 */
        fun onConsumed(rpId: String?) {}

        companion object {
            val NONE: Listener = object : Listener {}
        }
    }

    private val lock = ReentrantLock()
    private val changed = lock.newCondition()

    private var state = SessionState()
    private var epoch = 0L
    private var armId = 0L
    private var reservation: Lease? = null

    val snapshot: SessionState get() = lock.withLock { state }

    fun isArmed(): Boolean = lock.withLock { state.isArmed(elapsed()) }

    fun setForeground(foreground: Boolean) = lock.withLock {
        if (foreground) {
            update(state.copy(foreground = true))
        } else {
            revokeLocked()
            update(state.copy(foreground = false, armedUntilElapsed = null))
        }
        changed.signalAll()
    }

    /** 本人確認の成功により、[durationMillis] の間だけ受付状態にする。 */
    fun arm(durationMillis: Long) = lock.withLock {
        armId++
        update(state.copy(armedUntilElapsed = elapsed() + durationMillis, armedDurationMillis = durationMillis))
        changed.signalAll()
    }

    /**
     * 受付を明示的に停止し、発行済みのすべての Lease を失効させる。
     * @return 停止前に受付中 (期限の設定あり) だったか。
     */
    fun disarm(): Boolean = lock.withLock {
        val wasArmed = state.armedUntilElapsed != null
        revokeLocked()
        update(state.copy(armedUntilElapsed = null))
        changed.signalAll()
        wasArmed
    }

    /**
     * 操作の実行可否を判定する。
     *
     * @param blocking true の場合 (Bluetooth HID)、未確認・他操作の予約中なら最大 [waitTimeoutMillis] 待つ。
     *                 false の場合 (NFC)、即座に拒否する。
     * @param onVerificationNeeded 受付外のため本人確認が必要なときに 1 回呼ばれる (UI への確認要求用)。
     *                             ロック外で呼ばれる。
     */
    fun authorize(
        request: AuthorizationRequest,
        keepAlive: KeepAlive,
        blocking: Boolean,
        onVerificationNeeded: () -> Unit = {}
    ): AuthorizationResult {
        var verificationRequested = false
        val deadline = elapsed() + waitTimeoutMillis
        while (true) {
            var result: AuthorizationResult? = null
            var needVerification = false
            lock.withLock {
                val now = elapsed()
                val armed = state.isArmed(now)
                result = when {
                    keepAlive.isCancelled ->
                        AuthorizationResult.Denied(CtapStatus.ERR_KEEPALIVE_CANCEL, "cancelled by host")
                    !state.foreground ->
                        AuthorizationResult.Denied(CtapStatus.ERR_OPERATION_DENIED, "app is not in the foreground")
                    armed && reservation == null -> {
                        val lease = Lease(epoch, armId, request.rpId)
                        if (oneTime()) reservation = lease
                        AuthorizationResult.Granted(userPresent = true, userVerified = true, lease = lease)
                    }
                    !blocking && armed ->
                        AuthorizationResult.Denied(CtapStatus.ERR_OPERATION_DENIED, "another operation is in progress")
                    !blocking ->
                        AuthorizationResult.Denied(CtapStatus.ERR_OPERATION_DENIED, "user verification required")
                    now >= deadline ->
                        AuthorizationResult.Denied(CtapStatus.ERR_USER_ACTION_TIMEOUT, "verification timeout")
                    else -> null
                }
                if (!armed && !verificationRequested && (result == null || !blocking) &&
                    state.foreground && !keepAlive.isCancelled
                ) {
                    verificationRequested = true
                    needVerification = true
                }
            }
            if (needVerification) runCatching { onVerificationNeeded() }
            result?.let { return it }
            keepAlive.send(KeepAlive.STATUS_UP_NEEDED)
            lock.withLock {
                // 状態変化 (arm / 予約の解放 / 停止) で起こされる。取消は通知されないため短い間隔で再確認する。
                changed.await(KEEPALIVE_INTERVAL_MS, TimeUnit.MILLISECONDS)
            }
        }
    }

    private fun revokeLocked() {
        epoch++
        reservation = null
    }

    private fun update(next: SessionState) {
        if (next == state) return
        state = next
        runCatching { listener.onStateChanged(next) }
    }

    private inner class Lease(val epoch: Long, val armId: Long, val rpId: String?) : AuthorizationLease {
        private var completed = false

        override fun isValid(): Boolean = lock.withLock {
            state.foreground && this.epoch == this@AuthorizationGate.epoch
        }

        override fun complete(consumed: Boolean) {
            var consumedNow = false
            lock.withLock {
                if (completed) return
                completed = true
                if (reservation === this) reservation = null
                if (consumed && this.epoch == this@AuthorizationGate.epoch) {
                    var next = state.copy(lastAuthenticationAtMillis = wallClock(), lastAuthenticationRpId = rpId)
                    if (oneTime() && this.armId == this@AuthorizationGate.armId && next.armedUntilElapsed != null) {
                        next = next.copy(armedUntilElapsed = null)
                        consumedNow = true
                    }
                    update(next)
                }
                changed.signalAll()
            }
            if (consumedNow) runCatching { listener.onConsumed(rpId) }
        }
    }

    companion object {
        const val WAIT_TIMEOUT_MS: Long = 30_000
        const val KEEPALIVE_INTERVAL_MS: Long = 100
    }
}
