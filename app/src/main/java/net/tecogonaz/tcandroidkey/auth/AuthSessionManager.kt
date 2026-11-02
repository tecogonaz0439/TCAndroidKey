// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.auth

import android.os.SystemClock
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import net.tecogonaz.tcandroidkey.data.EventLogRepository
import net.tecogonaz.tcandroidkey.data.LogLevel
import net.tecogonaz.tcandroidkey.data.SettingsRepository
import net.tecogonaz.tcandroidkey.fido.ctap2.AuthorizationPolicy
import net.tecogonaz.tcandroidkey.fido.ctap2.AuthorizationRequest
import net.tecogonaz.tcandroidkey.fido.ctap2.AuthorizationResult
import net.tecogonaz.tcandroidkey.fido.ctap2.CtapOperation
import net.tecogonaz.tcandroidkey.fido.ctap2.CtapStatus
import net.tecogonaz.tcandroidkey.fido.ctap2.KeepAlive
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** 認証の受付状態。 */
data class AuthSessionState(
    /** アプリ画面が前面に表示されているか (= 認証を受け付ける前提条件)。 */
    val foreground: Boolean = false,
    /** 本人確認による受付の期限 (elapsedRealtime 基準)。null は未確認。 */
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

/** 本人確認ダイアログの表示要求。 */
data class VerificationRequest(val source: String, val rpId: String?)

/**
 * 「アプリ起動中 (前面表示中) のみ」「本人確認後の一定時間のみ」認証を許可するセッション管理。
 *
 * - [setForeground] は Activity の onStart/onStop から呼ばれる。前面でなくなると即座に受付を解除する。
 * - [arm] は BiometricPrompt 成功時に呼ばれ、設定された秒数だけ受付状態にする。
 * - ワンタイム設定時は 1 回の登録/認証で受付を解除する。
 */
class AuthSessionManager(
    private val settings: SettingsRepository,
    private val log: EventLogRepository,
    private val elapsed: () -> Long = SystemClock::elapsedRealtime
) {
    private val _state = MutableStateFlow(AuthSessionState())
    val state: StateFlow<AuthSessionState> = _state.asStateFlow()

    private val _verificationRequests = MutableSharedFlow<VerificationRequest>(
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    /** UI が購読し、本人確認ダイアログを表示する。 */
    val verificationRequests: SharedFlow<VerificationRequest> = _verificationRequests.asSharedFlow()

    private val lock = ReentrantLock()
    private val changed = lock.newCondition()

    fun isArmed(): Boolean = _state.value.isArmed(elapsed())

    fun setForeground(foreground: Boolean) {
        _state.update {
            if (foreground) it.copy(foreground = true)
            else it.copy(foreground = false, armedUntilElapsed = null)
        }
        if (!foreground) notifyWaiters()
    }

    fun arm() {
        val durationMs = settings.current.authWindowSeconds * 1000L
        _state.update { it.copy(armedUntilElapsed = elapsed() + durationMs, armedDurationMillis = durationMs) }
        log.log(LogLevel.INFO, SOURCE, "verified: accepting authentication for ${durationMs / 1000}s")
        notifyWaiters()
    }

    fun disarm(reason: String? = null) {
        val wasArmed = _state.value.armedUntilElapsed != null
        _state.update { it.copy(armedUntilElapsed = null) }
        if (wasArmed && reason != null) log.log(LogLevel.INFO, SOURCE, "authorization ended: $reason")
        notifyWaiters()
    }

    /** UI に本人確認を要求する (設定で無効な場合は何もしない)。 */
    fun requestVerification(source: String, rpId: String?) {
        if (!_state.value.foreground) return
        if (!settings.current.promptOnTap) return
        _verificationRequests.tryEmit(VerificationRequest(source, rpId))
    }

    /**
     * NFC の SELECT を受理してよいか。前面表示中かつ本人確認済みの場合のみ受理する。
     * 本人確認前にかざされた場合は確認ダイアログを要求し、拒否する (確認後に再度かざしてもらう)。
     */
    fun nfcSelectGate(): Boolean {
        val s = _state.value
        if (!s.foreground) {
            log.log(LogLevel.WARNING, "NFC", "reader detected but the app is not in the foreground; rejected")
            return false
        }
        if (!s.isArmed(elapsed())) {
            log.log(LogLevel.WARNING, "NFC", "reader detected before verification; asking for verification")
            requestVerification("NFC", null)
            return false
        }
        return true
    }

    /** トランスポート別の認可ポリシーを生成する。 */
    fun policy(transport: String, blocking: Boolean): TransportPolicy = TransportPolicy(transport, blocking)

    private fun notifyWaiters() {
        lock.withLock { changed.signalAll() }
    }

    private fun onCompleted(request: AuthorizationRequest, success: Boolean) {
        if (!success || !request.requireUserPresence) return
        if (request.operation == CtapOperation.SELECTION) return
        _state.update {
            it.copy(lastAuthenticationAtMillis = System.currentTimeMillis(), lastAuthenticationRpId = request.rpId)
        }
        if (settings.current.oneTimeAuthorization) disarm("one-time authorization used")
    }

    /**
     * @param blocking true の場合 (Bluetooth HID)、未確認ならダイアログを表示して最大 [WAIT_TIMEOUT_MS] 待つ。
     *                 false の場合 (NFC)、未確認なら即座に拒否する。
     */
    inner class TransportPolicy(private val transport: String, private val blocking: Boolean) : AuthorizationPolicy {
        @Volatile
        private var cancelled = false

        /** ホストからのキャンセル (CTAPHID_CANCEL)。 */
        fun cancel() {
            cancelled = true
            notifyWaiters()
        }

        override fun authorize(request: AuthorizationRequest, keepAlive: KeepAlive): AuthorizationResult {
            val s = _state.value
            if (!s.foreground) {
                return AuthorizationResult.Denied(CtapStatus.ERR_OPERATION_DENIED, "app is not in the foreground")
            }
            if (s.isArmed(elapsed())) return AuthorizationResult.Granted(userPresent = true, userVerified = true)
            if (!blocking) {
                requestVerification(transport, request.rpId)
                return AuthorizationResult.Denied(CtapStatus.ERR_OPERATION_DENIED, "user verification required")
            }
            cancelled = false
            requestVerification(transport, request.rpId)
            log.log(LogLevel.INFO, transport, "waiting for user verification (${request.rpId ?: "-"})")
            val deadline = elapsed() + WAIT_TIMEOUT_MS
            while (true) {
                val now = elapsed()
                val st = _state.value
                when {
                    cancelled -> return AuthorizationResult.Denied(CtapStatus.ERR_KEEPALIVE_CANCEL, "cancelled by host")
                    !st.foreground -> return AuthorizationResult.Denied(CtapStatus.ERR_OPERATION_DENIED, "app left foreground")
                    st.isArmed(now) -> return AuthorizationResult.Granted(userPresent = true, userVerified = true)
                    now >= deadline -> return AuthorizationResult.Denied(CtapStatus.ERR_USER_ACTION_TIMEOUT, "verification timeout")
                }
                keepAlive.send(KeepAlive.STATUS_UP_NEEDED)
                lock.withLock { changed.await(KEEPALIVE_INTERVAL_MS, TimeUnit.MILLISECONDS) }
            }
        }

        override fun onOperationCompleted(request: AuthorizationRequest, success: Boolean) =
            onCompleted(request, success)
    }

    companion object {
        private const val SOURCE = "Session"
        const val WAIT_TIMEOUT_MS: Long = 30_000
        const val KEEPALIVE_INTERVAL_MS: Long = 100
    }
}
