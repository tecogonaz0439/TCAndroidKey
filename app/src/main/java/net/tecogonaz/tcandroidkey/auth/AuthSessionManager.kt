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
import net.tecogonaz.tcandroidkey.data.EventLogRepository
import net.tecogonaz.tcandroidkey.data.LogLevel
import net.tecogonaz.tcandroidkey.data.SettingsRepository
import net.tecogonaz.tcandroidkey.fido.ctap2.AuthorizationPolicy
import net.tecogonaz.tcandroidkey.fido.ctap2.AuthorizationRequest
import net.tecogonaz.tcandroidkey.fido.ctap2.AuthorizationResult
import net.tecogonaz.tcandroidkey.fido.ctap2.KeepAlive
import net.tecogonaz.tcandroidkey.fido.session.AuthorizationGate
import net.tecogonaz.tcandroidkey.fido.session.SessionState

/** 認証の受付状態 (UI 表示用)。実体は fido-core の [SessionState]。 */
typealias AuthSessionState = SessionState

/** 本人確認ダイアログの表示要求。 */
data class VerificationRequest(val source: String, val rpId: String?)

/**
 * 「アプリ起動中 (前面表示中) のみ」「本人確認後の一定時間のみ」認証を許可するセッション管理。
 *
 * 判定・予約・失効は全トランスポートで共有する [AuthorizationGate] が行う (Android 非依存・単体テスト済み)。
 * 本クラスは Android の時計・設定・ログ・UI への確認要求との橋渡しをする。
 *
 * - [setForeground] は Activity の onStart/onStop から呼ばれる。前面でなくなると即座に受付を解除し、
 *   実行中・継続中 (GetNextAssertion) の操作も無効にする。
 * - [arm] は BiometricPrompt 成功時に呼ばれ、設定された秒数だけ受付状態にする。
 * - [disarm] (明示的な停止) も実行中・継続中の操作を無効にする。
 * - ワンタイム設定時は 1 つの操作だけに許可を出し、その成功で受付を解除する。
 */
class AuthSessionManager(
    private val settings: SettingsRepository,
    private val log: EventLogRepository,
    elapsed: () -> Long = SystemClock::elapsedRealtime
) {
    private val _state = MutableStateFlow(AuthSessionState())
    val state: StateFlow<AuthSessionState> = _state.asStateFlow()

    private val gate = AuthorizationGate(
        elapsed = elapsed,
        oneTime = { settings.current.oneTimeAuthorization },
        listener = object : AuthorizationGate.Listener {
            override fun onStateChanged(state: SessionState) {
                _state.value = state
            }

            override fun onConsumed(rpId: String?) {
                log.log(LogLevel.INFO, SOURCE, "authorization ended: one-time authorization used")
            }
        }
    )

    private val _verificationRequests = MutableSharedFlow<VerificationRequest>(
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    /** UI が購読し、本人確認ダイアログを表示する。 */
    val verificationRequests: SharedFlow<VerificationRequest> = _verificationRequests.asSharedFlow()

    fun isArmed(): Boolean = gate.isArmed()

    fun setForeground(foreground: Boolean) = gate.setForeground(foreground)

    fun arm() {
        val durationMs = settings.current.authWindowSeconds * 1000L
        gate.arm(durationMs)
        log.log(LogLevel.INFO, SOURCE, "verified: accepting authentication for ${durationMs / 1000}s")
    }

    fun disarm(reason: String? = null) {
        val wasArmed = gate.disarm()
        if (wasArmed && reason != null) log.log(LogLevel.INFO, SOURCE, "authorization ended: $reason")
    }

    /** UI に本人確認を要求する (設定で無効な場合は何もしない)。 */
    fun requestVerification(source: String, rpId: String?) {
        if (!gate.snapshot.foreground) return
        if (!settings.current.promptOnTap) return
        _verificationRequests.tryEmit(VerificationRequest(source, rpId))
    }

    /**
     * NFC の SELECT を受理してよいか。前面表示中かつ本人確認済みの場合のみ受理する。
     * 本人確認前にかざされた場合は確認ダイアログを要求し、拒否する (確認後に再度かざしてもらう)。
     */
    fun nfcSelectGate(): Boolean {
        if (!gate.snapshot.foreground) {
            log.log(LogLevel.WARNING, "NFC", "reader detected but the app is not in the foreground; rejected")
            return false
        }
        if (!gate.isArmed()) {
            log.log(LogLevel.WARNING, "NFC", "reader detected before verification; asking for verification")
            requestVerification("NFC", null)
            return false
        }
        return true
    }

    /**
     * トランスポート別の認可ポリシーを生成する。
     *
     * @param blocking true の場合 (Bluetooth HID)、未確認ならダイアログを表示して最大 30 秒待つ。
     *                 false の場合 (NFC)、未確認なら即座に拒否する。
     */
    fun policy(transport: String, blocking: Boolean): AuthorizationPolicy =
        AuthorizationPolicy { request: AuthorizationRequest, keepAlive: KeepAlive ->
            val result = gate.authorize(request, keepAlive, blocking) {
                requestVerification(transport, request.rpId)
                if (blocking) {
                    log.log(
                        LogLevel.INFO, transport, "waiting for user verification (${request.rpId ?: "-"})",
                        logcatMessage = "waiting for user verification"
                    )
                }
            }
            if (result is AuthorizationResult.Denied && result.reason.startsWith("another operation")) {
                log.log(LogLevel.WARNING, transport, "rejected: another operation is using the one-time authorization")
            }
            result
        }

    private companion object {
        const val SOURCE = "Session"
    }
}
