// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.data

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import net.tecogonaz.tcandroidkey.fido.ctap2.AuthenticatorEvent
import net.tecogonaz.tcandroidkey.fido.ctap2.CtapCommand
import net.tecogonaz.tcandroidkey.fido.ctap2.CtapStatus

enum class LogLevel { INFO, SUCCESS, WARNING, ERROR }

data class LogEntry(
    val id: Long,
    val timestampMillis: Long,
    val level: LogLevel,
    val source: String,
    val message: String
)

/**
 * 認証器の動作ログ (メモリ内のみ・プロセス終了で消去)。
 * プライバシー保護のため永続化しない。
 *
 * 開発時の確認用に logcat にも出力するが、logcat には RP ID・ユーザー名などの識別情報を含めない
 * (ADB・バグレポート等から読めるため)。詳細はアプリ内のログ画面でのみ確認できる。
 */
class EventLogRepository(private val maxEntries: Int = 300) {
    private val _entries = MutableStateFlow<List<LogEntry>>(emptyList())
    val entries: StateFlow<List<LogEntry>> = _entries.asStateFlow()
    private var nextId = 0L

    /**
     * @param message アプリ内のログに表示する内容 (RP ID・ユーザー名を含めてよい)。
     * @param logcatMessage logcat に出力する内容。識別情報を含む [message] の場合は、それを除いたものを渡す。
     */
    @Synchronized
    fun log(level: LogLevel, source: String, message: String, logcatMessage: String = message) {
        val entry = LogEntry(nextId++, System.currentTimeMillis(), level, source, message)
        _entries.update { (listOf(entry) + it).take(maxEntries) }
        when (level) {
            LogLevel.ERROR -> Log.e(TAG, "[$source] $logcatMessage")
            LogLevel.WARNING -> Log.w(TAG, "[$source] $logcatMessage")
            else -> Log.i(TAG, "[$source] $logcatMessage")
        }
    }

    fun onAuthenticatorEvent(event: AuthenticatorEvent) {
        val level = when {
            event.isSuccess && event.command != CtapCommand.GET_INFO -> LogLevel.SUCCESS
            event.isSuccess -> LogLevel.INFO
            event.status == CtapStatus.ERR_NO_CREDENTIALS -> LogLevel.WARNING
            else -> LogLevel.ERROR
        }
        val result = "${CtapCommand.name(event.command)} → ${CtapStatus.name(event.status)}"
        val detail = if (!event.isSuccess) event.detail?.let { " ($it)" } ?: "" else ""
        val msg = buildString {
            append(result)
            event.rpId?.let { append(" rp=").append(it) }
            event.userName?.let { append(" user=").append(it) }
            append(detail)
        }
        log(level, event.transport, msg, logcatMessage = result + detail)
    }

    fun clear() {
        _entries.value = emptyList()
    }

    private companion object {
        const val TAG = "TCAndroidKey"
    }
}
