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
 */
class EventLogRepository(private val maxEntries: Int = 300) {
    private val _entries = MutableStateFlow<List<LogEntry>>(emptyList())
    val entries: StateFlow<List<LogEntry>> = _entries.asStateFlow()
    private var nextId = 0L

    @Synchronized
    fun log(level: LogLevel, source: String, message: String) {
        val entry = LogEntry(nextId++, System.currentTimeMillis(), level, source, message)
        _entries.update { (listOf(entry) + it).take(maxEntries) }
        when (level) {
            LogLevel.ERROR -> Log.e(TAG, "[$source] $message")
            LogLevel.WARNING -> Log.w(TAG, "[$source] $message")
            else -> Log.i(TAG, "[$source] $message")
        }
    }

    fun onAuthenticatorEvent(event: AuthenticatorEvent) {
        val level = when {
            event.isSuccess && event.command != CtapCommand.GET_INFO -> LogLevel.SUCCESS
            event.isSuccess -> LogLevel.INFO
            event.status == CtapStatus.ERR_NO_CREDENTIALS -> LogLevel.WARNING
            else -> LogLevel.ERROR
        }
        val msg = buildString {
            append(CtapCommand.name(event.command))
            append(" → ")
            append(CtapStatus.name(event.status))
            event.rpId?.let { append(" rp=").append(it) }
            event.userName?.let { append(" user=").append(it) }
            if (!event.isSuccess) event.detail?.let { append(" (").append(it).append(")") }
        }
        log(level, event.transport, msg)
    }

    fun clear() {
        _entries.value = emptyList()
    }

    private companion object {
        const val TAG = "TCAndroidKey"
    }
}
