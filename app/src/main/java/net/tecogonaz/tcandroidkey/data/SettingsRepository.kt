// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.data

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.tecogonaz.tcandroidkey.domain.AppSettings
import net.tecogonaz.tcandroidkey.domain.AppTheme
import net.tecogonaz.tcandroidkey.fido.ctap2.AttestationMode

/** SharedPreferences に保存するアプリ設定のリポジトリ。 */
class SettingsRepository(context: Context) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _settings = MutableStateFlow(load())
    val settings: StateFlow<AppSettings> = _settings.asStateFlow()

    val current: AppSettings get() = _settings.value

    @Synchronized
    fun update(transform: (AppSettings) -> AppSettings) {
        val next = transform(_settings.value)
        if (!AppSettings.AUTH_WINDOW_CHOICES.contains(next.authWindowSeconds)) return
        save(next)
        _settings.value = next
    }

    private fun load(): AppSettings {
        val d = AppSettings()
        return AppSettings(
            theme = enumOrDefault(prefs.getString(KEY_THEME, null), d.theme),
            authWindowSeconds = prefs.getInt(KEY_AUTH_WINDOW, d.authWindowSeconds)
                .takeIf { it in AppSettings.AUTH_WINDOW_CHOICES } ?: d.authWindowSeconds,
            oneTimeAuthorization = prefs.getBoolean(KEY_ONE_TIME, d.oneTimeAuthorization),
            biometricOnly = prefs.getBoolean(KEY_BIOMETRIC_ONLY, d.biometricOnly),
            promptOnTap = prefs.getBoolean(KEY_PROMPT_ON_TAP, d.promptOnTap),
            attestationMode = enumOrDefault(prefs.getString(KEY_ATTESTATION, null), d.attestationMode),
            allowResetFromClient = prefs.getBoolean(KEY_ALLOW_RESET, d.allowResetFromClient),
            preferStrongBox = prefs.getBoolean(KEY_STRONGBOX, d.preferStrongBox),
            bluetoothEnabled = prefs.getBoolean(KEY_BLUETOOTH, d.bluetoothEnabled)
        )
    }

    private fun save(s: AppSettings) {
        prefs.edit {
            putString(KEY_THEME, s.theme.name)
            putInt(KEY_AUTH_WINDOW, s.authWindowSeconds)
            putBoolean(KEY_ONE_TIME, s.oneTimeAuthorization)
            putBoolean(KEY_BIOMETRIC_ONLY, s.biometricOnly)
            putBoolean(KEY_PROMPT_ON_TAP, s.promptOnTap)
            putString(KEY_ATTESTATION, s.attestationMode.name)
            putBoolean(KEY_ALLOW_RESET, s.allowResetFromClient)
            putBoolean(KEY_STRONGBOX, s.preferStrongBox)
            putBoolean(KEY_BLUETOOTH, s.bluetoothEnabled)
        }
    }

    private inline fun <reified T : Enum<T>> enumOrDefault(name: String?, default: T): T =
        name?.let { n -> enumValues<T>().firstOrNull { it.name == n } } ?: default

    private companion object {
        const val PREFS_NAME = "settings"
        const val KEY_THEME = "theme"
        const val KEY_AUTH_WINDOW = "auth_window_seconds"
        const val KEY_ONE_TIME = "one_time_authorization"
        const val KEY_BIOMETRIC_ONLY = "biometric_only"
        const val KEY_PROMPT_ON_TAP = "prompt_on_tap"
        const val KEY_ATTESTATION = "attestation_mode"
        const val KEY_ALLOW_RESET = "allow_reset_from_client"
        const val KEY_STRONGBOX = "prefer_strongbox"
        const val KEY_BLUETOOTH = "bluetooth_enabled"
    }
}
