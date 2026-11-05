// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.ui.settings

import android.app.LocaleManager
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.tecogonaz.tcsecuritykeyemulator.R
import net.tecogonaz.tcsecuritykeyemulator.domain.AppSettings
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AttestationMode
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.PinStatus
import net.tecogonaz.tcsecuritykeyemulator.ui.MainViewModel
import net.tecogonaz.tcsecuritykeyemulator.ui.UiActions
import net.tecogonaz.tcsecuritykeyemulator.ui.common.SettingItemClickable
import net.tecogonaz.tcsecuritykeyemulator.ui.common.SettingItemDropdown
import net.tecogonaz.tcsecuritykeyemulator.ui.common.SettingItemReadOnly
import net.tecogonaz.tcsecuritykeyemulator.ui.common.SettingItemSwitch
import net.tecogonaz.tcsecuritykeyemulator.ui.common.SettingsCategoryTitle
import net.tecogonaz.tcsecuritykeyemulator.ui.common.SettingsHelpText
import net.tecogonaz.tcsecuritykeyemulator.ui.common.ThemeSettingItem
import net.tecogonaz.tcsecuritykeyemulator.ui.common.mouseDragScroll

/** 設定画面 (TCSameuraDamMonitor の設定項目コンポーネントを再利用)。 */
@Composable
fun SettingsScreen(viewModel: MainViewModel, actions: UiActions) {
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val capabilities by viewModel.capabilities.collectAsStateWithLifecycle()
    val pinStatus by viewModel.pinStatus.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) { viewModel.refreshCapabilities() }

    val scrollState = rememberScrollState()
    val verifyTitle = stringResource(R.string.verify_title_change_setting)

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier
                .widthIn(max = 720.dp)
                .fillMaxWidth()
                .mouseDragScroll(scrollState, Orientation.Vertical)
                .verticalScroll(scrollState)
                .padding(16.dp)
        ) {
            SettingsCategoryTitle(stringResource(R.string.settings_category_display))
            // 言語 (TCSameuraDamMonitor と同じく OS のアプリ別言語設定を開く)
            val effectiveLocale = LocalConfiguration.current.locales[0]
            val context = LocalContext.current
            val isAppLocaleSystemDefault = remember(effectiveLocale) {
                runCatching {
                    context.getSystemService(LocaleManager::class.java)?.applicationLocales?.isEmpty ?: true
                }.getOrDefault(true)
            }
            val languageName = effectiveLocale.getDisplayName(effectiveLocale)
            SettingItemClickable(
                title = stringResource(R.string.settings_language),
                subtitle = if (isAppLocaleSystemDefault) {
                    stringResource(R.string.settings_language_system_default, languageName)
                } else {
                    languageName
                },
                onClick = actions.openAppLanguageSettings
            )
            ThemeSettingItem(currentTheme = settings.theme) { theme ->
                viewModel.updateSettings { it.copy(theme = theme) }
            }
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            SettingsCategoryTitle(stringResource(R.string.settings_category_verification))
            SettingItemDropdown(
                title = stringResource(R.string.settings_auth_window),
                selected = settings.authWindowSeconds,
                options = AppSettings.AUTH_WINDOW_CHOICES.map { it to pluralStringResource(R.plurals.settings_seconds, it, it) },
                onSelected = { sec -> viewModel.updateSettings { it.copy(authWindowSeconds = sec) } }
            )
            SettingsHelpText(stringResource(R.string.settings_auth_window_help))
            SettingItemSwitch(
                title = stringResource(R.string.settings_one_time),
                description = stringResource(R.string.settings_one_time_help),
                checked = settings.oneTimeAuthorization
            ) { checked ->
                if (checked) {
                    viewModel.updateSettings { it.copy(oneTimeAuthorization = true) }
                } else {
                    actions.verifyThen(verifyTitle) { viewModel.updateSettings { it.copy(oneTimeAuthorization = false) } }
                }
            }
            SettingItemSwitch(
                title = stringResource(R.string.settings_biometric_only),
                description = stringResource(R.string.settings_biometric_only_help),
                checked = settings.biometricOnly
            ) { checked ->
                if (checked) {
                    viewModel.updateSettings { it.copy(biometricOnly = true) }
                } else {
                    actions.verifyThen(verifyTitle) { viewModel.updateSettings { it.copy(biometricOnly = false) } }
                }
            }
            SettingItemSwitch(
                title = stringResource(R.string.settings_prompt_on_tap),
                description = stringResource(R.string.settings_prompt_on_tap_help),
                checked = settings.promptOnTap
            ) { checked -> viewModel.updateSettings { it.copy(promptOnTap = checked) } }
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            SettingsCategoryTitle(stringResource(R.string.settings_category_keys))
            SettingItemSwitch(
                title = stringResource(R.string.settings_strongbox),
                description = stringResource(
                    if (capabilities.hasStrongBox) R.string.settings_strongbox_help else R.string.settings_strongbox_unavailable
                ),
                checked = settings.preferStrongBox && capabilities.hasStrongBox,
                enabled = capabilities.hasStrongBox
            ) { checked -> viewModel.updateSettings { it.copy(preferStrongBox = checked) } }
            SettingItemDropdown(
                title = stringResource(R.string.settings_attestation),
                selected = settings.attestationMode,
                options = listOf(
                    AttestationMode.NONE to stringResource(R.string.attestation_none),
                    AttestationMode.SELF to stringResource(R.string.attestation_self)
                ),
                onSelected = { mode -> viewModel.updateSettings { it.copy(attestationMode = mode) } }
            )
            SettingsHelpText(stringResource(R.string.settings_attestation_help))
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            SettingsCategoryTitle(stringResource(R.string.settings_category_client))
            SettingItemSwitch(
                title = stringResource(R.string.settings_allow_reset),
                description = stringResource(R.string.settings_allow_reset_help),
                checked = settings.allowResetFromClient
            ) { checked ->
                if (checked) {
                    actions.verifyThen(verifyTitle) { viewModel.updateSettings { it.copy(allowResetFromClient = true) } }
                } else {
                    viewModel.updateSettings { it.copy(allowResetFromClient = false) }
                }
            }
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            SettingsCategoryTitle(stringResource(R.string.settings_category_pin))
            SettingItemReadOnly(
                title = stringResource(R.string.settings_pin_status),
                subtitle = when {
                    pinStatus.state == PinStatus.State.UNAVAILABLE -> stringResource(R.string.settings_pin_unavailable)
                    pinStatus.state == PinStatus.State.NOT_SET -> stringResource(R.string.settings_pin_not_set)
                    pinStatus.retries <= 0 -> stringResource(R.string.settings_pin_blocked)
                    else -> pluralStringResource(R.plurals.settings_pin_set, pinStatus.retries, pinStatus.retries)
                }
            )
            if (pinStatus.isSet) {
                val clearTitle = stringResource(R.string.verify_title_clear_pin)
                SettingItemClickable(
                    title = stringResource(R.string.settings_pin_clear),
                    subtitle = stringResource(R.string.settings_pin_clear_help),
                    onClick = { actions.verifyThen(clearTitle) { viewModel.clearPin() } }
                )
            }
            SettingsHelpText(stringResource(R.string.settings_pin_help))
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            SettingsCategoryTitle(stringResource(R.string.settings_category_bluetooth))
            SettingItemSwitch(
                title = stringResource(R.string.settings_bluetooth),
                description = stringResource(R.string.settings_bluetooth_help),
                checked = settings.bluetoothEnabled,
                enabled = capabilities.hasBluetooth
            ) { checked ->
                viewModel.updateSettings { it.copy(bluetoothEnabled = checked) }
                if (checked) actions.requestBluetoothPermission() else viewModel.stopBluetooth()
            }
        }
    }
}
