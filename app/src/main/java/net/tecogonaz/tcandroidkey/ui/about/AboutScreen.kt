// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.ui.about

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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import net.tecogonaz.tcandroidkey.AppContainer
import net.tecogonaz.tcandroidkey.BuildConfig
import net.tecogonaz.tcandroidkey.R
import net.tecogonaz.tcandroidkey.ui.UiActions
import net.tecogonaz.tcandroidkey.ui.common.SettingItemClickable
import net.tecogonaz.tcandroidkey.ui.common.SettingItemReadOnly
import net.tecogonaz.tcandroidkey.ui.common.SettingsCategoryTitle
import net.tecogonaz.tcandroidkey.ui.common.SettingsHelpText
import net.tecogonaz.tcandroidkey.ui.document.LegalDocument
import net.tecogonaz.tcandroidkey.ui.common.mouseDragScroll

private const val REPOSITORY_URL = "https://github.com/tecogonaz0439/TCSecurityKeyEmulator"
private const val LICENSE_URL = "https://www.apache.org/licenses/LICENSE-2.0"

/** 「このアプリについて」画面。 */
@Composable
fun AboutScreen(actions: UiActions, onOpenDocument: (LegalDocument) -> Unit) {
    val scrollState = rememberScrollState()
    val japanese = LocalConfiguration.current.locales[0]?.language == "ja"
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier
                .widthIn(max = 720.dp)
                .fillMaxWidth()
                .mouseDragScroll(scrollState, Orientation.Vertical)
                .verticalScroll(scrollState)
                .padding(16.dp)
        ) {
            SettingsCategoryTitle(stringResource(R.string.app_name))
            SettingsHelpText(stringResource(R.string.about_description))
            SettingItemReadOnly(stringResource(R.string.about_version), BuildConfig.VERSION_NAME)
            SettingItemReadOnly(stringResource(R.string.about_aaguid), aaguidString())
            SettingItemReadOnly(stringResource(R.string.about_protocols), stringResource(R.string.about_protocols_value))
            SettingItemReadOnly(stringResource(R.string.about_algorithms), "ES256 (ECDSA P-256 / SHA-256)")
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
            // 利用規約・セキュリティポリシー (TCSameuraDamMonitor と同様、表示言語の版を開き、
            // 日本語以外の表示では正本である日本語版も選べるようにする)
            SettingsCategoryTitle(stringResource(R.string.about_legal))
            SettingItemClickable(
                stringResource(R.string.doc_terms_item),
                stringResource(R.string.doc_terms_item_help)
            ) { onOpenDocument(LegalDocument.terms(japanese)) }
            SettingItemClickable(
                stringResource(R.string.doc_security_item),
                stringResource(R.string.doc_security_item_help)
            ) { onOpenDocument(LegalDocument.security(japanese)) }
            if (!japanese) {
                SettingItemClickable(stringResource(R.string.doc_terms_ja)) { onOpenDocument(LegalDocument.TERMS_JA) }
                SettingItemClickable(stringResource(R.string.doc_security_ja)) { onOpenDocument(LegalDocument.SECURITY_JA) }
            }
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
            SettingsCategoryTitle(stringResource(R.string.about_security))
            SettingsHelpText(stringResource(R.string.about_security_text))
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
            SettingsCategoryTitle(stringResource(R.string.about_links))
            SettingItemClickable(stringResource(R.string.about_source), REPOSITORY_URL) { actions.openUrl(REPOSITORY_URL) }
            SettingItemClickable(stringResource(R.string.about_license), "Apache License 2.0") { actions.openUrl(LICENSE_URL) }
            SettingsHelpText(stringResource(R.string.about_oss))
        }
    }
}

private fun aaguidString(): String {
    val hex = net.tecogonaz.tcandroidkey.fido.ctap2.Hex.encode(AppContainer.AAGUID)
    return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}"
}
