// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.ui.common

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.DialogProperties
import net.tecogonaz.tcsecuritykeyemulator.R

/**
 * 初回起動時の注意書きダイアログ (テスト専用・物理セキュリティキーの代替として使用しないこと)。
 * 「理解しました」を押すまで閉じない。詳細は利用規約 (このアプリについて) に記載する。
 */
@Composable
fun TestUseNoticeDialog(onAcknowledge: () -> Unit) {
    AlertDialog(
        onDismissRequest = {},
        properties = DialogProperties(dismissOnBackPress = false, dismissOnClickOutside = false),
        icon = { Icon(Icons.Outlined.Warning, contentDescription = null) },
        title = { Text(stringResource(R.string.notice_title)) },
        text = { Text(stringResource(R.string.notice_body)) },
        confirmButton = {
            TextButton(onClick = onAcknowledge) { Text(stringResource(R.string.notice_acknowledge)) }
        }
    )
}
