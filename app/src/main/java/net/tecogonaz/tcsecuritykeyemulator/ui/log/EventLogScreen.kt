// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.ui.log

import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Error
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.tecogonaz.tcsecuritykeyemulator.R
import net.tecogonaz.tcsecuritykeyemulator.data.LogEntry
import net.tecogonaz.tcsecuritykeyemulator.data.LogLevel
import net.tecogonaz.tcsecuritykeyemulator.ui.MainViewModel
import net.tecogonaz.tcsecuritykeyemulator.ui.common.SettingsHelpText
import net.tecogonaz.tcsecuritykeyemulator.ui.common.formatTime
import net.tecogonaz.tcsecuritykeyemulator.ui.common.mouseDragScroll

/** 認証器の動作ログ画面 (デバッグ・動作確認用)。 */
@Composable
fun EventLogScreen(viewModel: MainViewModel) {
    val entries by viewModel.events.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(modifier = Modifier.widthIn(max = 960.dp).fillMaxWidth().padding(horizontal = 16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    SettingsHelpText(stringResource(R.string.log_help))
                }
                OutlinedButton(onClick = viewModel::clearLog, enabled = entries.isNotEmpty()) {
                    Text(stringResource(R.string.action_clear))
                }
            }
            if (entries.isEmpty()) {
                Text(
                    text = stringResource(R.string.log_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 16.dp)
                )
            }
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize().mouseDragScroll(listState, Orientation.Vertical),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                items(entries, key = { it.id }) { entry ->
                    LogEntryRow(entry)
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
fun LogEntryRow(entry: LogEntry) {
    val (icon, tint) = when (entry.level) {
        LogLevel.INFO -> Icons.Outlined.Info to MaterialTheme.colorScheme.onSurfaceVariant
        LogLevel.SUCCESS -> Icons.Outlined.CheckCircle to MaterialTheme.colorScheme.primary
        LogLevel.WARNING -> Icons.Outlined.Warning to MaterialTheme.colorScheme.tertiary
        LogLevel.ERROR -> Icons.Outlined.Error to MaterialTheme.colorScheme.error
    }
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.Top) {
        Icon(icon, contentDescription = entry.level.name, tint = tint, modifier = Modifier.size(18.dp))
        Spacer(modifier = Modifier.size(8.dp))
        Column {
            Text(
                text = "${formatTime(entry.timestampMillis)}  [${entry.source}]",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = entry.message,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
        }
    }
}
