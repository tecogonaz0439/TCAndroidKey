// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.ui.authenticator

import android.os.SystemClock
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Bluetooth
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material.icons.outlined.Usb
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.delay
import net.tecogonaz.tcsecuritykeyemulator.R
import net.tecogonaz.tcsecuritykeyemulator.bluetooth.BluetoothHidAuthenticator
import net.tecogonaz.tcsecuritykeyemulator.bluetooth.BluetoothHidAuthenticator.Status
import net.tecogonaz.tcsecuritykeyemulator.data.LogEntry
import net.tecogonaz.tcsecuritykeyemulator.ui.MainViewModel
import net.tecogonaz.tcsecuritykeyemulator.ui.UiActions
import net.tecogonaz.tcsecuritykeyemulator.ui.common.formatDateTime
import net.tecogonaz.tcsecuritykeyemulator.ui.common.mouseDragScroll
import net.tecogonaz.tcsecuritykeyemulator.ui.log.LogEntryRow

/** 認証器のメイン画面: 受付状態、トランスポート、鍵保管の状態を表示する。 */
@Composable
fun AuthenticatorScreen(
    viewModel: MainViewModel,
    actions: UiActions,
    onShowCredentials: () -> Unit,
    onShowLog: () -> Unit,
    onShowSettings: () -> Unit
) {
    val session by viewModel.session.collectAsStateWithLifecycle()
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val capabilities by viewModel.capabilities.collectAsStateWithLifecycle()
    val credentials by viewModel.credentials.collectAsStateWithLifecycle()
    val events by viewModel.events.collectAsStateWithLifecycle()
    val bluetooth by viewModel.bluetooth.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) { viewModel.refreshCapabilities() }

    val now by produceState(SystemClock.elapsedRealtime(), session.armedUntilElapsed) {
        while (true) {
            value = SystemClock.elapsedRealtime()
            delay(250)
        }
    }
    val armed = session.isArmed(now)
    val remainingMs = session.remainingMillis(now)

    val scrollState = rememberScrollState()
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier
                .widthIn(max = 720.dp)
                .fillMaxWidth()
                .mouseDragScroll(scrollState, Orientation.Vertical)
                .verticalScroll(scrollState)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            StatusCard(
                armed = armed,
                remainingMs = remainingMs,
                durationMs = session.armedDurationMillis,
                deviceSecure = capabilities.deviceSecure,
                oneTime = settings.oneTimeAuthorization,
                lastAuthAt = session.lastAuthenticationAtMillis,
                lastAuthRp = session.lastAuthenticationRpId,
                onArm = actions.armWithVerification,
                onDisarm = viewModel::disarm,
                onOpenSecuritySettings = actions.openSecuritySettings
            )

            SectionCard(title = stringResource(R.string.section_transports)) {
                val nfcStatus = when {
                    !capabilities.hasNfc || !capabilities.hasHce -> stringResource(R.string.transport_nfc_unsupported)
                    !capabilities.nfcEnabled -> stringResource(R.string.transport_nfc_disabled)
                    else -> stringResource(R.string.transport_nfc_ready)
                }
                TransportRow(
                    icon = Icons.Outlined.Nfc,
                    title = stringResource(R.string.transport_nfc),
                    status = nfcStatus,
                    ok = capabilities.hasHce && capabilities.nfcEnabled,
                    actionLabel = if (capabilities.hasNfc && !capabilities.nfcEnabled) stringResource(R.string.action_open_nfc_settings) else null,
                    onAction = actions.openNfcSettings
                )
                HorizontalDivider()
                BluetoothRow(
                    enabledInSettings = settings.bluetoothEnabled,
                    state = bluetooth,
                    onStart = {
                        if (bluetooth.status == BluetoothHidAuthenticator.Status.PERMISSION_REQUIRED) {
                            actions.requestBluetoothPermission()
                        } else {
                            viewModel.startBluetooth()
                        }
                    },
                    onStop = viewModel::stopBluetooth,
                    onMakeDiscoverable = actions.makeDiscoverable,
                    onShowSettings = onShowSettings
                )
                HorizontalDivider()
                TransportRow(
                    icon = Icons.Outlined.Usb,
                    title = stringResource(R.string.transport_usb),
                    status = stringResource(R.string.transport_usb_unsupported),
                    ok = false,
                    actionLabel = null,
                    onAction = {}
                )
            }

            SectionCard(title = stringResource(R.string.section_key_storage)) {
                TransportRow(
                    icon = Icons.Outlined.Memory,
                    title = stringResource(if (capabilities.hasStrongBox) R.string.keystore_strongbox else R.string.keystore_tee),
                    status = pluralStringResource(R.plurals.keystore_credential_count, credentials.size, credentials.size),
                    ok = true,
                    actionLabel = stringResource(R.string.action_manage_credentials),
                    onAction = onShowCredentials
                )
            }

            SectionCard(title = stringResource(R.string.section_recent_events)) {
                val recent: List<LogEntry> = events.take(5)
                if (recent.isEmpty()) {
                    Text(
                        text = stringResource(R.string.log_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    recent.forEach { LogEntryRow(it) }
                }
                TextButton(onClick = onShowLog, modifier = Modifier.align(Alignment.End)) {
                    Text(stringResource(R.string.action_show_all))
                }
            }
        }
    }
}

@Composable
private fun StatusCard(
    armed: Boolean,
    remainingMs: Long,
    durationMs: Long,
    deviceSecure: Boolean,
    oneTime: Boolean,
    lastAuthAt: Long?,
    lastAuthRp: String?,
    onArm: () -> Unit,
    onDisarm: () -> Unit,
    onOpenSecuritySettings: () -> Unit
) {
    val containerColor = if (armed) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerHigh
    val contentColor = if (armed) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = containerColor, contentColor = contentColor)
    ) {
        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = if (armed) Icons.Outlined.LockOpen else Icons.Outlined.Lock,
                    contentDescription = null,
                    modifier = Modifier.size(40.dp)
                )
                Spacer(modifier = Modifier.size(16.dp))
                Column {
                    // live region は受付開始・終了の状態変化だけを読み上げる (毎秒変わる残り時間は含めない)。
                    Text(
                        text = stringResource(if (armed) R.string.status_armed_title else R.string.status_idle_title),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.semantics {
                            heading()
                            liveRegion = LiveRegionMode.Polite
                        }
                    )
                    if (armed) {
                        Text(
                            text = stringResource(R.string.status_armed_remaining, ((remainingMs + 999) / 1000).toInt()),
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }
            if (armed && durationMs > 0) {
                LinearProgressIndicator(
                    progress = { (remainingMs.toFloat() / durationMs).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth()
                )
            }
            Text(
                text = stringResource(
                    when {
                        !deviceSecure -> R.string.status_no_lock_screen
                        armed && oneTime -> R.string.status_armed_hint_one_time
                        armed -> R.string.status_armed_hint
                        else -> R.string.status_idle_hint
                    }
                ),
                style = MaterialTheme.typography.bodyMedium
            )
            if (!deviceSecure) {
                Button(onClick = onOpenSecuritySettings) {
                    Icon(Icons.Outlined.Warning, contentDescription = null)
                    Spacer(modifier = Modifier.size(ButtonDefaults.IconSpacing))
                    Text(stringResource(R.string.action_open_security_settings))
                }
            } else if (armed) {
                OutlinedButton(onClick = onDisarm) {
                    Text(stringResource(R.string.action_stop))
                }
            } else {
                Button(onClick = onArm, modifier = Modifier.fillMaxWidth().height(56.dp)) {
                    Icon(Icons.Outlined.Fingerprint, contentDescription = null)
                    Spacer(modifier = Modifier.size(ButtonDefaults.IconSpacing))
                    Text(stringResource(R.string.action_verify_and_start), style = MaterialTheme.typography.titleMedium)
                }
            }
            if (lastAuthAt != null) {
                Text(
                    text = stringResource(R.string.status_last_auth, formatDateTime(lastAuthAt), lastAuthRp ?: "-"),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.semantics { heading() }
            )
            content()
        }
    }
}

@Composable
private fun TransportRow(
    icon: ImageVector,
    title: String,
    status: String,
    ok: Boolean,
    actionLabel: String?,
    onAction: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = if (ok) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.size(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            Text(
                text = status,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (actionLabel != null) {
            TextButton(onClick = onAction) { Text(actionLabel) }
        }
    }
}

@Composable
private fun BluetoothRow(
    enabledInSettings: Boolean,
    state: BluetoothHidAuthenticator.State,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onMakeDiscoverable: () -> Unit,
    onShowSettings: () -> Unit
) {
    val status = when {
        state.status == Status.UNSUPPORTED -> stringResource(R.string.bt_status_unsupported)
        !enabledInSettings -> stringResource(R.string.bt_status_disabled_in_settings)
        else -> when (state.status) {
            Status.PERMISSION_REQUIRED -> stringResource(R.string.bt_status_permission)
            Status.BLUETOOTH_OFF -> stringResource(R.string.bt_status_off)
            Status.STOPPED -> stringResource(R.string.bt_status_stopped)
            Status.STARTING -> stringResource(R.string.bt_status_starting)
            Status.WAITING_FOR_HOST -> stringResource(R.string.bt_status_waiting)
            Status.CONNECTED -> stringResource(R.string.bt_status_connected, state.hostName ?: "?")
            Status.ERROR -> stringResource(R.string.bt_status_error, state.message ?: "")
            Status.UNSUPPORTED -> stringResource(R.string.bt_status_unsupported)
        }
    }
    val running = state.status == Status.WAITING_FOR_HOST || state.status == Status.CONNECTED || state.status == Status.STARTING
    Column {
        TransportRow(
            icon = Icons.Outlined.Bluetooth,
            title = stringResource(R.string.transport_bluetooth),
            status = status,
            ok = state.status == Status.CONNECTED,
            actionLabel = when {
                state.status == Status.UNSUPPORTED -> null
                !enabledInSettings -> stringResource(R.string.action_settings)
                running -> stringResource(R.string.action_stop)
                else -> stringResource(R.string.action_start)
            },
            onAction = when {
                !enabledInSettings -> onShowSettings
                running -> onStop
                else -> onStart
            }
        )
        if (enabledInSettings && state.status == Status.WAITING_FOR_HOST) {
            TextButton(onClick = onMakeDiscoverable, modifier = Modifier.padding(start = 32.dp)) {
                Text(stringResource(R.string.action_make_discoverable))
            }
        }
    }
}
