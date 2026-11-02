// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.ui.credentials

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
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.DeleteForever
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.tecogonaz.tcandroidkey.R
import net.tecogonaz.tcandroidkey.fido.ctap2.KeySecurityLevel
import net.tecogonaz.tcandroidkey.fido.ctap2.StoredCredential
import net.tecogonaz.tcandroidkey.keystore.KeystoreCredentialStore
import net.tecogonaz.tcandroidkey.ui.MainViewModel
import net.tecogonaz.tcandroidkey.ui.UiActions
import net.tecogonaz.tcandroidkey.ui.common.SettingsHelpText
import net.tecogonaz.tcandroidkey.ui.common.formatDateTime
import net.tecogonaz.tcandroidkey.ui.common.mouseDragScroll

/** 登録済みクレデンシャルの一覧・個別削除・全削除画面。削除には本人確認が必要。 */
@Composable
fun CredentialsScreen(viewModel: MainViewModel, actions: UiActions) {
    val credentials by viewModel.credentials.collectAsStateWithLifecycle()
    val storage by viewModel.storageStatus.collectAsStateWithLifecycle()
    val unavailable = storage.availability == KeystoreCredentialStore.Availability.UNAVAILABLE
    var deleteTarget by remember { mutableStateOf<StoredCredential?>(null) }
    var confirmDeleteAll by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    val deleteTitle = stringResource(R.string.verify_title_delete)
    val deleteAllTitle = stringResource(R.string.verify_title_delete_all)

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        LazyColumn(
            state = listState,
            modifier = Modifier
                .widthIn(max = 720.dp)
                .fillMaxSize()
                .mouseDragScroll(listState, Orientation.Vertical)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Column(modifier = Modifier.padding(top = 16.dp)) {
                    SettingsHelpText(stringResource(R.string.credentials_help))
                    if (unavailable) {
                        StorageUnavailableCard(error = storage.error, onInitialize = { confirmDeleteAll = true })
                    }
                    if (credentials.isNotEmpty()) {
                        OutlinedButton(
                            onClick = { confirmDeleteAll = true },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
                        ) {
                            Icon(Icons.Outlined.DeleteForever, contentDescription = null)
                            Spacer(modifier = Modifier.size(ButtonDefaults.IconSpacing))
                            Text(stringResource(R.string.action_delete_all))
                        }
                    }
                }
            }
            if (credentials.isEmpty() && !unavailable) {
                item {
                    Text(
                        text = stringResource(R.string.credentials_empty),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 24.dp)
                    )
                }
            }
            items(credentials, key = { it.idHex }) { credential ->
                CredentialCard(credential = credential, onDelete = { deleteTarget = credential })
            }
            item { Spacer(modifier = Modifier.size(16.dp)) }
        }
    }

    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(stringResource(R.string.dialog_delete_title)) },
            text = {
                Text(
                    stringResource(
                        R.string.dialog_delete_message,
                        target.rpName ?: target.rpId,
                        target.user.name ?: target.user.displayName ?: "-"
                    )
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    deleteTarget = null
                    actions.verifyThen(deleteTitle) { viewModel.deleteCredential(target) }
                }) { Text(stringResource(R.string.action_delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) { Text(stringResource(R.string.action_cancel)) }
            }
        )
    }

    if (confirmDeleteAll) {
        AlertDialog(
            onDismissRequest = { confirmDeleteAll = false },
            icon = { Icon(Icons.Outlined.DeleteForever, contentDescription = null) },
            title = { Text(stringResource(R.string.dialog_delete_all_title)) },
            text = {
                Text(
                    if (unavailable) stringResource(R.string.dialog_initialize_storage_message)
                    else stringResource(R.string.dialog_delete_all_message, credentials.size)
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmDeleteAll = false
                    actions.verifyThen(deleteAllTitle) { viewModel.deleteAllCredentials() }
                }) { Text(stringResource(R.string.action_delete_all), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { confirmDeleteAll = false }) { Text(stringResource(R.string.action_cancel)) }
            }
        )
    }
}

/** メタデータを読み込めない場合の案内と初期化ボタン。 */
@Composable
private fun StorageUnavailableCard(error: String?, onInitialize: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.credentials_unavailable_title),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            Text(
                text = stringResource(R.string.credentials_unavailable_message),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            error?.let {
                Text(text = it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onErrorContainer)
            }
            OutlinedButton(
                onClick = onInitialize,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
            ) {
                Icon(Icons.Outlined.DeleteForever, contentDescription = null)
                Spacer(modifier = Modifier.size(ButtonDefaults.IconSpacing))
                Text(stringResource(R.string.action_initialize_storage))
            }
        }
    }
}

@Composable
private fun CredentialCard(credential: StoredCredential, onDelete: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.Top) {
            Icon(
                Icons.Outlined.VpnKey,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(top = 2.dp)
            )
            Spacer(modifier = Modifier.size(16.dp))
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = credential.rpName?.takeIf { it.isNotBlank() } ?: credential.rpId,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                if (credential.rpName != null && credential.rpName != credential.rpId) {
                    Text(credential.rpId, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                val userLine = listOfNotNull(credential.user.displayName, credential.user.name?.let { "($it)" })
                    .joinToString(" ")
                if (userLine.isNotEmpty()) {
                    Text(userLine, style = MaterialTheme.typography.bodyMedium)
                }
                Text(
                    text = stringResource(R.string.credential_created, formatDateTime(credential.createdAtMillis)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = credential.lastUsedAtMillis?.let {
                        stringResource(R.string.credential_last_used, formatDateTime(it), credential.signCount)
                    } ?: stringResource(R.string.credential_never_used),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    AssistChip(
                        onClick = {},
                        label = {
                            Text(stringResource(if (credential.discoverable) R.string.credential_discoverable else R.string.credential_non_discoverable))
                        }
                    )
                    AssistChip(
                        onClick = {},
                        label = {
                            Text(
                                stringResource(
                                    when (credential.securityLevel) {
                                        KeySecurityLevel.STRONGBOX -> R.string.security_level_strongbox
                                        KeySecurityLevel.TEE -> R.string.security_level_tee
                                        KeySecurityLevel.SOFTWARE -> R.string.security_level_software
                                        KeySecurityLevel.UNKNOWN -> R.string.security_level_unknown
                                    }
                                )
                            )
                        }
                    )
                }
            }
            IconButton(onClick = onDelete) {
                Icon(
                    Icons.Outlined.Delete,
                    contentDescription = stringResource(R.string.action_delete),
                    tint = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}
