// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.ui.credentials

import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material.icons.outlined.Clear
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.DeleteForever
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.tecogonaz.tcsecuritykeyemulator.R
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.KeySecurityLevel
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.StoredCredential
import net.tecogonaz.tcsecuritykeyemulator.keystore.KeystoreCredentialStore
import net.tecogonaz.tcsecuritykeyemulator.ui.MainViewModel
import net.tecogonaz.tcsecuritykeyemulator.ui.UiActions
import net.tecogonaz.tcsecuritykeyemulator.ui.common.SettingsHelpText
import net.tecogonaz.tcsecuritykeyemulator.ui.common.formatDateTime
import net.tecogonaz.tcsecuritykeyemulator.ui.common.mouseDragScroll

/** 登録済みクレデンシャルの一覧・タイトルの編集・個別削除・全削除画面。削除には本人確認が必要 (タイトルの編集は不要)。 */
@Composable
fun CredentialsScreen(viewModel: MainViewModel, actions: UiActions) {
    val credentials by viewModel.credentials.collectAsStateWithLifecycle()
    val storage by viewModel.storageStatus.collectAsStateWithLifecycle()
    val unavailable = storage.availability == KeystoreCredentialStore.Availability.UNAVAILABLE
    var deleteTarget by remember { mutableStateOf<StoredCredential?>(null) }
    var editTarget by remember { mutableStateOf<StoredCredential?>(null) }
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
                CredentialCard(
                    credential = credential,
                    editable = !unavailable,
                    onEdit = { editTarget = credential },
                    onDelete = { deleteTarget = credential }
                )
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
                        target.title,
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

    editTarget?.let { target ->
        EditTitleDialog(
            credential = target,
            onDismiss = { editTarget = null },
            onSave = { label ->
                editTarget = null
                viewModel.updateCredentialLabel(target, label)
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
                    else pluralStringResource(R.plurals.dialog_delete_all_message, credentials.size, credentials.size)
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

/**
 * タイトルの編集 (FR-27)。空欄で保存すると既定のタイトル (rp.name、なければ RP ID) に戻る。
 * 入力は [StoredCredential.MAX_LABEL_LENGTH] コードポイントまで。保存時の正規化はストアが行う。
 * 未入力の欄には既定のタイトルを薄い色 ([PLACEHOLDER_ALPHA]) で表示する (入力済みの値と見分けるため)。
 */
@Composable
private fun EditTitleDialog(credential: StoredCredential, onDismiss: () -> Unit, onSave: (String?) -> Unit) {
    val initial = credential.label.orEmpty()
    var text by remember(credential.idHex) { mutableStateOf(TextFieldValue(initial, TextRange(initial.length))) }
    val focusRequester = remember { FocusRequester() }
    LaunchedEffect(Unit) { focusRequester.requestFocus() }
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Outlined.Edit, contentDescription = null) },
        title = { Text(stringResource(R.string.dialog_edit_title_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = text,
                    onValueChange = { value ->
                        if (value.text.codePointCount(0, value.text.length) <= StoredCredential.MAX_LABEL_LENGTH) text = value
                    },
                    label = { Text(stringResource(R.string.dialog_edit_title_label)) },
                    placeholder = {
                        // 入力済みの値と見分けられるよう、既定のプレースホルダーの色より薄くする
                        Text(
                            credential.defaultTitle,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = PLACEHOLDER_ALPHA),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    },
                    singleLine = true,
                    trailingIcon = if (text.text.isNotEmpty()) {
                        {
                            IconButton(onClick = { text = TextFieldValue("") }) {
                                Icon(Icons.Outlined.Clear, contentDescription = stringResource(R.string.action_clear_text))
                            }
                        }
                    } else {
                        null
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(focusRequester)
                )
                Text(
                    text = stringResource(R.string.dialog_edit_title_help, credential.defaultTitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onSave(StoredCredential.normalizeLabel(text.text)) }) {
                Text(stringResource(R.string.action_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        }
    )
}

/** タイトルの入力欄のプレースホルダーの不透明度 (Material の無効状態の 0.38 と同程度)。 */
private const val PLACEHOLDER_ALPHA = 0.38f

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

/**
 * クレデンシャルのカード (DD-08 §3 SC-02)。1 行目はタイトル (編集可能)、2 行目以降は登録時の情報
 * (rp.name・RP ID・ユーザー・作成日時・最終使用) と属性のチップ。
 */
@Composable
private fun CredentialCard(credential: StoredCredential, editable: Boolean, onEdit: () -> Unit, onDelete: () -> Unit) {
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
                    text = credential.title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = credential.defaultTitle,
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                if (credential.defaultTitle != credential.rpId) {
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
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    AssistChip(
                        onClick = {},
                        label = {
                            Text(stringResource(if (credential.discoverable) R.string.credential_discoverable else R.string.credential_non_discoverable))
                        }
                    )
                    if (credential.hmacSecret) {
                        AssistChip(onClick = {}, label = { Text(stringResource(R.string.credential_hmac_secret)) })
                    }
                    if (credential.credProtect > 1) {
                        AssistChip(
                            onClick = {},
                            label = {
                                Text(
                                    stringResource(
                                        if (credential.credProtect >= 3) R.string.credential_cred_protect_required
                                        else R.string.credential_cred_protect_list
                                    )
                                )
                            }
                        )
                    }
                    val weakKey = credential.securityLevel == KeySecurityLevel.SOFTWARE ||
                        credential.securityLevel == KeySecurityLevel.UNKNOWN
                    AssistChip(
                        onClick = {},
                        leadingIcon = if (weakKey) {
                            { Icon(Icons.Outlined.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error) }
                        } else {
                            null
                        },
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
                if (credential.securityLevel == KeySecurityLevel.SOFTWARE || credential.securityLevel == KeySecurityLevel.UNKNOWN) {
                    Text(
                        text = stringResource(R.string.credential_weak_key_warning),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
            Column {
                IconButton(onClick = onEdit, enabled = editable) {
                    Icon(Icons.Outlined.Edit, contentDescription = stringResource(R.string.action_edit_credential_title))
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
}
