// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.ui.document

import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import net.tecogonaz.tcandroidkey.ui.UiActions
import net.tecogonaz.tcandroidkey.ui.common.MarkdownBody
import net.tecogonaz.tcandroidkey.ui.common.mouseDragScroll

/** 利用規約・セキュリティポリシーの表示画面。文書内のリンクは、アプリ内の文書なら画面遷移、それ以外は外部で開く。 */
@Composable
fun DocumentScreen(document: LegalDocument, actions: UiActions, onOpenDocument: (LegalDocument) -> Unit) {
    val context = LocalContext.current
    val text = remember(document) {
        runCatching { context.assets.open(document.assetPath).bufferedReader(Charsets.UTF_8).use { it.readText() } }
            .getOrElse { "${document.repoPath}: ${it.message}" }
    }
    val scrollState = rememberScrollState()
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier
                .widthIn(max = 720.dp)
                .fillMaxWidth()
                .mouseDragScroll(scrollState, Orientation.Vertical)
                .verticalScroll(scrollState)
                .padding(16.dp)
        ) {
            MarkdownBody(text = text) { target ->
                when (val link = LegalDocument.resolve(document, target)) {
                    is LegalDocument.Link.Document -> onOpenDocument(link.document)
                    is LegalDocument.Link.External -> actions.openUrl(link.url)
                }
            }
        }
    }
}
