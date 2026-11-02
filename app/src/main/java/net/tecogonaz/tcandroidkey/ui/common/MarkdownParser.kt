// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.ui.common

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.AnnotatedString.Builder
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp

/*
 * TCSameuraDamMonitor の MarkdownParser.kt (MarkdownBody / parseInlineMarkdown) を流用し、
 * 本アプリの利用規約・セキュリティポリシーで使う次の記法を追加した。
 * - リンク `[text](target)` (相対パスのリンクは onOpenLink で文書間の移動に使う)
 * - 表 (`| a | b |`。区切り行は読み飛ばし、1 行目を見出しとして太字にする)
 * - 引用 (`> `)
 */

/** インラインのリンク (`[text](target)`) と URL。 */
private val LINK_REGEX = Regex("""\[([^\]]+)]\(([^)\s]+)\)|https?://[\w./?=&%#@!+\-~:]+""")
private val TABLE_SEPARATOR_REGEX = Regex("""^:?-{3,}:?$""")

/**
 * 簡易的な Markdown (見出し `#`〜`###`、リスト `-`、表、引用、区切り線、太字 `**`、インラインコード、リンク) を
 * Compose で描画する。主に利用規約・セキュリティポリシーの表示に使用する。
 *
 * @param text 描画する Markdown テキスト。
 * @param onOpenLink リンクを押したときに呼ばれる (URL・mailto・相対パスのいずれか)。
 */
@Composable
fun MarkdownBody(text: String, onOpenLink: (String) -> Unit) {
    val linkColor = MaterialTheme.colorScheme.primary
    val lines = text.replace("\r\n", "\n").split("\n")
    var i = 0
    while (i < lines.size) {
        val line = lines[i].trimEnd()
        when {
            line.startsWith("### ") -> Heading(line.removePrefix("### "), MaterialTheme.typography.titleSmall, 8, linkColor, onOpenLink)
            line.startsWith("## ") -> Heading(line.removePrefix("## "), MaterialTheme.typography.titleMedium, 12, linkColor, onOpenLink)
            line.startsWith("# ") -> Heading(line.removePrefix("# "), MaterialTheme.typography.titleLarge, 8, linkColor, onOpenLink)
            line.startsWith("- ") -> Row(modifier = Modifier.padding(start = 8.dp, top = 2.dp, bottom = 2.dp)) {
                Text("• ", style = MaterialTheme.typography.bodyMedium)
                Text(parseInlineMarkdown(line.removePrefix("- "), linkColor, onOpenLink), style = MaterialTheme.typography.bodyMedium)
            }
            line.startsWith("|") -> {
                val rows = mutableListOf<String>()
                while (i < lines.size && lines[i].trimStart().startsWith("|")) {
                    rows += lines[i].trim()
                    i++
                }
                MarkdownTable(rows, linkColor, onOpenLink)
                continue
            }
            line.startsWith("> ") || line == ">" -> Text(
                text = parseInlineMarkdown(line.removePrefix(">").trimStart(), linkColor, onOpenLink),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 12.dp, top = 2.dp, bottom = 2.dp)
            )
            line.startsWith("---") -> HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
            line.isEmpty() -> Spacer(Modifier.height(4.dp))
            else -> Text(
                text = parseInlineMarkdown(line, linkColor, onOpenLink),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 2.dp, bottom = 2.dp)
            )
        }
        i++
    }
}

@Composable
private fun Heading(
    text: String,
    style: androidx.compose.ui.text.TextStyle,
    topPadding: Int,
    linkColor: Color,
    onOpenLink: (String) -> Unit
) {
    Text(
        text = parseInlineMarkdown(text, linkColor, onOpenLink),
        style = style,
        fontWeight = FontWeight.Bold,
        modifier = Modifier
            .padding(top = topPadding.dp)
            .semantics { heading() }
    )
}

/** 表を、列幅を等分した行の並びとして描画する。 */
@Composable
private fun MarkdownTable(rows: List<String>, linkColor: Color, onOpenLink: (String) -> Unit) {
    val parsed = rows.map { row -> row.trim().removePrefix("|").removeSuffix("|").split("|").map { it.trim() } }
        .filterNot { cells -> cells.all { TABLE_SEPARATOR_REGEX.matches(it) } }
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        parsed.forEachIndexed { index, cells ->
            if (index > 0) HorizontalDivider()
            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                cells.forEach { cell ->
                    Text(
                        text = parseInlineMarkdown(cell, linkColor, onOpenLink),
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = if (index == 0) FontWeight.Bold else null,
                        modifier = Modifier.weight(1f).padding(end = 8.dp)
                    )
                }
            }
        }
    }
}

/**
 * 太字・インラインコード・リンク・URL を含む 1 行を [AnnotatedString] に変換する。
 *
 * @param onOpenLink null の場合、リンクは装飾のみ (押下不可)。
 */
fun parseInlineMarkdown(
    text: String,
    linkColor: Color = Color.Unspecified,
    onOpenLink: ((String) -> Unit)? = null
): AnnotatedString = buildAnnotatedString {
    var cursor = 0
    LINK_REGEX.findAll(text).forEach { match ->
        appendInlineMarkdown(text.substring(cursor, match.range.first))
        val label = match.groups[1]?.value ?: match.value
        val target = match.groups[2]?.value ?: match.value
        val style = SpanStyle(color = linkColor, textDecoration = TextDecoration.Underline)
        if (onOpenLink != null) {
            withLink(LinkAnnotation.Clickable(target) { onOpenLink(target) }) {
                withStyle(style) { appendInlineMarkdown(label) }
            }
        } else {
            withStyle(style) { appendInlineMarkdown(label) }
        }
        cursor = match.range.last + 1
    }
    appendInlineMarkdown(text.substring(cursor))
}

private fun Builder.appendInlineMarkdown(text: String) {
    var remaining = text
    while (remaining.isNotEmpty()) {
        val boldStart = remaining.indexOf("**")
        val codeStart = remaining.indexOf("`")
        val nextStart = listOf(boldStart, codeStart).filter { it >= 0 }.minOrNull()
        if (nextStart == null) {
            append(remaining)
            return
        }
        append(remaining.substring(0, nextStart))
        if (nextStart == boldStart) {
            val boldContent = remaining.substring(boldStart + 2)
            val boldEnd = boldContent.indexOf("**")
            if (boldEnd >= 0) {
                withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { append(boldContent.substring(0, boldEnd)) }
                remaining = boldContent.substring(boldEnd + 2)
            } else {
                append("**")
                remaining = boldContent
            }
        } else {
            val codeContent = remaining.substring(codeStart + 1)
            val codeEnd = codeContent.indexOf("`")
            if (codeEnd >= 0) {
                withStyle(SpanStyle(fontFamily = FontFamily.Monospace)) { append(codeContent.substring(0, codeEnd)) }
                remaining = codeContent.substring(codeEnd + 1)
            } else {
                append("`")
                remaining = codeContent
            }
        }
    }
}
