// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.ui.common

import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow

/**
 * テキストがコンテナの幅を超えた場合に、自動的にフォントサイズを縮小して1行に収めるための再利用可能なComposable関数です。
 *
 * 等倍 (スタイルのフォントサイズ。sp なのでシステムの文字サイズ設定は既に反映済み) から開始し、
 * はみ出し（Visual Overflow）が発生した場合は、指定された最小縮小率 [minScale] まで段階的に縮小します。
 * 表示幅が変わった場合は等倍から計算し直します (広げても縮小したままにならないようにする)。
 *
 * @param text 表示するテキスト文字列。
 * @param style テキストの基本スタイル。
 * @param modifier このコンポーネントのレイアウトや挙動をカスタマイズするための [Modifier]。
 * @param color テキストの描画色。デフォルトは現在のコンテンツ色。
 * @param minScale テキストが縮小される際の最小スケール比率。デフォルトは `0.72f`。
 */
@Composable
internal fun AutoResizingSingleLineText(
    text: String,
    style: TextStyle,
    modifier: Modifier = Modifier,
    color: Color = LocalContentColor.current,
    minScale: Float = 0.72f
) {
    BoxWithConstraints(modifier = modifier) {
        // 独自の縮小率は 1f を基準とし、システムの fontScale を重ねて掛けない (sp で二重に拡大されるため)。
        var scale by remember(text, style, maxWidth) { mutableFloatStateOf(1f) }
        Text(
            text = text,
            style = style.copy(fontSize = style.fontSize * scale),
            color = color,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            softWrap = false,
            onTextLayout = { result ->
                if (result.hasVisualOverflow && scale > minScale) {
                    scale = (scale * 0.92f).coerceAtLeast(minScale)
                }
            }
        )
    }
}
