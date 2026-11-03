// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.ui.document

import net.tecogonaz.tcsecuritykeyemulator.R

/**
 * アプリ内で表示する文書。本文はリポジトリの Markdown をビルド時に `assets/legal/` へコピーしたもの
 * (app/build.gradle.kts の copyLegalDocuments)。
 *
 * @property repoPath リポジトリのルートからのパス (文書内の相対リンクの解決に使う)。
 */
enum class LegalDocument(val id: String, val repoPath: String, val titleRes: Int) {
    TERMS("terms", "docs/TERMS.md", R.string.doc_terms),
    TERMS_JA("terms-ja", "docs/TERMS-ja.md", R.string.doc_terms_ja),
    SECURITY("security", "SECURITY.md", R.string.doc_security),
    SECURITY_JA("security-ja", "docs/SECURITY-ja.md", R.string.doc_security_ja);

    val assetPath: String get() = "legal/" + repoPath.substringAfterLast('/')

    companion object {
        const val REPOSITORY_URL = "https://github.com/tecogonaz0439/TCSecurityKeyEmulator"

        fun fromId(id: String?): LegalDocument? = entries.firstOrNull { it.id == id }

        /** 表示言語に合わせた利用規約 / セキュリティポリシー。日本語以外は英語版。 */
        fun terms(japanese: Boolean): LegalDocument = if (japanese) TERMS_JA else TERMS
        fun security(japanese: Boolean): LegalDocument = if (japanese) SECURITY_JA else SECURITY

        /**
         * [from] の中のリンク [target] を解決する。
         * @return アプリ内の文書なら [Link.Document]、それ以外は開く URL ([Link.External])。
         */
        fun resolve(from: LegalDocument, target: String): Link {
            if (target.startsWith("http://") || target.startsWith("https://") || target.startsWith("mailto:")) {
                return Link.External(target)
            }
            val path = normalize(from.repoPath.substringBeforeLast('/', "") , target.substringBefore('#'))
            entries.firstOrNull { it.repoPath == path }?.let { return Link.Document(it) }
            return Link.External("$REPOSITORY_URL/blob/HEAD/$path")
        }

        private fun normalize(baseDir: String, relative: String): String {
            val parts = ArrayDeque(if (baseDir.isEmpty()) emptyList() else baseDir.split('/'))
            relative.split('/').forEach { part ->
                when (part) {
                    "", "." -> Unit
                    ".." -> if (parts.isNotEmpty()) parts.removeLast()
                    else -> parts.addLast(part)
                }
            }
            return parts.joinToString("/")
        }
    }

    sealed interface Link {
        data class Document(val document: LegalDocument) : Link
        data class External(val url: String) : Link
    }
}
