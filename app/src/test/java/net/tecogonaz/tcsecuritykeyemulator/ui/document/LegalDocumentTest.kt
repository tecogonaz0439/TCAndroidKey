// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.ui.document

import net.tecogonaz.tcsecuritykeyemulator.ui.document.LegalDocument.Link
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class LegalDocumentTest {

    @Test
    fun relativeLinksBetweenDocumentsStayInTheApp() {
        assertEquals(Link.Document(LegalDocument.TERMS), LegalDocument.resolve(LegalDocument.TERMS_JA, "TERMS.md"))
        assertEquals(Link.Document(LegalDocument.SECURITY_JA), LegalDocument.resolve(LegalDocument.TERMS_JA, "SECURITY-ja.md"))
        assertEquals(Link.Document(LegalDocument.SECURITY), LegalDocument.resolve(LegalDocument.TERMS, "../SECURITY.md"))
        assertEquals(Link.Document(LegalDocument.TERMS), LegalDocument.resolve(LegalDocument.SECURITY, "docs/TERMS.md"))
        assertEquals(Link.Document(LegalDocument.TERMS_JA), LegalDocument.resolve(LegalDocument.SECURITY_JA, "TERMS-ja.md"))
    }

    @Test
    fun otherRelativeLinksOpenTheRepository() {
        assertEquals(
            Link.External("https://github.com/tecogonaz0439/TCSecurityKeyEmulator/blob/HEAD/LICENSE"),
            LegalDocument.resolve(LegalDocument.TERMS_JA, "../LICENSE")
        )
    }

    @Test
    fun absoluteLinksAreOpenedAsIs() {
        assertEquals(Link.External("https://example.com/a"), LegalDocument.resolve(LegalDocument.TERMS, "https://example.com/a"))
        assertEquals(Link.External("mailto:a@example.com"), LegalDocument.resolve(LegalDocument.SECURITY, "mailto:a@example.com"))
    }

    /** 文書内の相対リンクが、すべてリポジトリ内の実在するファイルを指していること。 */
    @Test
    fun allRelativeLinksInTheDocumentsExist() {
        val root = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "settings.gradle.kts").exists() }
        val link = Regex("""\[[^\]]+]\(([^)\s]+)\)""")
        LegalDocument.entries.forEach { doc ->
            val text = File(root, doc.repoPath).readText()
            link.findAll(text).map { it.groupValues[1] }.forEach { target ->
                when (val resolved = LegalDocument.resolve(doc, target)) {
                    is Link.Document -> Unit
                    is Link.External -> if (resolved.url.contains("/blob/HEAD/")) {
                        val path = resolved.url.substringAfter("/blob/HEAD/")
                        assert(File(root, path).exists()) { "${doc.repoPath}: broken link $target" }
                    }
                }
            }
        }
    }
}
