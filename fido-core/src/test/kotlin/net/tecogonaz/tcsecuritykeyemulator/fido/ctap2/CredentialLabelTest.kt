// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.FakePolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** クレデンシャルのタイトル (FR-27、DD-01 §3.2 手順 13)。 */
class CredentialLabelTest {

    private val store = InMemoryCredentialStore()
    private val authenticator =
        Ctap2Authenticator(store, FakePolicy(), { AuthenticatorConfig(ByteArray(16)) }, "test")

    private fun mc(userId: Byte, rk: Boolean = true, rpName: String? = "Example"): Int {
        val rp = linkedMapOf<String, Any>("id" to "example.com")
        if (rpName != null) rp["name"] = rpName
        val params = linkedMapOf<Long, Any?>(
            1L to TestCrypto.sha256(byteArrayOf(userId)),
            2L to rp,
            3L to linkedMapOf("id" to byteArrayOf(userId), "name" to "u$userId"),
            4L to listOf(linkedMapOf("alg" to -7L, "type" to "public-key")),
            7L to linkedMapOf("rk" to rk)
        )
        return authenticator.process(byteArrayOf(CtapCommand.MAKE_CREDENTIAL.toByte()) + Cbor.encode(params))[0]
            .toInt() and 0xFF
    }

    private fun only(userId: Byte): StoredCredential = store.list().single { it.user.id.contentEquals(byteArrayOf(userId)) }

    @Test
    fun defaultTitleIsRpNameOrRpId() {
        assertEquals(CtapStatus.OK, mc(1))
        val c = only(1)
        assertEquals("Example", c.defaultTitle)
        assertEquals("Example", c.title)
        assertEquals("example.com", c.copy(rpName = null).title)
        assertEquals("example.com", c.copy(rpName = "  ").title)
        assertEquals("work", c.copy(label = "work").title)
        assertEquals("Example", c.copy(label = " ").title)
    }

    @Test
    fun normalizeLabelTrimsAndLimitsTheLength() {
        assertNull(StoredCredential.normalizeLabel(null))
        assertNull(StoredCredential.normalizeLabel(""))
        assertNull(StoredCredential.normalizeLabel(" \n\t "))
        assertEquals("Work account", StoredCredential.normalizeLabel("  Work account \n"))
        assertEquals("a b", StoredCredential.normalizeLabel("a\nb"))
        val long = "あ".repeat(100)
        assertEquals(StoredCredential.MAX_LABEL_LENGTH, StoredCredential.normalizeLabel(long)!!.length)
        // サロゲートペアの途中で切らない
        val emoji = "🔑".repeat(70)
        val cut = StoredCredential.normalizeLabel(emoji)!!
        assertEquals(StoredCredential.MAX_LABEL_LENGTH, cut.codePointCount(0, cut.length))
        assertFalse(Character.isHighSurrogate(cut.last()))
    }

    @Test
    fun updateLabelChangesOnlyTheTitle() {
        assertEquals(CtapStatus.OK, mc(1))
        val before = only(1)
        assertTrue(store.updateLabel(before.id, "  Admin  "))
        val after = only(1)
        assertEquals("Admin", after.label)
        assertEquals("Admin", after.title)
        assertNotEquals("the UI must see the change", before, after)
        assertEquals(before.copy(label = "Admin"), after)
        assertTrue(store.updateLabel(before.id, ""))
        assertNull(only(1).label)
        assertFalse(store.updateLabel(ByteArray(32), "x"))
    }

    @Test
    fun overwriteInheritsTheTitle() {
        assertEquals(CtapStatus.OK, mc(1))
        assertEquals(CtapStatus.OK, mc(2))
        store.updateLabel(only(1).id, "Admin")
        val old = only(1)
        assertEquals(CtapStatus.OK, mc(1, rpName = "Renamed"))
        val now = only(1)
        assertFalse(now.isSameCredential(old))
        assertEquals("Admin", now.label)
        assertEquals("Renamed", now.defaultTitle)
        assertNull("other users keep their own title", only(2).label)
    }

    @Test
    fun nonDiscoverableAndUnlabeledRegistrationsDoNotInherit() {
        assertEquals(CtapStatus.OK, mc(1))
        assertEquals(CtapStatus.OK, mc(1))
        assertNull(only(1).label)
        store.updateLabel(only(1).id, "Admin")
        assertEquals(CtapStatus.OK, mc(1, rk = false))
        val nonDiscoverable = store.list().single { !it.discoverable }
        assertNull(nonDiscoverable.label)
        assertEquals("Admin", store.list().single { it.discoverable }.label)
    }

    @Test
    fun updateUserKeepsTheTitle() {
        assertEquals(CtapStatus.OK, mc(1))
        store.updateLabel(only(1).id, "Admin")
        store.updateUser(only(1).id, UserEntity(byteArrayOf(1), "new", "New"))
        assertEquals("Admin", only(1).label)
        assertEquals("new", only(1).user.name)
    }
}
