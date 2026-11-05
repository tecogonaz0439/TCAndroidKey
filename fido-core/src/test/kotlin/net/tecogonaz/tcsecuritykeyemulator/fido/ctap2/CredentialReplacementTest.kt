// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.FakePolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** discoverable credential の上書き登録 (レビュー指摘 F-10) と StoredCredential の等価性 (O-03)。 */
class CredentialReplacementTest {

    private val store = InMemoryCredentialStore()
    private val policy = FakePolicy()
    private var attestation = AttestationMode.NONE

    private fun mc(userId: Byte, a: Ctap2Authenticator): Int {
        val params = linkedMapOf<Long, Any?>(
            1L to TestCrypto.sha256(byteArrayOf(userId)),
            2L to linkedMapOf("id" to "example.com"),
            3L to linkedMapOf("id" to byteArrayOf(userId), "name" to "u"),
            4L to listOf(linkedMapOf("alg" to -7L, "type" to "public-key")),
            7L to linkedMapOf("rk" to true)
        )
        return a.process(byteArrayOf(CtapCommand.MAKE_CREDENTIAL.toByte()) + Cbor.encode(params))[0].toInt() and 0xFF
    }

    private fun authenticator(s: CredentialStore = store) =
        Ctap2Authenticator(s, policy, { AuthenticatorConfig(ByteArray(16), attestationMode = attestation) }, "test")

    @Test
    fun successfulOverwriteReplacesTheOldCredential() {
        val a = authenticator()
        assertEquals(CtapStatus.OK, mc(1, a))
        val old = store.list().single()
        assertEquals(CtapStatus.OK, mc(1, a))
        val now = store.list().single()
        assertFalse(now.isSameCredential(old))
        assertEquals(CtapStatus.OK, mc(2, a))
        assertEquals("other users are kept", 2, store.list().size)
    }

    @Test
    fun failedOverwriteKeepsTheOldCredential() {
        val a = authenticator()
        assertEquals(CtapStatus.OK, mc(1, a))
        val old = store.list().single()
        val failing = object : CredentialStore by store {
            override fun create(
                rpId: String, rpName: String?, user: UserEntity, discoverable: Boolean, options: CredentialOptions
            ): StoredCredential =
                throw CtapException(CtapStatus.ERR_OPERATION_DENIED, "key generation failed")
        }
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, mc(1, authenticator(failing)))
        assertArrayEquals(old.id, store.list().single().id)
    }

    @Test
    fun failedAttestationKeepsTheOldCredentialAndRemovesTheNewOne() {
        val a = authenticator()
        assertEquals(CtapStatus.OK, mc(1, a))
        val old = store.list().single()
        attestation = AttestationMode.SELF
        val failing = object : CredentialStore by store {
            override fun sign(credential: StoredCredential, data: ByteArray): ByteArray =
                throw KeyUseNotAuthorizedException("expired")
        }
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, mc(1, authenticator(failing)))
        assertArrayEquals(old.id, store.list().single().id)
    }

    @Test
    fun revokedOverwriteKeepsTheOldCredential() {
        val a = authenticator()
        assertEquals(CtapStatus.OK, mc(1, a))
        val old = store.list().single()
        var checks = 0
        policy.onValidityCheck = { if (++checks >= 2) policy.leaseValid = false }
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, mc(1, a))
        assertArrayEquals(old.id, store.list().single().id)
    }

    @Test
    fun equalityIncludesCounterAndLastUse() {
        val a = authenticator()
        mc(1, a)
        val c = store.list().single()
        val used = c.copy(signCount = 1, lastUsedAtMillis = 5)
        assertNotEquals(c, used)
        assertTrue(c.isSameCredential(used))
        assertEquals(c, c.copy())
        assertNotEquals("list updates must not be swallowed by StateFlow", listOf(c), listOf(used))
    }
}
