// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.fido.ctap2

import net.tecogonaz.tcandroidkey.fido.cbor.Cbor
import net.tecogonaz.tcandroidkey.fido.session.AuthorizationGate
import net.tecogonaz.tcandroidkey.fido.testutil.CancellableKeepAlive
import net.tecogonaz.tcandroidkey.fido.testutil.FakePolicy
import net.tecogonaz.tcandroidkey.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcandroidkey.fido.testutil.TestCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** 認可 (Lease)・取消・チャネルと CTAP 処理の結合を確認する (レビュー指摘 S-01〜S-05, F-12)。 */
class Ctap2AuthorizationTest {

    private val aaguid = ByteArray(16)
    private val config = AuthenticatorConfig(aaguid)
    private val clientDataHash = TestCrypto.sha256("cd".toByteArray())

    private fun req(cmd: Int, params: Map<Long, Any?>? = null): ByteArray =
        if (params == null) byteArrayOf(cmd.toByte()) else byteArrayOf(cmd.toByte()) + Cbor.encode(params)

    private fun mc(rk: Boolean, userId: ByteArray = byteArrayOf(1), extra: Map<Long, Any?> = emptyMap()) = req(
        CtapCommand.MAKE_CREDENTIAL,
        linkedMapOf<Long, Any?>(
            1L to clientDataHash,
            2L to linkedMapOf("id" to "example.com"),
            3L to linkedMapOf("id" to userId, "name" to "alice"),
            4L to listOf(linkedMapOf("alg" to -7L, "type" to "public-key")),
            7L to linkedMapOf("rk" to rk)
        ).apply { putAll(extra) }
    )

    private fun ga(rpId: String = "example.com", allow: List<ByteArray> = emptyList(), up: Boolean = true) = req(
        CtapCommand.GET_ASSERTION,
        linkedMapOf<Long, Any?>(1L to rpId, 2L to clientDataHash).apply {
            if (allow.isNotEmpty()) this[3L] = allow.map { linkedMapOf("id" to it, "type" to "public-key") }
            if (!up) this[5L] = linkedMapOf("up" to false)
        }
    )

    private val gna = byteArrayOf(CtapCommand.GET_NEXT_ASSERTION.toByte())

    private fun status(resp: ByteArray) = resp[0].toInt() and 0xFF

    private fun credentialId(resp: ByteArray): ByteArray {
        val m = Cbor.decode(resp, 1, resp.size - 1) as Map<*, *>
        val authData = m[2L] as ByteArray
        val len = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
        return authData.copyOfRange(55, 55 + len)
    }

    // ------------------------------------------------------------------ FakePolicy

    private val store = InMemoryCredentialStore()
    private val policy = FakePolicy()
    private val auth = Ctap2Authenticator(store, policy, { config }, "test")

    @Test
    fun noCredentialsIsReportedOnlyAfterAuthorization() {
        val denying = Ctap2Authenticator(store, FakePolicy.denied(), { config }, "test")
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, status(denying.process(ga(rpId = "nobody.example"))))
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, status(denying.process(ga(rpId = "nobody.example", up = false))))
        assertEquals(CtapStatus.ERR_NO_CREDENTIALS, status(auth.process(ga(rpId = "nobody.example"))))
        assertEquals(listOf(false), policy.completed.map { it.second })
    }

    @Test
    fun everyGrantIsCompletedExactlyOnce() {
        val id = credentialId(auth.process(mc(rk = false)))
        assertEquals(CtapStatus.OK, status(auth.process(ga(allow = listOf(id)))))
        assertEquals(CtapStatus.OK, status(auth.process(ga(allow = listOf(id), up = false))))
        assertEquals(
            CtapStatus.ERR_CREDENTIAL_EXCLUDED,
            status(auth.process(mc(rk = false, extra = mapOf(5L to listOf(linkedMapOf("id" to id, "type" to "public-key"))))))
        )
        assertEquals(CtapStatus.ERR_PIN_NOT_SET, status(auth.process(mc(rk = false, extra = mapOf(8L to ByteArray(0), 9L to 1L)))))
        assertEquals(CtapStatus.OK, status(auth.process(req(CtapCommand.SELECTION))))
        assertEquals(policy.requests.size, policy.completed.size)
        assertEquals(listOf(true, true, false, false, false, false), policy.completed.map { it.second })
    }

    @Test
    fun revokedAuthorizationBeforeKeyGenerationCreatesNothing() {
        policy.leaseValid = false
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, status(auth.process(mc(rk = true))))
        assertTrue(store.list().isEmpty())
        assertEquals(listOf(false), policy.completed.map { it.second })
    }

    @Test
    fun revocationAfterKeyGenerationDeletesTheNewCredential() {
        var checks = 0
        policy.onValidityCheck = { if (++checks >= 2) policy.leaseValid = false }
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, status(auth.process(mc(rk = true))))
        assertTrue("credential that was never returned must not remain", store.list().isEmpty())
    }

    @Test
    fun revocationAfterSigningSuppressesTheAssertion() {
        val id = credentialId(auth.process(mc(rk = false)))
        var checks = 0
        policy.onValidityCheck = { if (++checks >= 2) policy.leaseValid = false }
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, status(auth.process(ga(allow = listOf(id)))))
    }

    @Test
    fun cancelledRequestDoesNotUseKeys() {
        val ka = CancellableKeepAlive().apply { cancelled = true }
        assertEquals(CtapStatus.ERR_KEEPALIVE_CANCEL, status(auth.process(mc(rk = true), ka)))
        assertTrue(store.list().isEmpty())
    }

    private fun twoDiscoverable(a: Ctap2Authenticator = auth) {
        assertEquals(CtapStatus.OK, status(a.process(mc(rk = true, userId = byteArrayOf(1)))))
        assertEquals(CtapStatus.OK, status(a.process(mc(rk = true, userId = byteArrayOf(2)))))
    }

    @Test
    fun getNextAssertionRequiresAValidLease() {
        twoDiscoverable()
        assertEquals(CtapStatus.OK, status(auth.process(ga())))
        policy.leaseValid = false
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, status(auth.process(gna)))
    }

    @Test
    fun getNextAssertionIsBoundToTheChannel() {
        twoDiscoverable()
        assertEquals(CtapStatus.OK, status(auth.process(ga(), channel = 0x1111)))
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, status(auth.process(gna, channel = 0x2222)))
        // 不一致で状態は破棄される
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, status(auth.process(gna, channel = 0x1111)))
    }

    @Test
    fun getNextAssertionIsInvalidAfterTheOriginalRequestWasCancelled() {
        twoDiscoverable()
        val origin = CancellableKeepAlive()
        assertEquals(CtapStatus.OK, status(auth.process(ga(), origin)))
        origin.cancelled = true // トランスポートの切断・再同期
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, status(auth.process(gna)))
    }

    @Test
    fun checkedExceptionsFromTheStoreBecomeErrOther() {
        val failing = object : CredentialStore by store {
            override fun create(rpId: String, rpName: String?, user: UserEntity, discoverable: Boolean): StoredCredential =
                throw IOException("disk full")
        }
        val a = Ctap2Authenticator(failing, policy, { config }, "test")
        assertEquals(CtapStatus.ERR_OTHER, status(a.process(mc(rk = false))))
        assertEquals(listOf(false), policy.completed.map { it.second })
    }

    // ------------------------------------------------------------------ 実際の AuthorizationGate との結合

    private var now = 0L
    private val gate = AuthorizationGate(elapsed = { now }, oneTime = { true })
    private fun gatePolicy() = AuthorizationPolicy { r, ka -> gate.authorize(r, ka, blocking = false) }

    @Test
    fun oneTimeAuthorizationCannotBeUsedByTwoTransportsAtOnce() {
        gate.setForeground(true)
        gate.arm(60_000)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val slowStore = object : CredentialStore by store {
            override fun create(rpId: String, rpName: String?, user: UserEntity, discoverable: Boolean): StoredCredential {
                entered.countDown()
                release.await(5, TimeUnit.SECONDS)
                return store.create(rpId, rpName, user, discoverable)
            }
        }
        val nfc = Ctap2Authenticator(slowStore, gatePolicy(), { config }, "NFC")
        val bt = Ctap2Authenticator(store, gatePolicy(), { config }, "Bluetooth")
        var nfcStatus = -1
        val t = Thread { nfcStatus = status(nfc.process(mc(rk = false))) }.apply { start() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, status(bt.process(mc(rk = false, userId = byteArrayOf(9)))))
        release.countDown()
        t.join(5_000)
        assertEquals(CtapStatus.OK, nfcStatus)
        assertFalse(gate.isArmed())
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, status(bt.process(mc(rk = false, userId = byteArrayOf(9)))))
        assertEquals(1, store.list().size)
    }

    @Test
    fun getNextAssertionContinuesAfterOneTimeConsumptionButNotAfterStop() {
        gate.setForeground(true)
        gate.arm(60_000)
        val a = Ctap2Authenticator(store, gatePolicy(), { config }, "NFC")
        assertEquals(CtapStatus.OK, status(a.process(mc(rk = true, userId = byteArrayOf(1)))))
        gate.arm(60_000)
        assertEquals(CtapStatus.OK, status(a.process(mc(rk = true, userId = byteArrayOf(2)))))
        gate.arm(60_000)
        assertEquals(CtapStatus.OK, status(a.process(ga())))
        assertFalse("one-time authorization was consumed by GetAssertion", gate.isArmed())
        assertEquals(CtapStatus.OK, status(a.process(gna)))

        gate.arm(60_000)
        assertEquals(CtapStatus.OK, status(a.process(ga())))
        gate.disarm()
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, status(a.process(gna)))

        gate.arm(60_000)
        assertEquals(CtapStatus.OK, status(a.process(ga())))
        gate.setForeground(false)
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, status(a.process(gna)))
    }
}
