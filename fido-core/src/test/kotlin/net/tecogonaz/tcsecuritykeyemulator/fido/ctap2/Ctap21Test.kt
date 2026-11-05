// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.CtapTestClient
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.FakePolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestCrypto
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestPlatform
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** CTAP 2.1 の pinUvAuthToken (内蔵 UV による発行と、MakeCredential / GetAssertion での使用。DD-01 §12.1、§12.2)。 */
class Ctap21Test {
    private val store = InMemoryCredentialStore()
    private val policy = FakePolicy()
    private var now = 1_000_000L
    private var config = AuthenticatorConfig(ByteArray(16) { 2 })
    private val authenticator = Ctap2Authenticator(store, policy, { config }, "test", monotonicClock = { now })
    private val client = CtapTestClient(authenticator)
    private val cdh = TestCrypto.sha256("client-data".toByteArray())
    private val mcGa = (ClientPin.PERMISSION_MC or ClientPin.PERMISSION_GA).toLong()

    @Test
    fun uvTokenIsIssuedThroughTheGateWithoutConsumingTheOneTimeAuthorization() {
        for (version in listOf(1L, 2L)) {
            policy.requests.clear()
            policy.completed.clear()
            val token = client.uvToken(version, mcGa, "example.com")
            assertEquals(32, token.token.size)
            val request = policy.requests.single()
            assertEquals(CtapOperation.PIN_UV_AUTH_TOKEN, request.operation)
            assertEquals("example.com", request.rpId)
            assertTrue(request.requireUserVerification)
            assertEquals(listOf(request to false), policy.completed)
        }
    }

    @Test
    fun uvTokenIsRefusedWhenTheGateDenies() {
        val denied = FakePolicy.denied()
        val c = CtapTestClient(Ctap2Authenticator(store, denied, { config }, "test"))
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, c.requestUvToken(2, mcGa).first)
        // UV なしの許可ではトークンを発行しない
        val noUv = FakePolicy(AuthorizationResult.Granted(userPresent = true, userVerified = false))
        val c2 = CtapTestClient(Ctap2Authenticator(store, noUv, { config }, "test"))
        assertEquals(CtapStatus.ERR_UV_INVALID, c2.requestUvToken(2, mcGa).first)
    }

    @Test
    fun uvTokenRequestsAreValidatedBeforeAuthorization() {
        val platform = TestPlatform(2)
        val key = platform.keyAgreement
        fun req(vararg entries: Pair<Long, Any>): Int =
            client.status(CtapCommand.CLIENT_PIN, linkedMapOf<Long, Any?>(2L to 6L).apply { entries.forEach { put(it.first, it.second) } })
        client.keyAgreement(2)
        policy.requests.clear()
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, req(1L to 2L, 3L to key, 9L to 0L))
        for (unsupported in listOf(0x08L, 0x10L, 0x20L, 0x21L)) {
            assertEquals(CtapStatus.ERR_UNAUTHORIZED_PERMISSION, req(1L to 2L, 3L to key, 9L to unsupported))
        }
        assertEquals(CtapStatus.ERR_MISSING_PARAMETER, req(1L to 2L, 9L to mcGa))
        assertEquals(CtapStatus.ERR_MISSING_PARAMETER, req(1L to 2L, 3L to key))
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, req(1L to 3L, 3L to key, 9L to mcGa))
        assertEquals(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, req(1L to 2L, 3L to key, 9L to mcGa, 0x0AL to 1L))
        val offCurve = key + (-3L to (key[-3L] as ByteArray).copyOf().also { it[0] = (it[0] + 1).toByte() })
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, req(1L to 2L, 3L to offCurve, 9L to mcGa))
        assertTrue(policy.requests.isEmpty())
    }

    @Test
    fun tokenAuthorizesMakeCredentialAndGetAssertionButTheGateIsStillConsulted() {
        for (version in listOf(1L, 2L)) {
            val token = client.uvToken(version, mcGa)
            policy.requests.clear()
            policy.completed.clear()
            val (s1, mc) = client.call(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, token = token, userId = byteArrayOf(version.toByte())))
            assertEquals(CtapStatus.OK, s1)
            assertTrue((mc!![2L] as ByteArray)[32].toInt() and AuthDataFlags.UV != 0)
            assertEquals(CtapOperation.MAKE_CREDENTIAL, policy.requests.single().operation)
            assertEquals(true, policy.completed.single().second)

            // UP を伴う操作に使うと権限が消える (CTAP 2.1 §6.1.2 手順 14.4)
            val reuse = client.call(CtapCommand.GET_ASSERTION, client.getAssertionParams(cdh, token = token)).first
            assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, reuse)

            val gaToken = client.uvToken(version, ClientPin.PERMISSION_GA.toLong())
            val (s2, ga) = client.call(CtapCommand.GET_ASSERTION, client.getAssertionParams(cdh, token = gaToken))
            assertEquals(CtapStatus.OK, s2)
            assertEquals(AuthDataFlags.UP or AuthDataFlags.UV, (ga!![2L] as ByteArray)[32].toInt())
        }
    }

    @Test
    fun invalidPinUvAuthParamsAreRejected() {
        val token = client.uvToken(2, mcGa)
        val good = client.makeCredentialParams(cdh, token = token)
        val tampered = good + (8L to (good[8L] as ByteArray).copyOf().also { it[0] = (it[0] + 1).toByte() })
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, client.status(CtapCommand.MAKE_CREDENTIAL, tampered))
        assertEquals(CtapStatus.ERR_MISSING_PARAMETER, client.status(CtapCommand.MAKE_CREDENTIAL, good - 9L))
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, client.status(CtapCommand.MAKE_CREDENTIAL, good + (9L to 3L)))
        // Protocol 2 のトークンを Protocol 1 として送ると検証できない
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, client.status(CtapCommand.MAKE_CREDENTIAL, good + (9L to 1L)))

        // 権限の不足: ga のみのトークンで登録
        val gaOnly = client.uvToken(2, ClientPin.PERMISSION_GA.toLong())
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, client.status(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, token = gaOnly)))
        // RP ID の不一致
        val bound = client.uvToken(2, mcGa, "other.example")
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, client.status(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, token = bound)))
    }

    @Test
    fun tokenWithoutRpIdIsBoundOnFirstUse() {
        client.call(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, rpId = "a.example"))
        client.call(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, rpId = "b.example"))
        val token = client.uvToken(2, ClientPin.PERMISSION_GA.toLong())
        val silent = mapOf("up" to false)
        // silent assertion は権限を消さないため、同じトークンで続けて送れる
        assertEquals(CtapStatus.OK, client.status(CtapCommand.GET_ASSERTION, client.getAssertionParams(cdh, "a.example", options = silent, token = token)))
        assertEquals(CtapStatus.OK, client.status(CtapCommand.GET_ASSERTION, client.getAssertionParams(cdh, "a.example", options = silent, token = token)))
        assertEquals(
            CtapStatus.ERR_PIN_AUTH_INVALID,
            client.status(CtapCommand.GET_ASSERTION, client.getAssertionParams(cdh, "b.example", options = silent, token = token))
        )
    }

    @Test
    fun silentAssertionWithATokenHasUvButDoesNotConsumeTheOneTimeAuthorization() {
        client.call(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh))
        val token = client.uvToken(2, ClientPin.PERMISSION_GA.toLong())
        policy.completed.clear()
        val (status, ga) = client.call(
            CtapCommand.GET_ASSERTION, client.getAssertionParams(cdh, options = mapOf("up" to false), token = token)
        )
        assertEquals(CtapStatus.OK, status)
        assertEquals(AuthDataFlags.UV, (ga!![2L] as ByteArray)[32].toInt())
        assertEquals(false, policy.completed.single().second)
    }

    @Test
    fun tokensExpireAndAreRevoked() {
        val ga = ClientPin.PERMISSION_GA.toLong()
        client.call(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh))
        val silent = mapOf("up" to false)
        fun use(token: CtapTestClient.Token) =
            client.status(CtapCommand.GET_ASSERTION, client.getAssertionParams(cdh, options = silent, token = token))

        // 発行から最初の使用までの期限
        val t1 = client.uvToken(2, ga)
        now += ClientPin.INITIAL_USAGE_LIMIT_MS + 1
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, use(t1))

        // 使用後は最大の使用期間まで有効
        val t2 = client.uvToken(2, ga)
        assertEquals(CtapStatus.OK, use(t2))
        now += ClientPin.INITIAL_USAGE_LIMIT_MS + 1
        assertEquals(CtapStatus.OK, use(t2))
        now += ClientPin.MAX_USAGE_PERIOD_MS
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, use(t2))

        // トランスポートのセッションの変化 (NFC の切断など)
        val t3 = client.uvToken(2, ga)
        authenticator.resetSession()
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, use(t3))

        // 発行時の認可の失効 (受付の停止・前面離脱)
        val t4 = client.uvToken(2, ga)
        policy.leaseValid = false
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, use(t4))
        policy.leaseValid = true

        // 新しいトークンの発行で古いトークンは無効になる
        val t5 = client.uvToken(2, ga)
        val t6 = client.uvToken(1, ga)
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, use(t5))
        assertEquals(CtapStatus.OK, use(t6))

        // Reset で無効になる
        config = config.copy(allowReset = true)
        val t7 = client.uvToken(2, ga)
        assertEquals(CtapStatus.OK, client.status(CtapCommand.RESET))
        client.call(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh))
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, use(t7))
    }

    @Test
    fun uvOptionStillWorksWithoutAToken() {
        val (s1, mc) = client.call(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, uv = true))
        assertEquals(CtapStatus.OK, s1)
        assertTrue((mc!![2L] as ByteArray)[32].toInt() and AuthDataFlags.UV != 0)
        val (s2, _) = client.call(CtapCommand.GET_ASSERTION, client.getAssertionParams(cdh, options = mapOf("uv" to true)))
        assertEquals(CtapStatus.OK, s2)
        // ゼロ長の pinUvAuthParam は従来どおりのプローブ (PIN 非対応のため PIN_NOT_SET)
        val probe = client.makeCredentialParams(cdh) + (8L to ByteArray(0)) + (9L to 2L)
        assertEquals(CtapStatus.ERR_PIN_NOT_SET, client.status(CtapCommand.MAKE_CREDENTIAL, probe))
        assertFalse(store.list().isEmpty())
    }
}
