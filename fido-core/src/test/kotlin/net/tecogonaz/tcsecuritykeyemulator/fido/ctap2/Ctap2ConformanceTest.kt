// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.FakePolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/** CTAP 2.0 の境界条件 (レビュー指摘 F-05〜F-09)。 */
class Ctap2ConformanceTest {

    private val store = InMemoryCredentialStore()
    private val policy = FakePolicy()
    private var monotonic = 0L
    private val auth = Ctap2Authenticator(
        store, policy, { AuthenticatorConfig(ByteArray(16)) }, "test",
        monotonicClock = { monotonic }
    )
    private val cdh = TestCrypto.sha256("cd".toByteArray())

    private fun call(cmd: Int, params: Map<Long, Any?>? = null, a: Ctap2Authenticator = auth): Pair<Int, Map<*, *>?> {
        val req = if (params == null) byteArrayOf(cmd.toByte()) else byteArrayOf(cmd.toByte()) + Cbor.encode(params)
        val resp = a.process(req)
        val body = if (resp.size > 1) Cbor.decode(resp, 1, resp.size - 1) as Map<*, *> else null
        return (resp[0].toInt() and 0xFF) to body
    }

    private fun mcParams(
        rk: Boolean = true,
        userId: ByteArray = byteArrayOf(1),
        hash: ByteArray = cdh,
        algs: List<Long> = listOf(-7L),
        extra: Map<Long, Any?> = emptyMap(),
        options: Map<String, Any?> = mapOf("rk" to rk)
    ): Map<Long, Any?> = linkedMapOf<Long, Any?>(
        1L to hash,
        2L to linkedMapOf("id" to "example.com"),
        3L to linkedMapOf("id" to userId, "name" to "u${userId[0]}"),
        4L to algs.map { linkedMapOf("alg" to it, "type" to "public-key") },
        7L to options
    ).apply { putAll(extra) }

    private fun gaParams(
        allow: List<Map<String, Any>>? = null,
        hash: ByteArray = cdh,
        options: Map<String, Any?>? = null,
        extra: Map<Long, Any?> = emptyMap()
    ): Map<Long, Any?> = linkedMapOf<Long, Any?>(1L to "example.com", 2L to hash).apply {
        if (allow != null) this[3L] = allow
        if (options != null) this[5L] = options
        putAll(extra)
    }

    private fun register(rk: Boolean = true, userId: Byte = 1): ByteArray {
        val (s, r) = call(CtapCommand.MAKE_CREDENTIAL, mcParams(rk = rk, userId = byteArrayOf(userId)))
        assertEquals(CtapStatus.OK, s)
        val authData = r!![2L] as ByteArray
        val len = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
        return authData.copyOfRange(55, 55 + len)
    }

    private fun flags(resp: Map<*, *>) = (resp[2L] as ByteArray)[32].toInt() and 0xFF

    // ------------------------------------------------------------------ F-05 allowList

    @Test
    fun allowListWithOnlyUnknownTypesDoesNotFallBackToDiscoverable() {
        register()
        val (s, _) = call(CtapCommand.GET_ASSERTION, gaParams(allow = listOf(mapOf("type" to "future-credential", "id" to byteArrayOf(0x63)))))
        assertEquals(CtapStatus.ERR_NO_CREDENTIALS, s)
    }

    @Test
    fun emptyAllowListMeansDiscoverableSearch() {
        register()
        val (s, r) = call(CtapCommand.GET_ASSERTION, gaParams(allow = emptyList()))
        assertEquals(CtapStatus.OK, s)
        assertEquals(true, r!!.containsKey(4L))
    }

    @Test
    fun mixedAllowListUsesKnownEntriesOnly() {
        val id = register(rk = false)
        val (s, r) = call(
            CtapCommand.GET_ASSERTION,
            gaParams(allow = listOf(mapOf("type" to "future-credential", "id" to byteArrayOf(1)), mapOf("type" to "public-key", "id" to id)))
        )
        assertEquals(CtapStatus.OK, s)
        assertArrayEquals(id, (r!![1L] as Map<*, *>)["id"] as ByteArray)
    }

    // ------------------------------------------------------------------ F-06 UP / UV

    @Test
    fun upAndUvAreIndependent() {
        val id = register(rk = false)
        val allow = listOf(mapOf("type" to "public-key", "id" to id))
        val cases = listOf(
            mapOf("up" to true, "uv" to true) to (AuthDataFlags.UP or AuthDataFlags.UV),
            mapOf("up" to true) to (AuthDataFlags.UP or AuthDataFlags.UV), // 本人確認済みの受付なので UV も立つ
            mapOf("up" to false, "uv" to true) to AuthDataFlags.UV,
            mapOf("up" to false) to 0
        )
        for ((options, expected) in cases) {
            policy.completed.clear()
            val (s, r) = call(CtapCommand.GET_ASSERTION, gaParams(allow = allow, options = options))
            assertEquals(CtapStatus.OK, s)
            assertEquals("flags for $options", expected, flags(r!!))
            assertEquals("consumption for $options", listOf(expected != 0), policy.completed.map { it.second })
        }
    }

    @Test
    fun uvRequestFailsWhenVerificationWasNotPerformed() {
        val id = register(rk = false)
        policy.result = AuthorizationResult.Granted(userPresent = true, userVerified = false)
        val (s, _) = call(CtapCommand.GET_ASSERTION, gaParams(allow = listOf(mapOf("type" to "public-key", "id" to id)), options = mapOf("uv" to true)))
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, s)
    }

    // ------------------------------------------------------------------ F-07 入力検証・エラー順序

    @Test
    fun clientDataHashMustBe32Bytes() {
        for (n in listOf(0, 31, 33)) {
            assertEquals(CtapStatus.ERR_INVALID_LENGTH, call(CtapCommand.MAKE_CREDENTIAL, mcParams(hash = ByteArray(n))).first)
            assertEquals(CtapStatus.ERR_INVALID_LENGTH, call(CtapCommand.GET_ASSERTION, gaParams(hash = ByteArray(n))).first)
        }
        assertEquals(CtapStatus.OK, call(CtapCommand.MAKE_CREDENTIAL, mcParams(hash = ByteArray(32))).first)
    }

    @Test
    fun extensionsMustBeAMapButUnknownExtensionsAreIgnored() {
        assertEquals(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, call(CtapCommand.MAKE_CREDENTIAL, mcParams(extra = mapOf(6L to "x"))).first)
        assertEquals(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, call(CtapCommand.GET_ASSERTION, gaParams(extra = mapOf(4L to listOf(1L)))).first)
        assertEquals(CtapStatus.OK, call(CtapCommand.MAKE_CREDENTIAL, mcParams(extra = mapOf(6L to mapOf("credProtect" to 2L)))).first)
    }

    @Test
    fun pinProtocolMustBeAnInteger() {
        assertEquals(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, call(CtapCommand.MAKE_CREDENTIAL, mcParams(extra = mapOf(9L to "1"))).first)
        assertEquals(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, call(CtapCommand.GET_ASSERTION, gaParams(extra = mapOf(7L to "1"))).first)
    }

    @Test
    fun makeCredentialUpOption() {
        assertEquals(CtapStatus.ERR_INVALID_OPTION, call(CtapCommand.MAKE_CREDENTIAL, mcParams(options = mapOf("up" to false))).first)
        // up:true は CTAP 2.1 で許容されており、互換性のため受け付ける
        assertEquals(CtapStatus.OK, call(CtapCommand.MAKE_CREDENTIAL, mcParams(options = mapOf("up" to true))).first)
    }

    @Test
    fun excludeListIsCheckedBeforeTheAlgorithm() {
        val id = register(rk = false)
        val (s, _) = call(
            CtapCommand.MAKE_CREDENTIAL,
            mcParams(algs = listOf(-257L), extra = mapOf(5L to listOf(mapOf("type" to "public-key", "id" to id))))
        )
        assertEquals(CtapStatus.ERR_CREDENTIAL_EXCLUDED, s)
        assertEquals(CtapStatus.ERR_UNSUPPORTED_ALGORITHM, call(CtapCommand.MAKE_CREDENTIAL, mcParams(algs = listOf(-257L))).first)
    }

    // ------------------------------------------------------------------ F-08 GetNextAssertion

    private fun threeDiscoverable() {
        register(userId = 1); register(userId = 2); register(userId = 3)
    }

    @Test
    fun getNextAssertionTimerRestartsAfterEachAssertion() {
        threeDiscoverable()
        monotonic = 0
        val (s0, r0) = call(CtapCommand.GET_ASSERTION, gaParams())
        assertEquals(CtapStatus.OK, s0)
        assertEquals(3L, r0!![5L])
        monotonic = 20_000
        assertEquals(CtapStatus.OK, call(CtapCommand.GET_NEXT_ASSERTION).first)
        monotonic = 40_000 // 直前から 20 秒
        assertEquals(CtapStatus.OK, call(CtapCommand.GET_NEXT_ASSERTION).first)
    }

    @Test
    fun getNextAssertionTimesOut() {
        threeDiscoverable()
        monotonic = 0
        call(CtapCommand.GET_ASSERTION, gaParams())
        monotonic = 30_001
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, call(CtapCommand.GET_NEXT_ASSERTION).first)
    }

    @Test
    fun failedGetNextAssertionDoesNotSkipTheCredential() {
        threeDiscoverable()
        var failNext = false
        val flaky = object : CredentialStore by store {
            override fun sign(credential: StoredCredential, data: ByteArray): ByteArray {
                if (failNext) {
                    failNext = false
                    throw KeyUseNotAuthorizedException("transient")
                }
                return store.sign(credential, data)
            }
        }
        val a = Ctap2Authenticator(flaky, policy, { AuthenticatorConfig(ByteArray(16)) }, "test", monotonicClock = { monotonic })
        call(CtapCommand.GET_ASSERTION, gaParams(), a)
        failNext = true
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, call(CtapCommand.GET_NEXT_ASSERTION, a = a).first)
        val (s, r) = call(CtapCommand.GET_NEXT_ASSERTION, a = a)
        assertEquals(CtapStatus.OK, s)
        assertArrayEquals(byteArrayOf(2), (r!![4L] as Map<*, *>)["id"] as ByteArray)
    }

    // ------------------------------------------------------------------ F-09 順序

    @Test
    fun discoverableCredentialsAreReturnedNewestCreatedFirstRegardlessOfUse() {
        val older = register(userId = 1)
        register(userId = 2)
        // 古い方を allowList 指定で使用する (最終使用日時が新しくなる)
        call(CtapCommand.GET_ASSERTION, gaParams(allow = listOf(mapOf("type" to "public-key", "id" to older))))
        val (_, r) = call(CtapCommand.GET_ASSERTION, gaParams())
        assertArrayEquals(byteArrayOf(2), (r!![4L] as Map<*, *>)["id"] as ByteArray)
    }

    @Test
    fun newestFirstOrderingIsDeterministicForEqualTimestamps() {
        fun cred(id: Byte, created: Long) = StoredCredential(
            byteArrayOf(id), "rp", null, UserEntity(byteArrayOf(id), null, null), true, created,
            lastUsedAtMillis = 99_999, signCount = 0, publicKeyX = ByteArray(32), publicKeyY = ByteArray(32),
            securityLevel = KeySecurityLevel.TEE
        )
        val sorted = listOf(cred(2, 10), cred(1, 10), cred(3, 20)).sortedWith(StoredCredential.NEWEST_FIRST)
        assertEquals(listOf<Byte>(3, 1, 2), sorted.map { it.id[0] })
    }
}
