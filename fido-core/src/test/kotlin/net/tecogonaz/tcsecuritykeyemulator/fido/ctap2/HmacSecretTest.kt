// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor
import net.tecogonaz.tcsecuritykeyemulator.fido.pin.Hkdf
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.FakePolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestCrypto
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestPlatform
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** hmac-secret 拡張と clientPIN の getKeyAgreement (DD-01 §11)。 */
class HmacSecretTest {
    private val store = InMemoryCredentialStore()
    private val policy = FakePolicy()
    private var config = AuthenticatorConfig(ByteArray(16) { 1 })
    private val authenticator = Ctap2Authenticator(store, policy, { config }, "test")
    private val clientDataHash = TestCrypto.sha256("client-data".toByteArray())
    private val salt1 = ByteArray(32) { 0x11 }
    private val salt2 = ByteArray(32) { 0x22 }

    private fun call(cmd: Int, params: Map<Long, Any?>? = null): Pair<Int, Map<*, *>?> {
        val req = if (params == null) byteArrayOf(cmd.toByte()) else byteArrayOf(cmd.toByte()) + Cbor.encode(params)
        val resp = authenticator.process(req)
        val body = if (resp.size > 1) Cbor.decode(resp, 1, resp.size - 1) as Map<*, *> else null
        return (resp[0].toInt() and 0xFF) to body
    }

    private fun keyAgreement(protocol: Long = 1): Map<*, *> {
        val (status, resp) = call(CtapCommand.CLIENT_PIN, linkedMapOf(1L to protocol, 2L to 2L))
        assertEquals(CtapStatus.OK, status)
        return resp!![1L] as Map<*, *>
    }

    private fun makeCredential(
        user: ByteArray = byteArrayOf(1),
        rk: Boolean = false,
        extensions: Map<String, Any>? = mapOf("hmac-secret" to true)
    ): Pair<Int, Map<*, *>?> {
        val p = linkedMapOf<Long, Any?>(
            1L to clientDataHash,
            2L to linkedMapOf("id" to "example.com"),
            3L to linkedMapOf("id" to user, "name" to "u${user[0]}"),
            4L to listOf(linkedMapOf("alg" to -7L, "type" to "public-key")),
            7L to linkedMapOf("rk" to rk)
        )
        if (extensions != null) p[6L] = extensions
        return call(CtapCommand.MAKE_CREDENTIAL, p)
    }

    /** プラットフォーム側で salt を暗号化した hmac-secret の入力と、復号用の共有鍵。 */
    private fun hmacInput(
        salts: ByteArray = salt1,
        platform: TestPlatform = TestPlatform(1),
        includeProtocol: Boolean = true
    ): Pair<Map<Long, Any>, ByteArray> {
        val secret = platform.sharedSecret(keyAgreement(platform.version.toLong()))
        val saltEnc = platform.encrypt(secret, salts)
        val input = linkedMapOf<Long, Any>(1L to platform.keyAgreement, 2L to saltEnc, 3L to platform.authenticate(secret, saltEnc))
        if (includeProtocol) input[4L] = platform.version.toLong()
        return input to secret
    }

    private fun getAssertion(
        extension: Any?,
        allowId: ByteArray? = null,
        options: Map<String, Any>? = null
    ): Pair<Int, Map<*, *>?> {
        val p = linkedMapOf<Long, Any?>(1L to "example.com", 2L to clientDataHash)
        if (allowId != null) p[3L] = listOf(linkedMapOf("id" to allowId, "type" to "public-key"))
        if (extension != null) p[4L] = mapOf("hmac-secret" to extension)
        if (options != null) p[5L] = options
        return call(CtapCommand.GET_ASSERTION, p)
    }

    /** authenticatorData の拡張 (ED) を返す。ED がなければ null。 */
    private fun extensionsOf(authData: ByteArray): Map<*, *>? {
        val flags = authData[32].toInt()
        if (flags and AuthDataFlags.ED == 0) return null
        var offset = 37
        if (flags and AuthDataFlags.AT != 0) {
            val idLen = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
            offset = 55 + idLen
            offset += Cbor.decodeFirst(authData, offset).second
        }
        return Cbor.decode(authData, offset, authData.size - offset) as Map<*, *>
    }

    private fun credentialIdOf(resp: Map<*, *>): ByteArray {
        val authData = resp[2L] as ByteArray
        val idLen = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
        return authData.copyOfRange(55, 55 + idLen)
    }

    private fun expected(credRandom: ByteArray, vararg salts: ByteArray): ByteArray =
        salts.fold(ByteArray(0)) { acc, s -> acc + Hkdf.hmacSha256(credRandom, s) }

    @Test
    fun getKeyAgreementReturnsACoseKeyAndRejectsInvalidRequests() {
        val key = keyAgreement()
        assertEquals(2L, key[1L])
        assertEquals(-25L, key[3L])
        assertEquals(1L, key[-1L])

        assertEquals(2L, (call(CtapCommand.CLIENT_PIN, linkedMapOf(1L to 2L, 2L to 2L)).second!![1L] as Map<*, *>)[1L])
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, call(CtapCommand.CLIENT_PIN, linkedMapOf(1L to 3L, 2L to 2L)).first)
        assertEquals(CtapStatus.ERR_MISSING_PARAMETER, call(CtapCommand.CLIENT_PIN, linkedMapOf(1L to 1L)).first)
        assertEquals(CtapStatus.ERR_MISSING_PARAMETER, call(CtapCommand.CLIENT_PIN).first)
        assertEquals(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, call(CtapCommand.CLIENT_PIN, linkedMapOf(1L to "1", 2L to 2L)).first)
        // getUVRetries (0x07) と未定義の番号は未対応
        assertEquals(CtapStatus.ERR_INVALID_SUBCOMMAND, call(CtapCommand.CLIENT_PIN, linkedMapOf(1L to 1L, 2L to 7L)).first)
        assertEquals(CtapStatus.ERR_INVALID_SUBCOMMAND, call(CtapCommand.CLIENT_PIN, linkedMapOf(1L to 1L, 2L to 8L)).first)
        assertTrue("clientPIN must not ask for authorization", policy.requests.isEmpty())
    }

    @Test
    fun makeCredentialReportsTheExtensionOnlyWhenRequested() {
        val (s1, r1) = makeCredential()
        assertEquals(CtapStatus.OK, s1)
        assertEquals(mapOf("hmac-secret" to true), extensionsOf(r1!![2L] as ByteArray))
        assertTrue(store.list().single().hmacSecret)

        val (s2, r2) = makeCredential(user = byteArrayOf(2), extensions = null)
        assertEquals(CtapStatus.OK, s2)
        assertNull(extensionsOf(r2!![2L] as ByteArray))
        val (s3, r3) = makeCredential(user = byteArrayOf(3), extensions = mapOf("hmac-secret" to false))
        assertEquals(CtapStatus.OK, s3)
        assertNull(extensionsOf(r3!![2L] as ByteArray))
        assertEquals(1, store.list().count { it.hmacSecret })

        assertEquals(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, makeCredential(user = byteArrayOf(4), extensions = mapOf("hmac-secret" to 1L)).first)
    }

    @Test
    fun getAssertionReturnsEncryptedOutputsForOneOrTwoSalts() {
        val id = credentialIdOf(makeCredential().second!!)
        val credential = store.list().single()
        val (withUv, _) = store.credRandoms(credential)!!
        val publicKey = TestCrypto.publicKeyFromCose(
            Cbor.decodeFirst(makeCredentialAuthDataFor(credential), 0).first as Map<*, *>
        )

        for (salts in listOf(salt1, salt1 + salt2)) {
            val platform = TestPlatform(1)
            val (input, secret) = hmacInput(salts, platform)
            val (status, resp) = getAssertion(input, allowId = id)
            assertEquals(CtapStatus.OK, status)
            val authData = resp!![2L] as ByteArray
            assertTrue(authData[32].toInt() and AuthDataFlags.ED != 0)
            val encrypted = extensionsOf(authData)!!["hmac-secret"] as ByteArray
            val decrypted = platform.decrypt(secret, encrypted)
            val expectedOutputs = if (salts.size == 32) expected(withUv, salt1) else expected(withUv, salt1, salt2)
            assertArrayEquals(expectedOutputs, decrypted)
            // 署名は拡張を含む authenticatorData に対して行う
            assertTrue(TestCrypto.verify(publicKey, authData + clientDataHash, resp[3L] as ByteArray))
        }
    }

    @Test
    fun outputsAreDeterministicPerSaltAndDifferWithoutUv() {
        val id = credentialIdOf(makeCredential().second!!)
        fun output(): ByteArray {
            val platform = TestPlatform(1)
            val (input, secret) = hmacInput(salt1, platform)
            val resp = getAssertion(input, allowId = id).second!!
            return platform.decrypt(secret, extensionsOf(resp[2L] as ByteArray)!!["hmac-secret"] as ByteArray)
        }
        val first = output()
        assertArrayEquals(first, output())

        // UV なしの認証 (ポリシーが UV を許可しない) では CredRandomWithoutUV を使う
        policy.result = AuthorizationResult.Granted(userPresent = true, userVerified = false)
        val withoutUv = output()
        assertFalse(first.contentEquals(withoutUv))
        val (_, noUv) = store.credRandoms(store.list().single())!!
        assertArrayEquals(expected(noUv, salt1), withoutUv)
    }

    @Test
    fun protocolDefaultsToOneWhenOmitted() {
        val id = credentialIdOf(makeCredential().second!!)
        val platform = TestPlatform(1)
        val (input, secret) = hmacInput(salt1, platform, includeProtocol = false)
        val (status, resp) = getAssertion(input, allowId = id)
        assertEquals(CtapStatus.OK, status)
        val (withUv, _) = store.credRandoms(store.list().single())!!
        assertArrayEquals(
            expected(withUv, salt1),
            platform.decrypt(secret, extensionsOf(resp!![2L] as ByteArray)!!["hmac-secret"] as ByteArray)
        )
    }

    @Test
    fun invalidInputsAreRejectedBeforeAuthorization() {
        val id = credentialIdOf(makeCredential().second!!)
        policy.requests.clear()

        val (valid, secret) = hmacInput()
        val badAuth = valid + (3L to ByteArray(16))
        val badLength = TestPlatform(1).let { platform ->
            val s = platform.sharedSecret(keyAgreement())
            val enc = platform.encrypt(s, ByteArray(48))
            linkedMapOf<Long, Any>(1L to platform.keyAgreement, 2L to enc, 3L to platform.authenticate(s, enc), 4L to 1L)
        }
        val offCurve = valid + (1L to (valid[1L] as Map<*, *>).let { k ->
            k.entries.associate { (key, v) -> key to if (key == -3L) (v as ByteArray).copyOf().also { it[0] = (it[0] + 1).toByte() } else v }
        })
        val cases = listOf(
            badAuth to CtapStatus.ERR_PIN_AUTH_INVALID,
            badLength to CtapStatus.ERR_INVALID_PARAMETER,
            (valid + (4L to 3L)) to CtapStatus.ERR_INVALID_PARAMETER,      // 未対応のプロトコル
            (valid + (4L to 2L)) to CtapStatus.ERR_PIN_AUTH_INVALID,       // Protocol 1 で作った入力を Protocol 2 として送る
            offCurve to CtapStatus.ERR_INVALID_PARAMETER,
            (valid - 3L) to CtapStatus.ERR_MISSING_PARAMETER,
            (valid + (2L to "x")) to CtapStatus.ERR_CBOR_UNEXPECTED_TYPE,
            "not-a-map" to CtapStatus.ERR_CBOR_UNEXPECTED_TYPE
        )
        for ((input, expectedStatus) in cases) {
            assertEquals(expectedStatus, getAssertion(input, allowId = id).first)
        }
        assertEquals(CtapStatus.ERR_UNSUPPORTED_OPTION, getAssertion(valid, allowId = id, options = mapOf("up" to false)).first)
        assertTrue("invalid input must not use the authorization", policy.requests.isEmpty())
        assertTrue(secret.isNotEmpty())
    }

    @Test
    fun credentialWithoutHmacSecretIgnoresTheExtension() {
        val id = credentialIdOf(makeCredential(extensions = null).second!!)
        val (status, resp) = getAssertion(hmacInput().first, allowId = id)
        assertEquals(CtapStatus.OK, status)
        assertNull(extensionsOf(resp!![2L] as ByteArray))
    }

    @Test
    fun getNextAssertionReturnsOutputsForEachCredential() {
        makeCredential(user = byteArrayOf(1), rk = true)
        makeCredential(user = byteArrayOf(2), rk = true)
        val platform = TestPlatform(1)
        val (input, secret) = hmacInput(salt1, platform)
        val (s1, first) = getAssertion(input)
        assertEquals(CtapStatus.OK, s1)
        assertEquals(2L, first!![5L])
        val (s2, second) = call(CtapCommand.GET_NEXT_ASSERTION)
        assertEquals(CtapStatus.OK, s2)

        for (resp in listOf(first, second!!)) {
            val userId = (resp[4L] as Map<*, *>)["id"] as ByteArray
            val credential = store.list().single { it.user.id.contentEquals(userId) }
            val (withUv, _) = store.credRandoms(credential)!!
            val out = platform.decrypt(secret, extensionsOf(resp[2L] as ByteArray)!!["hmac-secret"] as ByteArray)
            assertArrayEquals(expected(withUv, salt1), out)
        }
    }

    @Test
    fun resetRegeneratesTheKeyAgreementKey() {
        config = config.copy(allowReset = true)
        val before = keyAgreement()[-2L] as ByteArray
        assertEquals(CtapStatus.OK, call(CtapCommand.RESET).first)
        assertFalse(before.contentEquals(keyAgreement()[-2L] as ByteArray))
    }

    /** 登録時の公開鍵 (COSE_Key) のバイト列。 */
    private fun makeCredentialAuthDataFor(credential: StoredCredential): ByteArray =
        Cbor.encode(EcKeys.coseKey(credential.publicKeyX, credential.publicKeyY))
}
