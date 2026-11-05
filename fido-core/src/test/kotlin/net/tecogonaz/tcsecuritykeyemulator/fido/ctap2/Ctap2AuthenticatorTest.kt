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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Ctap2AuthenticatorTest {

    private val aaguid = Hex.decode("7c1e3a5b9d2f4e60a1b2c3d4e5f60718")
    private val store = InMemoryCredentialStore()
    private val policy = FakePolicy()
    private val events = mutableListOf<AuthenticatorEvent>()
    private var config = AuthenticatorConfig(aaguid)
    private val authenticator = Ctap2Authenticator(store, policy, { config }, "test", { events += it })

    private val clientDataHash = TestCrypto.sha256("client-data".toByteArray())

    private fun call(cmd: Int, params: Map<Long, Any?>? = null): Pair<Int, Map<*, *>?> {
        val req = if (params == null) byteArrayOf(cmd.toByte()) else byteArrayOf(cmd.toByte()) + Cbor.encode(params)
        val resp = authenticator.process(req)
        val status = resp[0].toInt() and 0xFF
        val body = if (resp.size > 1) Cbor.decode(resp, 1, resp.size - 1) as Map<*, *> else null
        return status to body
    }

    private fun makeCredentialParams(
        rk: Boolean,
        userId: ByteArray = byteArrayOf(1, 2, 3, 4),
        rpId: String = "example.com",
        exclude: List<ByteArray> = emptyList(),
        extra: Map<Long, Any?> = emptyMap()
    ): Map<Long, Any?> {
        val m = linkedMapOf<Long, Any?>(
            1L to clientDataHash,
            2L to linkedMapOf("id" to rpId, "name" to "Example"),
            3L to linkedMapOf("id" to userId, "name" to "alice@example.com", "displayName" to "Alice"),
            4L to listOf(
                linkedMapOf("alg" to -257L, "type" to "public-key"),
                linkedMapOf("alg" to -7L, "type" to "public-key")
            ),
            7L to linkedMapOf("rk" to rk, "uv" to true)
        )
        if (exclude.isNotEmpty()) m[5L] = exclude.map { linkedMapOf("id" to it, "type" to "public-key") }
        m.putAll(extra)
        return m
    }

    private data class Attested(val credentialId: ByteArray, val cose: Map<*, *>, val authData: ByteArray, val response: Map<*, *>)

    private fun parseAttested(resp: Map<*, *>): Attested {
        val authData = resp[2L] as ByteArray
        val credIdLen = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
        val credId = authData.copyOfRange(55, 55 + credIdLen)
        val (cose, _) = Cbor.decodeFirst(authData, 55 + credIdLen)
        return Attested(credId, cose as Map<*, *>, authData, resp)
    }

    @Test
    fun getInfoAdvertisesFido20And21WithBuiltInUvAndClientPin() {
        val (status, info) = call(CtapCommand.GET_INFO)
        assertEquals(CtapStatus.OK, status)
        assertEquals(listOf("FIDO_2_0", "FIDO_2_1"), info!![1L])
        assertArrayEquals(aaguid, info[3L] as ByteArray)
        val options = info[4L] as Map<*, *>
        assertEquals(true, options["rk"])
        assertEquals(true, options["uv"])
        assertEquals(false, options["plat"])
        // PIN 未設定 (clientPin: false)。最小の長さは 4
        assertEquals(false, options["clientPin"])
        assertEquals(4L, info[0x0DL])
        assertEquals(true, options["pinUvAuthToken"])
        assertEquals(true, options["credMgmt"])
        assertEquals(true, options["makeCredUvNotRqd"])
        assertEquals(listOf("credProtect", "hmac-secret"), info[2L])
        assertEquals(listOf(2L, 1L), info[6L])
    }

    @Test
    fun makeCredentialThenGetAssertionWithAllowListVerifiesSignature() {
        val (status, resp) = call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = false))
        assertEquals(CtapStatus.OK, status)
        assertEquals("none", resp!![1L])
        val att = parseAttested(resp)
        assertArrayEquals(Ctap2Authenticator.rpIdHash("example.com"), att.authData.copyOfRange(0, 32))
        val flags = att.authData[32].toInt()
        assertTrue(flags and AuthDataFlags.UP != 0)
        assertTrue(flags and AuthDataFlags.UV != 0)
        assertTrue(flags and AuthDataFlags.AT != 0)
        assertArrayEquals(aaguid, att.authData.copyOfRange(37, 53))
        assertEquals(-7L, att.cose[3L])

        val (aStatus, assertion) = call(
            CtapCommand.GET_ASSERTION,
            linkedMapOf(
                1L to "example.com",
                2L to clientDataHash,
                3L to listOf(linkedMapOf("id" to att.credentialId, "type" to "public-key")),
                5L to linkedMapOf("uv" to true)
            )
        )
        assertEquals(CtapStatus.OK, aStatus)
        val authData = assertion!![2L] as ByteArray
        assertEquals(37, authData.size)
        assertEquals(1, authData[36].toInt()) // sign counter
        val pub = TestCrypto.publicKeyFromCose(att.cose)
        assertTrue(TestCrypto.verify(pub, authData + clientDataHash, assertion[3L] as ByteArray))
        assertNull("non-discoverable credential must not return user", assertion[4L])
        assertArrayEquals(att.credentialId, (assertion[1L] as Map<*, *>)["id"] as ByteArray)
    }

    @Test
    fun selfAttestationIsSignedByCredentialKey() {
        config = config.copy(attestationMode = AttestationMode.SELF)
        val (status, resp) = call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = true))
        assertEquals(CtapStatus.OK, status)
        assertEquals("packed", resp!![1L])
        val att = parseAttested(resp)
        val stmt = resp[3L] as Map<*, *>
        assertEquals(-7L, stmt["alg"])
        val pub = TestCrypto.publicKeyFromCose(att.cose)
        assertTrue(TestCrypto.verify(pub, att.authData + clientDataHash, stmt["sig"] as ByteArray))
    }

    @Test
    fun discoverableCredentialsAreEnumeratedWithGetNextAssertion() {
        call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = true, userId = byteArrayOf(1)))
        call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = true, userId = byteArrayOf(2)))
        call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = true, userId = byteArrayOf(3), rpId = "other.example"))

        val (status, first) = call(
            CtapCommand.GET_ASSERTION,
            linkedMapOf(1L to "example.com", 2L to clientDataHash, 5L to linkedMapOf("uv" to true))
        )
        assertEquals(CtapStatus.OK, status)
        assertEquals(2L, first!![5L])
        val user1 = first[4L] as Map<*, *>
        assertEquals("alice@example.com", user1["name"])
        assertEquals("Alice", user1["displayName"])

        val (s2, second) = call(CtapCommand.GET_NEXT_ASSERTION)
        assertEquals(CtapStatus.OK, s2)
        val user2 = second!![4L] as Map<*, *>
        val ids = setOf((user1["id"] as ByteArray).toList(), (user2["id"] as ByteArray).toList())
        assertEquals(setOf(listOf<Byte>(1), listOf<Byte>(2)), ids)

        val (s3, _) = call(CtapCommand.GET_NEXT_ASSERTION)
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, s3)
    }

    @Test
    fun registeringSameUserAgainReplacesDiscoverableCredential() {
        call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = true))
        call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = true))
        assertEquals(1, store.list().size)
    }

    @Test
    fun excludeListMatchReturnsCredentialExcluded() {
        val (_, resp) = call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = false))
        val id = parseAttested(resp!!).credentialId
        val (status, _) = call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = false, exclude = listOf(id)))
        assertEquals(CtapStatus.ERR_CREDENTIAL_EXCLUDED, status)
        assertEquals(1, store.list().size)
    }

    @Test
    fun noCredentialsForRp() {
        val (status, _) = call(CtapCommand.GET_ASSERTION, linkedMapOf(1L to "nobody.example", 2L to clientDataHash))
        assertEquals(CtapStatus.ERR_NO_CREDENTIALS, status)
    }

    @Test
    fun deniedPolicyBlocksRegistrationAndCreatesNothing() {
        val denying = FakePolicy.denied()
        val a = Ctap2Authenticator(store, denying, { config }, "test")
        val resp = a.process(byteArrayOf(CtapCommand.MAKE_CREDENTIAL.toByte()) + Cbor.encode(makeCredentialParams(rk = true)))
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, resp[0].toInt())
        assertTrue(store.list().isEmpty())
    }

    @Test
    fun silentAssertionHasNoUpUvFlagsAndDoesNotConsumeAuthorization() {
        val (_, resp) = call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = false))
        val id = parseAttested(resp!!).credentialId
        policy.completed.clear()
        val (status, assertion) = call(
            CtapCommand.GET_ASSERTION,
            linkedMapOf(
                1L to "example.com",
                2L to clientDataHash,
                3L to listOf(linkedMapOf("id" to id, "type" to "public-key")),
                5L to linkedMapOf("up" to false)
            )
        )
        assertEquals(CtapStatus.OK, status)
        assertEquals(0, (assertion!![2L] as ByteArray)[32].toInt())
        assertEquals("silent assertion completes without consuming", listOf(false), policy.completed.map { it.second })
        assertFalse(policy.requests.last().requireUserPresence)
    }

    @Test
    fun successfulOperationsAreReportedAsCompleted() {
        call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = true))
        assertEquals(1, policy.completed.size)
        assertTrue(policy.completed[0].second)
        assertEquals(CtapOperation.MAKE_CREDENTIAL, policy.completed[0].first.operation)
        assertTrue(events.any { it.command == CtapCommand.MAKE_CREDENTIAL && it.isSuccess && it.rpId == "example.com" })
    }

    @Test
    fun zeroLengthPinAuthProbeReturnsPinNotSet() {
        val (status, _) = call(
            CtapCommand.MAKE_CREDENTIAL,
            makeCredentialParams(rk = false, extra = mapOf(8L to ByteArray(0), 9L to 1L))
        )
        assertEquals(CtapStatus.ERR_PIN_NOT_SET, status)
        assertTrue(store.list().isEmpty())
    }

    @Test
    fun unsupportedAlgorithmIsRejected() {
        val params = makeCredentialParams(rk = false).toMutableMap()
        params[4L] = listOf(linkedMapOf("alg" to -257L, "type" to "public-key"))
        val (status, _) = call(CtapCommand.MAKE_CREDENTIAL, params)
        assertEquals(CtapStatus.ERR_UNSUPPORTED_ALGORITHM, status)
    }

    @Test
    fun missingParametersAndBadCbor() {
        val (s1, _) = call(CtapCommand.MAKE_CREDENTIAL, linkedMapOf(1L to clientDataHash))
        assertEquals(CtapStatus.ERR_MISSING_PARAMETER, s1)
        val r = authenticator.process(byteArrayOf(CtapCommand.GET_ASSERTION.toByte(), 0xA1.toByte()))
        assertEquals(CtapStatus.ERR_INVALID_CBOR, r[0].toInt())
        val (s3, _) = call(0x55)
        assertEquals(CtapStatus.ERR_INVALID_COMMAND, s3)
    }

    @Test
    fun resetIsDeniedUnlessEnabled() {
        call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = true))
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, call(CtapCommand.RESET).first)
        assertEquals(1, store.list().size)
        config = config.copy(allowReset = true)
        assertEquals(CtapStatus.OK, call(CtapCommand.RESET).first)
        assertTrue(store.list().isEmpty())
    }

    @Test
    fun signCounterIncreasesMonotonically() {
        val (_, resp) = call(CtapCommand.MAKE_CREDENTIAL, makeCredentialParams(rk = true))
        val id = parseAttested(resp!!).credentialId
        var last = 0
        repeat(3) {
            val (_, a) = call(
                CtapCommand.GET_ASSERTION,
                linkedMapOf(1L to "example.com", 2L to clientDataHash, 3L to listOf(linkedMapOf("id" to id, "type" to "public-key")))
            )
            val ad = a!![2L] as ByteArray
            val counter = ((ad[33].toInt() and 0xFF) shl 24) or ((ad[34].toInt() and 0xFF) shl 16) or
                ((ad[35].toInt() and 0xFF) shl 8) or (ad[36].toInt() and 0xFF)
            assertTrue(counter > last)
            last = counter
        }
    }
}
