// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.CtapTestClient
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.FakePolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** credProtect 拡張 (DD-01 §12.3)。 */
class CredProtectTest {
    private val store = InMemoryCredentialStore()
    private val policy = FakePolicy()
    private val authenticator = Ctap2Authenticator(store, policy, { AuthenticatorConfig(ByteArray(16) { 3 }) }, "test")
    private val client = CtapTestClient(authenticator)
    private val cdh = TestCrypto.sha256("client-data".toByteArray())
    private val silent = mapOf("up" to false)

    private fun register(level: Long?, userId: Byte = 1, rk: Boolean = true): ByteArray {
        val ext = level?.let { mapOf<String, Any>("credProtect" to it) }
        val (status, resp) = client.call(
            CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, userId = byteArrayOf(userId), rk = rk, extensions = ext)
        )
        assertEquals(CtapStatus.OK, status)
        return CtapTestClient.credentialId(resp!!)
    }

    private fun assertion(allowIds: List<ByteArray>? = null, options: Map<String, Any>? = null) =
        client.call(CtapCommand.GET_ASSERTION, client.getAssertionParams(cdh, allowIds = allowIds, options = options))

    @Test
    fun levelIsStoredAndReportedOnlyWhenRequested() {
        val (_, resp) = client.call(
            CtapCommand.MAKE_CREDENTIAL,
            client.makeCredentialParams(cdh, extensions = mapOf("credProtect" to 2L, "hmac-secret" to true))
        )
        assertEquals(mapOf("credProtect" to 2L, "hmac-secret" to true), CtapTestClient.extensions(resp!![2L] as ByteArray))
        assertEquals(2, store.list().single().credProtect)

        val (_, plain) = client.call(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, userId = byteArrayOf(2)))
        assertNull(CtapTestClient.extensions(plain!![2L] as ByteArray))
        assertEquals(1, store.list().single { it.user.id[0] == 2.toByte() }.credProtect)

        val bad = { v: Any -> client.status(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, userId = byteArrayOf(3), extensions = mapOf("credProtect" to v))) }
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, bad(0L))
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, bad(4L))
        assertEquals(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, bad("high"))
    }

    @Test
    fun levelThreeRequiresUserVerification() {
        val id = register(3)
        // silent assertion (UV なし) では allowList があっても使えない
        assertEquals(CtapStatus.ERR_NO_CREDENTIALS, assertion(listOf(id), silent).first)
        assertEquals(CtapStatus.ERR_NO_CREDENTIALS, assertion(options = silent).first)
        // UV なしの認可でも使えない
        policy.result = AuthorizationResult.Granted(userPresent = true, userVerified = false)
        assertEquals(CtapStatus.ERR_NO_CREDENTIALS, assertion(listOf(id)).first)
        policy.result = AuthorizationResult.Granted(userPresent = true, userVerified = true)
        assertEquals(CtapStatus.OK, assertion(listOf(id)).first)
        assertEquals(CtapStatus.OK, assertion().first)
    }

    @Test
    fun levelTwoIsHiddenFromDiscoverableSearchWithoutUserVerification() {
        val id = register(2)
        assertEquals(CtapStatus.ERR_NO_CREDENTIALS, assertion(options = silent).first)
        assertEquals(CtapStatus.OK, assertion(listOf(id), silent).first)
        assertEquals(CtapStatus.OK, assertion().first)
    }

    @Test
    fun levelOneIsNeverFiltered() {
        val id = register(1)
        assertEquals(CtapStatus.OK, assertion(options = silent).first)
        assertEquals(CtapStatus.OK, assertion(listOf(id), silent).first)
    }

    @Test
    fun filteringKeepsOtherCredentialsInTheEnumeration() {
        register(3, userId = 1)
        register(1, userId = 2)
        val (status, resp) = assertion(options = silent)
        assertEquals(CtapStatus.OK, status)
        assertNull(resp!![5L]) // 1 件に絞られる (numberOfCredentials なし)
        assertEquals(2.toByte(), ((resp[4L] as Map<*, *>)["id"] as ByteArray)[0])
    }

    @Test
    fun excludeListIgnoresLevelThreeCredentialsWithoutUserVerification() {
        val id = register(3)
        val params = client.makeCredentialParams(cdh, userId = byteArrayOf(9)) + (5L to listOf(linkedMapOf("id" to id, "type" to "public-key")))
        policy.result = AuthorizationResult.Granted(userPresent = true, userVerified = false)
        assertEquals(CtapStatus.OK, client.status(CtapCommand.MAKE_CREDENTIAL, params))
        policy.result = AuthorizationResult.Granted(userPresent = true, userVerified = true)
        assertEquals(CtapStatus.ERR_CREDENTIAL_EXCLUDED, client.status(CtapCommand.MAKE_CREDENTIAL, params))
    }
}
