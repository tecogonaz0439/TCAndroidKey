// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.CtapTestClient
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.FakePolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** authenticatorCredentialManagement (DD-01 §12.4)。 */
class CredentialManagementTest {
    private val store = InMemoryCredentialStore()
    private val policy = FakePolicy()
    private var now = 5_000_000L
    private val authenticator = Ctap2Authenticator(
        store, policy, { AuthenticatorConfig(ByteArray(16) { 4 }) }, "test", monotonicClock = { now }
    )
    private val client = CtapTestClient(authenticator)
    private val cdh = TestCrypto.sha256("client-data".toByteArray())
    private val cm = ClientPin.PERMISSION_CM.toLong()

    private fun register(rpId: String, userId: Byte, rk: Boolean = true, credProtect: Long? = null): ByteArray {
        val ext = credProtect?.let { mapOf<String, Any>("credProtect" to it) }
        val (status, resp) = client.call(
            CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, rpId, byteArrayOf(userId), rk, ext)
        )
        assertEquals(CtapStatus.OK, status)
        return CtapTestClient.credentialId(resp!!)
    }

    /** credentialManagement の要求。[token] があれば pinUvAuthParam を付ける。 */
    private fun cm(sub: Long, params: Map<Long, Any>? = null, token: CtapTestClient.Token? = null, version: Long? = token?.version): Pair<Int, Map<*, *>?> {
        val p = linkedMapOf<Long, Any?>(1L to sub)
        if (params != null) p[2L] = params
        if (version != null) p[3L] = version
        if (token != null) {
            val message = byteArrayOf(sub.toByte()) + (if (params != null) Cbor.encode(params) else ByteArray(0))
            p[4L] = token.authenticate(message)
        }
        return client.call(CtapCommand.CREDENTIAL_MANAGEMENT, p)
    }

    private fun setup(): Map<String, ByteArray> = linkedMapOf(
        "a1" to register("a.example", 1),
        "a2" to register("a.example", 2, credProtect = 2),
        "b1" to register("b.example", 3),
        "c-nd" to register("c.example", 4, rk = false)
    )

    @Test
    fun metadataCountsDiscoverableCredentials() {
        setup()
        val token = client.uvToken(2, cm)
        val (status, resp) = cm(1, token = token)
        assertEquals(CtapStatus.OK, status)
        assertEquals(3L, resp!![1L])
        assertEquals((CredentialManagement.DISCOVERABLE_CAPACITY - 3).toLong(), resp[2L])
    }

    @Test
    fun requestsWithoutAValidCmTokenAreRejected() {
        setup()
        val token = client.uvToken(2, cm)
        assertEquals(CtapStatus.ERR_PUAT_REQUIRED, cm(1, version = 2).first)
        assertEquals(CtapStatus.ERR_MISSING_PARAMETER, client.status(CtapCommand.CREDENTIAL_MANAGEMENT, linkedMapOf(1L to 1L, 4L to token.authenticate(byteArrayOf(1)))))
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, cm(1, token = token, version = 3).first)
        // Protocol 2 のトークンを Protocol 1 として送ると検証できない
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, cm(1, token = token, version = 1).first)
        // 認証対象の不一致 (サブコマンドの取り違え)
        val p = linkedMapOf<Long, Any?>(1L to 2L, 3L to 2L, 4L to token.authenticate(byteArrayOf(1)))
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, client.status(CtapCommand.CREDENTIAL_MANAGEMENT, p))
        // cm 権限のないトークン
        val mcGa = client.uvToken(2, (ClientPin.PERMISSION_MC or ClientPin.PERMISSION_GA).toLong())
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, cm(1, token = mcGa).first)
        // RP ID に結び付いたトークンでは件数の取得・RP の列挙はできない
        val bound = client.uvToken(2, cm, "a.example")
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, cm(1, token = bound).first)
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, cm(2, token = bound).first)
        // 未対応のサブコマンド
        assertEquals(CtapStatus.ERR_INVALID_SUBCOMMAND, cm(8, token = client.uvToken(2, cm)).first)
    }

    @Test
    fun rpsAreEnumeratedInOrder() {
        setup()
        val token = client.uvToken(1, cm)
        val (s1, first) = cm(2, token = token)
        assertEquals(CtapStatus.OK, s1)
        assertEquals(2L, first!![5L])
        assertEquals(mapOf("id" to "a.example", "name" to "RP a.example"), first[3L])
        assertArrayEquals(Ctap2Authenticator.rpIdHash("a.example"), first[4L] as ByteArray)
        val (s2, second) = cm(3)
        assertEquals(CtapStatus.OK, s2)
        assertEquals("b.example", (second!![3L] as Map<*, *>)["id"])
        assertNull(second[5L])
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, cm(3).first)
    }

    @Test
    fun credentialsOfAnRpAreEnumerated() {
        val ids = setup()
        val token = client.uvToken(2, cm)
        val params = mapOf<Long, Any>(1L to Ctap2Authenticator.rpIdHash("a.example"))
        val (s1, first) = cm(4, params, token)
        assertEquals(CtapStatus.OK, s1)
        assertEquals(2L, first!![9L])
        // 作成日時の新しい順
        assertArrayEquals(ids["a2"], (first[7L] as Map<*, *>)["id"] as ByteArray)
        assertEquals(mapOf("id" to byteArrayOf(2).toList(), "name" to "user2", "displayName" to "User 2"),
            (first[6L] as Map<*, *>).mapValues { (_, v) -> if (v is ByteArray) v.toList() else v })
        assertEquals(2L, first[0x0AL])
        assertEquals(-7L, (first[8L] as Map<*, *>)[3L])
        val (s2, second) = cm(5)
        assertEquals(CtapStatus.OK, s2)
        assertArrayEquals(ids["a1"], (second!![7L] as Map<*, *>)["id"] as ByteArray)
        assertEquals(1L, second[0x0AL])

        assertEquals(CtapStatus.ERR_NO_CREDENTIALS, cm(4, mapOf(1L to Ctap2Authenticator.rpIdHash("c.example")), token).first)
        assertEquals(CtapStatus.ERR_MISSING_PARAMETER, cm(4, null, token).first)
        // RP ID に結び付いたトークンは、その RP のみ列挙できる
        val bound = client.uvToken(2, cm, "b.example")
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, cm(4, params, bound).first)
        assertEquals(CtapStatus.OK, cm(4, mapOf(1L to Ctap2Authenticator.rpIdHash("b.example")), bound).first)
    }

    @Test
    fun enumerationStateIsDiscardedByOtherCommandsTimeoutAndRevocation() {
        setup()
        val token = client.uvToken(2, cm)
        assertEquals(CtapStatus.OK, cm(2, token = token).first)
        client.call(CtapCommand.GET_INFO)
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, cm(3).first)

        assertEquals(CtapStatus.OK, cm(2, token = token).first)
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, cm(5).first) // 別の種類の続き

        assertEquals(CtapStatus.OK, cm(2, token = token).first)
        now += CredentialManagement.STATE_TIMEOUT_MS + 1
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, cm(3).first)

        assertEquals(CtapStatus.OK, cm(2, token = token).first)
        policy.leaseValid = false
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, cm(3).first)
        policy.leaseValid = true

        assertEquals(CtapStatus.OK, cm(2, token = token).first)
        authenticator.resetSession()
        assertEquals(CtapStatus.ERR_NOT_ALLOWED, cm(3).first)
    }

    @Test
    fun discoverableCredentialsCanBeDeleted() {
        val ids = setup()
        val token = client.uvToken(2, cm)
        fun delete(id: ByteArray, t: CtapTestClient.Token = token) =
            cm(6, mapOf(2L to linkedMapOf("id" to id, "type" to "public-key")), t).first
        assertEquals(CtapStatus.OK, delete(ids.getValue("b1")))
        assertFalse(store.list().any { it.id.contentEquals(ids["b1"]) })
        assertEquals(CtapStatus.ERR_NO_CREDENTIALS, delete(ids.getValue("b1")))
        assertEquals(CtapStatus.ERR_NO_CREDENTIALS, delete(ids.getValue("c-nd"))) // non-discoverable は対象外
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, delete(ids.getValue("a1"), client.uvToken(2, cm, "b.example")))
        assertEquals(CtapStatus.OK, delete(ids.getValue("a1"), client.uvToken(2, cm, "a.example")))
    }

    @Test
    fun userInformationCanBeUpdated() {
        val ids = setup()
        val token = client.uvToken(2, cm)
        val descriptor = linkedMapOf("id" to ids.getValue("a1"), "type" to "public-key")
        val update = mapOf<Long, Any>(2L to descriptor, 3L to linkedMapOf("id" to byteArrayOf(1), "name" to "renamed"))
        assertEquals(CtapStatus.OK, cm(7, update, token).first)
        val updated = store.list().single { it.id.contentEquals(ids["a1"]) }.user
        assertEquals("renamed", updated.name)
        assertNull(updated.displayName) // 指定のない displayName は削除する

        val wrongUser = mapOf<Long, Any>(2L to descriptor, 3L to linkedMapOf("id" to byteArrayOf(9), "name" to "x"))
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, cm(7, wrongUser, token).first)
        assertEquals(CtapStatus.ERR_MISSING_PARAMETER, cm(7, mapOf(2L to descriptor), token).first)
    }

    @Test
    fun everyOperationIsAuthorizedByTheGateWithoutConsumption() {
        setup()
        val token = client.uvToken(2, cm)
        policy.requests.clear()
        policy.completed.clear()
        assertEquals(CtapStatus.OK, cm(1, token = token).first)
        assertEquals(CtapStatus.OK, cm(2, token = token).first)
        assertEquals(CtapStatus.OK, cm(3).first) // 続きは開始時の認可で継続する
        assertEquals(listOf(CtapOperation.CREDENTIAL_MANAGEMENT, CtapOperation.CREDENTIAL_MANAGEMENT), policy.requests.map { it.operation })
        assertTrue(policy.completed.none { it.second })

        policy.result = AuthorizationResult.Denied(CtapStatus.ERR_OPERATION_DENIED, "denied")
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, cm(1, token = token).first)
    }

    @Test
    fun enumeratingWithNoCredentialsReturnsNoCredentials() {
        val token = client.uvToken(2, cm)
        assertEquals(CtapStatus.ERR_NO_CREDENTIALS, cm(2, token = token).first)
        assertEquals(0L, cm(1, token = token).second!![1L])
    }
}
