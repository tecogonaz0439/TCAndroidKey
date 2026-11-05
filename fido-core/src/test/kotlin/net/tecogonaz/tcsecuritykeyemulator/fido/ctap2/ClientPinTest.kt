// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.CtapTestClient
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.FakePolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** clientPIN (PIN の設定・変更・照合、PIN によるトークンの発行。DD-01 §13)。 */
class ClientPinTest {
    private val store = InMemoryCredentialStore()
    private val pinStore = InMemoryPinStore()
    private val policy = FakePolicy()
    private var config = AuthenticatorConfig(ByteArray(16) { 5 })
    private val authenticator = Ctap2Authenticator(store, policy, { config }, "test", pinStore = pinStore)
    private val client = CtapTestClient(authenticator)
    private val cdh = TestCrypto.sha256("client-data".toByteArray())
    private val pin = "1234"

    private fun clientPinOption(): Any? = (client.call(CtapCommand.GET_INFO).second!![4L] as Map<*, *>)["clientPin"]

    @Test
    fun setPinIsReportedInGetInfoAndCannotBeSetTwice() {
        for (version in listOf(1L, 2L)) {
            pinStore.clear()
            assertEquals(false, clientPinOption())
            policy.requests.clear()
            policy.completed.clear()
            assertEquals(CtapStatus.OK, client.setPin(version, pin))
            assertEquals(true, clientPinOption())
            assertEquals(8L to false, client.pinRetries(version))
            // 受付ゲートの許可を得るが、ワンタイムは消費しない
            assertEquals(listOf(CtapOperation.CLIENT_PIN), policy.requests.map { it.operation })
            assertTrue(policy.completed.none { it.second })
            assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, client.setPin(version, "5678"))
        }
    }

    @Test
    fun newPinsAreValidated() {
        assertEquals(CtapStatus.ERR_PIN_POLICY_VIOLATION, client.setPin(2, "123"))
        assertEquals(CtapStatus.ERR_PIN_POLICY_VIOLATION, client.setPin(2, "", padded = ByteArray(64) { 0x31 })) // 64 バイト (63 超)
        assertEquals(CtapStatus.ERR_PIN_POLICY_VIOLATION, client.setPin(2, "", padded = byteArrayOf(-1, -2, -3, -4).copyOf(64)))
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, client.setPin(2, "", padded = client.padPin("1234").copyOf(48)))
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, client.setPin(2, pin, tamperAuth = true))
        assertEquals(CtapStatus.ERR_MISSING_PARAMETER, client.status(CtapCommand.CLIENT_PIN, linkedMapOf(1L to 2L, 2L to 3L)))
        assertEquals(false, clientPinOption())
        // 4 コードポイント (12 バイト) は受け付ける
        assertEquals(CtapStatus.OK, client.setPin(2, "あいうえ"))
        assertEquals(CtapStatus.OK, client.requestPinToken(2, "あいうえ").first)
    }

    @Test
    fun pinTokensAuthorizeOperations() {
        assertEquals(CtapStatus.ERR_PIN_NOT_SET, client.requestPinToken(1, pin).first)
        client.setPin(2, pin)
        for (version in listOf(1L, 2L)) {
            // getPinToken (0x05): 権限は mc・ga
            val token = client.requestPinToken(version, pin).second!!
            val (status, mc) = client.call(
                CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, userId = byteArrayOf(version.toByte()), token = token)
            )
            assertEquals(CtapStatus.OK, status)
            assertTrue((mc!![2L] as ByteArray)[32].toInt() and AuthDataFlags.UV != 0)
        }
        val withPermissions = client.status(
            CtapCommand.CLIENT_PIN, linkedMapOf(1L to 2L, 2L to 5L, 3L to client.keyAgreement(2), 6L to ByteArray(32), 9L to 1L)
        )
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, withPermissions)

        // getPinUvAuthTokenUsingPinWithPermissions (0x09): cm 権限で資格情報の管理
        val cm = client.requestPinToken(2, pin, ClientPin.PERMISSION_CM.toLong()).second!!
        val (s, metadata) = client.call(
            CtapCommand.CREDENTIAL_MANAGEMENT, linkedMapOf(1L to 1L, 3L to 2L, 4L to cm.authenticate(byteArrayOf(1)))
        )
        assertEquals(CtapStatus.OK, s)
        assertEquals(2L, metadata!![1L])
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, client.requestPinToken(2, pin, 0L).first)
        assertEquals(CtapStatus.ERR_UNAUTHORIZED_PERMISSION, client.requestPinToken(2, pin, 0x10L).first)
        assertEquals(8L, client.pinRetries().first)
    }

    @Test
    fun threeConsecutiveMismatchesRequireAPowerCycle() {
        client.setPin(2, pin)
        assertEquals(CtapStatus.ERR_PIN_INVALID, client.requestPinToken(2, "0000").first)
        assertEquals(7L to false, client.pinRetries())
        assertEquals(CtapStatus.ERR_PIN_INVALID, client.requestPinToken(1, "0000").first)
        assertEquals(CtapStatus.ERR_PIN_AUTH_BLOCKED, client.requestPinToken(2, "0000").first)
        assertEquals(5L to true, client.pinRetries())
        // 正しい PIN でも、セッションが変わるまで照合しない (回数も減らさない)
        assertEquals(CtapStatus.ERR_PIN_AUTH_BLOCKED, client.requestPinToken(2, pin).first)
        assertEquals(5L, client.pinRetries().first)

        authenticator.resetSession() // NFC の再接続 (電源の再投入) に相当
        assertEquals(false, client.pinRetries().second)
        assertEquals(CtapStatus.OK, client.requestPinToken(2, pin).first)
        assertEquals(8L, client.pinRetries().first)
    }

    @Test
    fun eightMismatchesBlockThePinUntilReset() {
        client.setPin(2, pin)
        val results = (1..8).map { i ->
            if (i % 3 == 1) authenticator.resetSession()
            client.requestPinToken(2, "0000").first
        }
        assertEquals(CtapStatus.ERR_PIN_BLOCKED, results.last())
        assertEquals(0L, client.pinRetries().first)
        authenticator.resetSession()
        assertEquals(CtapStatus.ERR_PIN_BLOCKED, client.requestPinToken(2, pin).first)
        assertEquals(CtapStatus.ERR_PIN_BLOCKED, client.changePin(2, pin, "5678"))

        config = config.copy(allowReset = true)
        assertEquals(CtapStatus.OK, client.status(CtapCommand.RESET))
        assertEquals(false, clientPinOption())
        assertEquals(CtapStatus.OK, client.setPin(2, "5678"))
    }

    @Test
    fun changePinReplacesThePinAndRevokesTokens() {
        assertEquals(CtapStatus.ERR_PIN_NOT_SET, client.changePin(2, pin, "5678"))
        client.setPin(2, pin)
        val oldToken = client.requestPinToken(2, pin, ClientPin.PERMISSION_GA.toLong()).second!!
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, client.changePin(2, pin, "5678", tamperAuth = true))
        assertEquals(CtapStatus.ERR_PIN_INVALID, client.changePin(2, "0000", "5678"))
        assertEquals(CtapStatus.ERR_PIN_POLICY_VIOLATION, client.changePin(1, pin, "56"))
        assertEquals(CtapStatus.OK, client.changePin(1, pin, "5678"))
        assertEquals(CtapStatus.ERR_PIN_INVALID, client.requestPinToken(2, pin).first)
        assertEquals(CtapStatus.OK, client.requestPinToken(2, "5678").first)
        client.call(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh))
        val use = client.status(
            CtapCommand.GET_ASSERTION, client.getAssertionParams(cdh, options = mapOf("up" to false), token = oldToken)
        )
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, use)
    }

    @Test
    fun zeroLengthProbeReportsPinInvalidOncePinIsSet() {
        val probe = client.makeCredentialParams(cdh) + (8L to ByteArray(0)) + (9L to 2L)
        assertEquals(CtapStatus.ERR_PIN_NOT_SET, client.status(CtapCommand.MAKE_CREDENTIAL, probe))
        client.setPin(2, pin)
        assertEquals(CtapStatus.ERR_PIN_INVALID, client.status(CtapCommand.MAKE_CREDENTIAL, probe))
    }

    @Test
    fun pinChecksRequireTheGateAndDoNotSpendRetriesWhenDenied() {
        client.setPin(2, pin)
        policy.result = AuthorizationResult.Denied(CtapStatus.ERR_OPERATION_DENIED, "denied")
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, client.requestPinToken(2, "0000").first)
        assertEquals(CtapStatus.ERR_OPERATION_DENIED, client.changePin(2, "0000", "5678"))
        policy.result = AuthorizationResult.Granted(userPresent = true, userVerified = true)
        assertEquals(8L, client.pinRetries().first)
    }

    @Test
    fun builtInUvStillWorksWithAPinSet() {
        client.setPin(2, pin)
        val token = client.uvToken(2, (ClientPin.PERMISSION_MC or ClientPin.PERMISSION_GA).toLong())
        assertEquals(CtapStatus.OK, client.status(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, token = token)))
        assertEquals(CtapStatus.OK, client.status(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, userId = byteArrayOf(2), uv = true)))
    }

    @Test
    fun pinStoreIsSharedAcrossTransports() {
        val other = CtapTestClient(Ctap2Authenticator(store, policy, { config }, "other", pinStore = pinStore))
        client.setPin(2, pin)
        assertEquals(true, (other.call(CtapCommand.GET_INFO).second!![4L] as Map<*, *>)["clientPin"])
        assertEquals(CtapStatus.ERR_PIN_INVALID, other.requestPinToken(2, "0000").first)
        assertEquals(7L, client.pinRetries().first)
        assertEquals(CtapStatus.OK, other.requestPinToken(2, pin).first)
    }

    @Test
    fun unreadablePinStorageIsTreatedAsSetAndRejectsPinOperations() {
        val unavailable = object : PinStore {
            override fun status() = PinStatus(PinStatus.State.UNAVAILABLE, 0)
            override val revision: Long = 0
            override fun setPin(pinHash: ByteArray): Boolean = error("unavailable")
            override fun check(pinHash: ByteArray): PinCheck = error("unavailable")
            override fun changePin(pinHash: ByteArray) = error("unavailable")
            override fun clear() {}
        }
        val c = CtapTestClient(Ctap2Authenticator(store, policy, { config }, "test", pinStore = unavailable))
        assertEquals(true, (c.call(CtapCommand.GET_INFO).second!![4L] as Map<*, *>)["clientPin"])
        assertEquals(CtapStatus.ERR_OTHER, c.status(CtapCommand.CLIENT_PIN, linkedMapOf(1L to 2L, 2L to 1L)))
        assertEquals(CtapStatus.ERR_OTHER, c.setPin(2, pin))
        assertEquals(CtapStatus.ERR_OTHER, c.requestPinToken(2, pin).first)
        val probe = c.makeCredentialParams(cdh) + (8L to ByteArray(0)) + (9L to 2L)
        assertEquals(CtapStatus.ERR_PIN_INVALID, c.status(CtapCommand.MAKE_CREDENTIAL, probe))
        assertNull(c.requestPinToken(2, pin).second)
    }

    @Test
    fun tokensOnOtherTransportsAreRevokedByResetPinChangesAndClearing() {
        val other = CtapTestClient(Ctap2Authenticator(store, policy, { config }, "other", pinStore = pinStore))
        val mc = ClientPin.PERMISSION_MC.toLong()
        var user: Byte = 0
        fun register(token: CtapTestClient.Token) =
            client.status(CtapCommand.MAKE_CREDENTIAL, client.makeCredentialParams(cdh, userId = byteArrayOf(++user), token = token))

        // 他のトランスポートの GetInfo・鍵交換はトークンを無効にしない
        val control = client.uvToken(2, mc)
        other.call(CtapCommand.GET_INFO)
        other.keyAgreement(2)
        assertEquals(CtapStatus.OK, register(control))

        // 他のトランスポートでの PIN の設定・変更
        val beforeSet = client.uvToken(2, mc)
        assertEquals(CtapStatus.OK, other.setPin(2, pin))
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, register(beforeSet))
        val pinToken = client.requestPinToken(2, pin, mc).second!!
        assertEquals(CtapStatus.OK, other.changePin(2, pin, "5678"))
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, register(pinToken))

        // アプリでの PIN の消去・全削除
        val beforeClear = client.uvToken(2, mc)
        pinStore.clear()
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, register(beforeClear))

        // 他のトランスポートでの Reset (PIN 未設定でも内蔵 UV のトークンを無効にする)
        config = config.copy(allowReset = true)
        val beforeReset = client.uvToken(2, mc)
        assertEquals(CtapStatus.OK, other.status(CtapCommand.RESET))
        assertEquals(CtapStatus.ERR_PIN_AUTH_INVALID, register(beforeReset))
    }

    @Test
    fun getPinRetriesDoesNotRequireAProtocol() {
        client.setPin(2, pin)
        val (status, resp) = client.call(CtapCommand.CLIENT_PIN, linkedMapOf(2L to 1L))
        assertEquals(CtapStatus.OK, status)
        assertEquals(8L, resp!![3L])
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, client.status(CtapCommand.CLIENT_PIN, linkedMapOf(1L to 3L, 2L to 1L)))
        // その他のサブコマンドは従来どおり必須
        assertEquals(CtapStatus.ERR_MISSING_PARAMETER, client.status(CtapCommand.CLIENT_PIN, linkedMapOf(2L to 2L)))
    }

    @Test
    fun protocolOneAcceptsPaddingLongerThan64Bytes() {
        // CTAP 2.0 は「64 バイト以上」、CTAP 2.1 は 64 バイトちょうど
        assertEquals(CtapStatus.ERR_INVALID_PARAMETER, client.setPin(2, "", padded = client.padPin(pin).copyOf(80)))
        assertEquals(CtapStatus.OK, client.setPin(1, "", padded = client.padPin(pin).copyOf(80)))
        assertEquals(CtapStatus.OK, client.requestPinToken(2, pin).first)
    }
}
