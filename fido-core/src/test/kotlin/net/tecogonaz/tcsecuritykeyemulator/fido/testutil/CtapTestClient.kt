// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.testutil

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Ctap2Authenticator
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.CtapCommand
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.CtapStatus
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.PinStore
import org.junit.Assert.assertEquals

/** テスト用の CTAP クライアント (プラットフォーム)。CBOR の組み立てと pinUvAuthToken の取得を行う。 */
class CtapTestClient(private val authenticator: Ctap2Authenticator) {
    /** pinUvAuthToken と、それを使う PIN/UV Auth Protocol (プラットフォーム側)。 */
    class Token(val platform: TestPlatform, val token: ByteArray) {
        val version: Long get() = platform.version.toLong()

        fun authenticate(message: ByteArray): ByteArray = platform.authenticate(token, message)
    }

    fun call(cmd: Int, params: Map<Long, Any?>? = null): Pair<Int, Map<*, *>?> {
        val req = if (params == null) byteArrayOf(cmd.toByte()) else byteArrayOf(cmd.toByte()) + Cbor.encode(params)
        val resp = authenticator.process(req)
        val body = if (resp.size > 1) Cbor.decode(resp, 1, resp.size - 1) as Map<*, *> else null
        return (resp[0].toInt() and 0xFF) to body
    }

    fun status(cmd: Int, params: Map<Long, Any?>? = null): Int = call(cmd, params).first

    fun keyAgreement(version: Long): Map<*, *> {
        val (status, resp) = call(CtapCommand.CLIENT_PIN, linkedMapOf(1L to version, 2L to 2L))
        assertEquals(CtapStatus.OK, status)
        return resp!![1L] as Map<*, *>
    }

    /** getPinUvAuthTokenUsingUvWithPermissions の要求を送り、(ステータス, 復号したトークン) を返す。 */
    fun requestUvToken(version: Long, permissions: Long, rpId: String? = null): Pair<Int, Token?> {
        val platform = TestPlatform(version.toInt())
        val secret = platform.sharedSecret(keyAgreement(version))
        val params = linkedMapOf<Long, Any?>(1L to version, 2L to 6L, 3L to platform.keyAgreement, 9L to permissions)
        if (rpId != null) params[0x0AL] = rpId
        val (status, resp) = call(CtapCommand.CLIENT_PIN, params)
        if (status != CtapStatus.OK) return status to null
        return status to Token(platform, platform.decrypt(secret, resp!![2L] as ByteArray))
    }

    fun uvToken(version: Long, permissions: Long, rpId: String? = null): Token {
        val (status, token) = requestUvToken(version, permissions, rpId)
        assertEquals(CtapStatus.OK, status)
        return token!!
    }

    // ---------------------------------------------------------------- clientPIN

    /** PIN を 64 バイトに 0x00 でパディングする (CTAP 2.1 §6.5.5.5)。 */
    fun padPin(pin: String): ByteArray = pin.toByteArray(Charsets.UTF_8).copyOf(64)

    /** setPIN。[padded] でパディング済みの値 (不正な長さ・内容の試験用) を直接指定できる。 */
    fun setPin(version: Long, pin: String, padded: ByteArray = padPin(pin), tamperAuth: Boolean = false): Int {
        val platform = TestPlatform(version.toInt())
        val secret = platform.sharedSecret(keyAgreement(version))
        val newPinEnc = platform.encrypt(secret, padded)
        val auth = platform.authenticate(secret, newPinEnc).also { if (tamperAuth) it[0] = (it[0] + 1).toByte() }
        return status(
            CtapCommand.CLIENT_PIN,
            linkedMapOf(1L to version, 2L to 3L, 3L to platform.keyAgreement, 4L to auth, 5L to newPinEnc)
        )
    }

    fun changePin(version: Long, current: String, newPin: String, tamperAuth: Boolean = false): Int {
        val platform = TestPlatform(version.toInt())
        val secret = platform.sharedSecret(keyAgreement(version))
        val pinHashEnc = platform.encrypt(secret, PinStore.hash(current.toByteArray(Charsets.UTF_8)))
        val newPinEnc = platform.encrypt(secret, padPin(newPin))
        val auth = platform.authenticate(secret, newPinEnc + pinHashEnc).also { if (tamperAuth) it[0] = (it[0] + 1).toByte() }
        return status(
            CtapCommand.CLIENT_PIN,
            linkedMapOf(1L to version, 2L to 4L, 3L to platform.keyAgreement, 4L to auth, 5L to newPinEnc, 6L to pinHashEnc)
        )
    }

    /**
     * PIN によるトークンの取得。[permissions] が null なら getPinToken (0x05)、指定すれば
     * getPinUvAuthTokenUsingPinWithPermissions (0x09)。
     */
    fun requestPinToken(version: Long, pin: String, permissions: Long? = null, rpId: String? = null): Pair<Int, Token?> {
        val platform = TestPlatform(version.toInt())
        val secret = platform.sharedSecret(keyAgreement(version))
        val pinHashEnc = platform.encrypt(secret, PinStore.hash(pin.toByteArray(Charsets.UTF_8)))
        val params = linkedMapOf<Long, Any?>(
            1L to version, 2L to (if (permissions == null) 5L else 9L), 3L to platform.keyAgreement, 6L to pinHashEnc
        )
        if (permissions != null) params[9L] = permissions
        if (rpId != null) params[0x0AL] = rpId
        val (status, resp) = call(CtapCommand.CLIENT_PIN, params)
        if (status != CtapStatus.OK) return status to null
        return status to Token(platform, platform.decrypt(secret, resp!![2L] as ByteArray))
    }

    /** getPINRetries の (pinRetries, powerCycleState)。 */
    fun pinRetries(version: Long = 2): Pair<Long, Boolean> {
        val (status, resp) = call(CtapCommand.CLIENT_PIN, linkedMapOf(1L to version, 2L to 1L))
        assertEquals(CtapStatus.OK, status)
        return (resp!![3L] as Long) to (resp[4L] as Boolean)
    }

    fun makeCredentialParams(
        clientDataHash: ByteArray,
        rpId: String = "example.com",
        userId: ByteArray = byteArrayOf(1),
        rk: Boolean = true,
        extensions: Map<String, Any>? = null,
        token: Token? = null,
        uv: Boolean = false
    ): Map<Long, Any?> {
        val p = linkedMapOf<Long, Any?>(
            1L to clientDataHash,
            2L to linkedMapOf("id" to rpId, "name" to "RP $rpId"),
            3L to linkedMapOf("id" to userId, "name" to "user${userId[0]}", "displayName" to "User ${userId[0]}"),
            4L to listOf(linkedMapOf("alg" to -7L, "type" to "public-key"))
        )
        if (extensions != null) p[6L] = extensions
        p[7L] = if (uv) linkedMapOf("rk" to rk, "uv" to true) else linkedMapOf("rk" to rk)
        if (token != null) {
            p[8L] = token.authenticate(clientDataHash)
            p[9L] = token.version
        }
        return p
    }

    fun getAssertionParams(
        clientDataHash: ByteArray,
        rpId: String = "example.com",
        allowIds: List<ByteArray>? = null,
        options: Map<String, Any>? = null,
        token: Token? = null
    ): Map<Long, Any?> {
        val p = linkedMapOf<Long, Any?>(1L to rpId, 2L to clientDataHash)
        if (allowIds != null) p[3L] = allowIds.map { linkedMapOf("id" to it, "type" to "public-key") }
        if (options != null) p[5L] = options
        if (token != null) {
            p[6L] = token.authenticate(clientDataHash)
            p[7L] = token.version
        }
        return p
    }

    companion object {
        /** MakeCredential の応答の authData から credential ID を取り出す。 */
        fun credentialId(makeCredentialResponse: Map<*, *>): ByteArray {
            val authData = makeCredentialResponse[2L] as ByteArray
            val idLen = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
            return authData.copyOfRange(55, 55 + idLen)
        }

        /** authenticatorData の拡張 (ED) を返す。ED がなければ null。 */
        fun extensions(authData: ByteArray): Map<*, *>? {
            val flags = authData[32].toInt()
            if (flags and 0x80 == 0) return null
            var offset = 37
            if (flags and 0x40 != 0) {
                val idLen = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
                offset = 55 + idLen
                offset += Cbor.decodeFirst(authData, offset).second
            }
            return Cbor.decode(authData, offset, authData.size - offset) as Map<*, *>
        }
    }
}
