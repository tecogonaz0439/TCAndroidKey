// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.has
import net.tecogonaz.tcsecuritykeyemulator.fido.pin.PinUvAuthProtocol
import net.tecogonaz.tcsecuritykeyemulator.fido.pin.PinUvAuthProtocolException
import java.security.SecureRandom

/**
 * authenticatorClientPIN (0x06) と、PIN/UV Auth Protocol の状態 (鍵交換の鍵・pinUvAuthToken) の管理 (DD-01 §11.1、§12.1)。
 *
 * 対応するサブコマンドは getKeyAgreement (0x02) と getPinUvAuthTokenUsingUvWithPermissions (0x06)。
 * PIN には対応しない (GetInfo に clientPin を含めない)。内蔵 UV は [AuthorizationPolicy] (受付ゲート) の許可で代える。
 *
 * pinUvAuthToken は次の場合に使えなくなる:
 * - 発行から [INITIAL_USAGE_LIMIT_MS] 以内に一度も使われない / 発行から [MAX_USAGE_PERIOD_MS] が経過した
 * - 発行時の認可 (Lease) が失効した (受付の停止・前面離脱)
 * - トランスポートのセッションが変わった ([sessionEpoch] の変化。NFC の切断など)
 * - 新しいトークンの発行・Reset
 *
 * [Ctap2Authenticator] のインスタンスごとに 1 つ持ち、`process` の直列化の内側で使う (スレッドセーフではない)。
 */
class ClientPin(
    private val monotonicClock: () -> Long = { System.nanoTime() / 1_000_000 },
    private val sessionEpoch: () -> Long = { 0L },
    /** 対応するプロトコルの番号 (GetInfo の pinUvAuthProtocols の順)。 */
    val supportedProtocols: List<Int> = SUPPORTED_PROTOCOLS,
    private val random: SecureRandom = SecureRandom()
) {
    private val protocols: Map<Int, PinUvAuthProtocol> =
        supportedProtocols.associateWith { PinUvAuthProtocol.create(it.toLong(), random)!! }

    // ---------------------------------------------------------------- pinUvAuthToken の状態 (CTAP 2.1 §6.5.2.1)
    private var tokens: Map<Int, ByteArray> = newTokens()
    private var inUse = false
    private var used = false
    private var permissions = 0
    private var permissionsRpId: String? = null
    // userPresent フラグは持たない: 登録・認証は毎回受付ゲートで UP を得るため、トークンの UP 状態を使わない
    private var userVerifiedFlag = false
    private var beganAt = 0L
    private var tokenLease: AuthorizationLease = AuthorizationLease.UNBOUND
    private var tokenEpoch = 0L

    /** 鍵交換の鍵とトークンを作り直す (Reset に相当)。 */
    fun reset() {
        protocols.values.forEach { it.regenerate() }
        resetTokens()
    }

    /**
     * 番号に対応するプロトコルを返す。未対応の番号は `0x02 INVALID_PARAMETER`。
     * [version] が null の場合は Protocol 1 (CTAP 2.1 §12.5 の hmac-secret の既定値)。
     * Protocol 1 に対応しない場合の省略は [absentStatus]。
     */
    fun protocol(version: Long?, absentStatus: Int = CtapStatus.ERR_MISSING_PARAMETER): PinUvAuthProtocol {
        if (version == null) {
            return protocols[1] ?: throw CtapException(absentStatus, "pinUvAuthProtocol is missing")
        }
        return protocols[version.toInt().takeIf { it.toLong() == version } ?: -1]
            ?: throw CtapException(CtapStatus.ERR_INVALID_PARAMETER, "unsupported pinUvAuthProtocol $version")
    }

    /**
     * プラットフォームの鍵交換の公開鍵から共有鍵を導出する。
     * 公開鍵が不正な場合は `0x02 INVALID_PARAMETER` (CTAP 2.1 §6.5.5.5 等の decapsulate の失敗と同じ)。
     */
    fun sharedSecret(protocol: PinUvAuthProtocol, keyAgreement: Map<*, *>): ByteArray = try {
        protocol.decapsulate(keyAgreement)
    } catch (e: PinUvAuthProtocolException) {
        throw CtapException(CtapStatus.ERR_INVALID_PARAMETER, e.message ?: "invalid key agreement")
    }

    /**
     * authenticatorClientPIN の処理。
     * @param authorize 内蔵 UV (受付ゲート) の認可。拒否時は例外を投げる。
     */
    fun process(p: Map<*, *>, authorize: (AuthorizationRequest) -> AuthorizationResult.Granted): Map<Long, Any> {
        val version = p.requireLong(KEY_PIN_UV_AUTH_PROTOCOL)
        val subCommand = p.requireLong(KEY_SUB_COMMAND)
        return when (subCommand) {
            SUB_GET_KEY_AGREEMENT -> linkedMapOf(RESP_KEY_AGREEMENT to protocol(version).getPublicKey())
            SUB_GET_PIN_UV_AUTH_TOKEN_USING_UV -> tokenUsingUv(p, version, authorize)
            else -> throw CtapException(CtapStatus.ERR_INVALID_SUBCOMMAND, "unsupported clientPIN subcommand $subCommand")
        }
    }

    /** getPinUvAuthTokenUsingUvWithPermissions (CTAP 2.1 §6.5.5.7.3)。 */
    private fun tokenUsingUv(
        p: Map<*, *>,
        version: Long,
        authorize: (AuthorizationRequest) -> AuthorizationResult.Granted
    ): Map<Long, Any> {
        if (!p.has(KEY_KEY_AGREEMENT)) throw CtapException(CtapStatus.ERR_MISSING_PARAMETER, "keyAgreement is missing")
        val keyAgreement = p[KEY_KEY_AGREEMENT] as? Map<*, *> ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
        val requested = p.requireLong(KEY_PERMISSIONS)
        val rpId = if (p.has(KEY_RP_ID)) {
            p[KEY_RP_ID] as? String ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
        } else {
            null
        }
        val protocol = protocol(version)
        if (requested == 0L) throw CtapException(CtapStatus.ERR_INVALID_PARAMETER, "permissions must not be 0")
        if (requested and UNSUPPORTED_PERMISSIONS != 0L) {
            throw CtapException(CtapStatus.ERR_UNAUTHORIZED_PERMISSION, "unsupported permission")
        }
        val sharedSecret = sharedSecret(protocol, keyAgreement)

        val grant = authorize(AuthorizationRequest(CtapOperation.PIN_UV_AUTH_TOKEN, rpId, null, false, true))
        try {
            if (!grant.userVerified) throw CtapException(CtapStatus.ERR_UV_INVALID, "user verification was not performed")
            if (!grant.lease.isValid()) throw CtapException(CtapStatus.ERR_OPERATION_DENIED, "authorization revoked")
            resetTokens()
            beginUsing(grant.lease)
            // 未定義のビットは無視する (CTAP 2.1 §6.5.5.7)
            permissions = (requested and KNOWN_PERMISSIONS).toInt()
            permissionsRpId = rpId
            return linkedMapOf(RESP_PIN_UV_AUTH_TOKEN to protocol.encrypt(sharedSecret, tokens.getValue(protocol.version)))
        } finally {
            // トークンの発行はワンタイムの受付を消費しない (登録・認証の時点で消費する)
            grant.lease.complete(consumed = false)
        }
    }

    /**
     * MakeCredential / GetAssertion の pinUvAuthParam を検証する (CTAP 2.1 §6.1.2 手順 11.1、§6.2.2 手順 6.1)。
     * 成功するとトークンに RP ID を結び付ける (未設定の場合)。失敗はすべて `0x33 PIN_AUTH_INVALID`。
     *
     * @param version pinUvAuthProtocol。省略は `0x14`、未対応は `0x02`
     */
    fun verifyForOperation(version: Long?, clientDataHash: ByteArray, param: ByteArray, permission: Int, rpId: String) {
        if (version == null) throw CtapException(CtapStatus.ERR_MISSING_PARAMETER, "pinUvAuthProtocol is missing")
        val protocol = protocol(version)
        verifyToken(protocol, clientDataHash, param)
        if (permissions and permission == 0) throw CtapException(CtapStatus.ERR_PIN_AUTH_INVALID, "permission is not granted")
        permissionsRpId?.let { if (it != rpId) throw CtapException(CtapStatus.ERR_PIN_AUTH_INVALID, "rpId mismatch") }
        if (!userVerifiedFlag) throw CtapException(CtapStatus.ERR_PIN_AUTH_INVALID, "token is not user verified")
        if (permissionsRpId == null) permissionsRpId = rpId
        used = true
    }

    /**
     * credentialManagement の pinUvAuthParam を検証し、cm 権限を確認する。トークンに結び付いた RP ID (なければ null) を返す。
     * pinUvAuthParam の省略は `0x36 PUAT_REQUIRED`、pinUvAuthProtocol の省略は `0x14`、検証失敗・権限なしは `0x33`。
     */
    fun verifyForCredentialManagement(version: Long?, message: ByteArray, param: ByteArray?): String? {
        if (param == null) throw CtapException(CtapStatus.ERR_PUAT_REQUIRED, "pinUvAuthParam is required")
        if (version == null) throw CtapException(CtapStatus.ERR_MISSING_PARAMETER, "pinUvAuthProtocol is missing")
        verifyToken(protocol(version), message, param)
        if (permissions and PERMISSION_CM == 0) throw CtapException(CtapStatus.ERR_PIN_AUTH_INVALID, "cm permission is not granted")
        used = true
        return permissionsRpId
    }

    /** トークンが使用中 (発行済みで期限・失効の条件に当たらない) か。 */
    fun isTokenInUse(): Boolean {
        if (!inUse) return false
        val elapsed = monotonicClock() - beganAt
        val expired = elapsed > MAX_USAGE_PERIOD_MS || (!used && elapsed > INITIAL_USAGE_LIMIT_MS) ||
            tokenEpoch != sessionEpoch() || !tokenLease.isValid()
        if (expired) stopUsing()
        return inUse
    }

    /**
     * UP を伴う登録・認証にトークンを使った後に呼ぶ (CTAP 2.1 §6.1.2 手順 14.4、§6.2.2 手順 9.4)。
     * UV のフラグと権限 (lbw 以外。本アプリは lbw に対応しないため全権限) を消す。
     */
    fun onUserPresentOperation() {
        userVerifiedFlag = false
        permissions = 0
    }

    private fun verifyToken(protocol: PinUvAuthProtocol, message: ByteArray, param: ByteArray) {
        // 使用中でないトークンでの検証は失敗とする (CTAP 2.1 §6.5.6 / §6.5.7 の verify)
        if (!isTokenInUse() || !protocol.verify(tokens.getValue(protocol.version), message, param)) {
            throw CtapException(CtapStatus.ERR_PIN_AUTH_INVALID, "pinUvAuthParam is invalid")
        }
    }

    private fun beginUsing(lease: AuthorizationLease) {
        inUse = true
        used = false
        userVerifiedFlag = true
        beganAt = monotonicClock()
        tokenLease = lease
        tokenEpoch = sessionEpoch()
    }

    private fun stopUsing() {
        inUse = false
        used = false
        permissions = 0
        permissionsRpId = null
        userVerifiedFlag = false
        tokenLease = AuthorizationLease.UNBOUND
    }

    private fun resetTokens() {
        tokens = newTokens()
        stopUsing()
    }

    private fun newTokens(): Map<Int, ByteArray> =
        supportedProtocols.associateWith { ByteArray(TOKEN_LENGTH).also { b -> random.nextBytes(b) } }

    private fun Map<*, *>.requireLong(key: Long): Long {
        if (!has(key)) throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
        return this[key] as? Long ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
    }

    companion object {
        /** GetInfo の pinUvAuthProtocols (0x06) に広告するプロトコル (優先順)。 */
        val SUPPORTED_PROTOCOLS: List<Int> = listOf(2, 1)

        const val KEY_PIN_UV_AUTH_PROTOCOL: Long = 0x01
        const val KEY_SUB_COMMAND: Long = 0x02
        const val KEY_KEY_AGREEMENT: Long = 0x03
        const val KEY_PERMISSIONS: Long = 0x09
        const val KEY_RP_ID: Long = 0x0A

        const val SUB_GET_KEY_AGREEMENT: Long = 0x02
        const val SUB_GET_PIN_UV_AUTH_TOKEN_USING_UV: Long = 0x06

        const val RESP_KEY_AGREEMENT: Long = 0x01
        const val RESP_PIN_UV_AUTH_TOKEN: Long = 0x02

        // permissions (CTAP 2.1 §6.5.5.7)
        const val PERMISSION_MC: Int = 0x01
        const val PERMISSION_GA: Int = 0x02
        const val PERMISSION_CM: Int = 0x04
        const val PERMISSION_BE: Int = 0x08
        const val PERMISSION_LBW: Int = 0x10
        const val PERMISSION_ACFG: Int = 0x20
        private const val KNOWN_PERMISSIONS: Long = (PERMISSION_MC or PERMISSION_GA or PERMISSION_CM).toLong()
        private const val UNSUPPORTED_PERMISSIONS: Long = (PERMISSION_BE or PERMISSION_LBW or PERMISSION_ACFG).toLong()

        const val TOKEN_LENGTH = 32

        /** 発行から最初の使用までの期限。NFC の既定の上限 (19.8 秒) 以下とする (CTAP 2.1 §6.5.2.1)。 */
        const val INITIAL_USAGE_LIMIT_MS: Long = 19_000

        /** トークンの最大の使用期間 (CTAP 2.1 §6.5.2.1 の推奨値)。 */
        const val MAX_USAGE_PERIOD_MS: Long = 600_000
    }
}
