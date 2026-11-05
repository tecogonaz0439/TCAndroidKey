// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor

/**
 * authenticatorCredentialManagement (0x0A。CTAP 2.1 §6.8、DD-01 §12.4)。discoverable credential の列挙・削除・更新を行う。
 *
 * - 列挙を始めるコマンド・削除・更新・件数の取得は、cm 権限の pinUvAuthToken による pinUvAuthParam を必須とし、
 *   さらに受付ゲートの認可を得る (ワンタイムは消費しない)
 * - 列挙の続き (GetNextRP / GetNextCredential) は、開始時の認可・トークンが有効で、他のコマンドを挟まず、
 *   直前の応答から [STATE_TIMEOUT_MS] 以内の場合のみ受け付ける
 *
 * [Ctap2Authenticator] のインスタンスごとに 1 つ持ち、`process` の直列化の内側で使う (スレッドセーフではない)。
 */
class CredentialManagement(
    private val store: CredentialStore,
    private val clientPin: ClientPin,
    private val monotonicClock: () -> Long,
    private val sessionEpoch: () -> Long
) {
    private class Enumeration(
        val kind: Long,
        val items: List<Map<Long, Any>>,
        var next: Int,
        var lastAt: Long,
        val lease: AuthorizationLease,
        val epoch: Long
    )

    private var state: Enumeration? = null

    /** 列挙の途中状態を破棄する (credentialManagement 以外のコマンドの受信時)。 */
    fun reset() {
        state = null
    }

    /**
     * @param raw 要求のマップの各値の受信したままのバイト列 ([Cbor.rawMapValues])。pinUvAuthParam の認証対象に使う
     * @param authorize 受付ゲートの認可。拒否時は例外を投げる。
     * @return 応答の CBOR マップ (空の応答は null)
     */
    fun process(
        p: Map<*, *>,
        raw: Map<Any?, ByteArray>,
        authorize: (AuthorizationRequest) -> AuthorizationResult.Granted
    ): Map<Long, Any>? {
        val subCommand = p.requireLong(KEY_SUB_COMMAND)
        val previous = state
        state = null
        return when (subCommand) {
            SUB_GET_NEXT_RP -> next(previous, SUB_ENUMERATE_RPS_BEGIN)
            SUB_GET_NEXT_CREDENTIAL -> next(previous, SUB_ENUMERATE_CREDENTIALS_BEGIN)
            SUB_GET_CREDS_METADATA, SUB_ENUMERATE_RPS_BEGIN, SUB_ENUMERATE_CREDENTIALS_BEGIN,
            SUB_DELETE_CREDENTIAL, SUB_UPDATE_USER_INFORMATION -> authenticated(p, raw, subCommand, authorize)
            else -> throw CtapException(CtapStatus.ERR_INVALID_SUBCOMMAND, "unsupported credentialManagement subcommand $subCommand")
        }
    }

    private fun authenticated(
        p: Map<*, *>,
        raw: Map<Any?, ByteArray>,
        subCommand: Long,
        authorize: (AuthorizationRequest) -> AuthorizationResult.Granted
    ): Map<Long, Any>? {
        val params = p.optMap(KEY_SUB_COMMAND_PARAMS)
        val version = p.optLong(KEY_PIN_UV_AUTH_PROTOCOL)
        val param = p.optBytes(KEY_PIN_UV_AUTH_PARAM)
        // 認証対象: サブコマンド (1 バイト) ‖ subCommandParams の受信したバイト列 (パラメータを持つサブコマンドのみ)。
        // 再エンコードすると、canonical でない CBOR を送るクライアントの署名と一致しないため、受信したバイト列を使う。
        val takesParams = subCommand == SUB_ENUMERATE_CREDENTIALS_BEGIN || subCommand == SUB_DELETE_CREDENTIAL ||
            subCommand == SUB_UPDATE_USER_INFORMATION
        if (takesParams && params == null) throw CtapException(CtapStatus.ERR_MISSING_PARAMETER, "subCommandParams is missing")
        val message = byteArrayOf(subCommand.toByte()) + (if (takesParams) raw.getValue(KEY_SUB_COMMAND_PARAMS) else ByteArray(0))
        val boundRpId = clientPin.verifyForCredentialManagement(version, message, param)

        val grant = authorize(AuthorizationRequest(CtapOperation.CREDENTIAL_MANAGEMENT, boundRpId, null, false, true))
        try {
            if (!grant.lease.isValid()) throw CtapException(CtapStatus.ERR_OPERATION_DENIED, "authorization revoked")
            return when (subCommand) {
                SUB_GET_CREDS_METADATA -> {
                    requireNoRpId(boundRpId)
                    val existing = discoverable().size
                    linkedMapOf(
                        RESP_EXISTING_COUNT to existing.toLong(),
                        RESP_REMAINING_COUNT to (DISCOVERABLE_CAPACITY - existing).coerceAtLeast(0).toLong()
                    )
                }
                SUB_ENUMERATE_RPS_BEGIN -> {
                    requireNoRpId(boundRpId)
                    val rps = discoverable().groupBy { it.rpId }.toSortedMap().map { (rpId, creds) ->
                        val rp = linkedMapOf<String, Any>("id" to rpId)
                        creds.firstNotNullOfOrNull { it.rpName }?.let { rp["name"] = it }
                        linkedMapOf<Long, Any>(RESP_RP to rp, RESP_RP_ID_HASH to Ctap2Authenticator.rpIdHash(rpId))
                    }
                    begin(SUB_ENUMERATE_RPS_BEGIN, rps, RESP_TOTAL_RPS, grant.lease)
                }
                SUB_ENUMERATE_CREDENTIALS_BEGIN -> {
                    val rpIdHash = params!!.requireBytes(PARAM_RP_ID_HASH)
                    if (boundRpId != null && !Ctap2Authenticator.rpIdHash(boundRpId).contentEquals(rpIdHash)) {
                        throw CtapException(CtapStatus.ERR_PIN_AUTH_INVALID, "rpId mismatch")
                    }
                    val creds = discoverable().filter { Ctap2Authenticator.rpIdHash(it.rpId).contentEquals(rpIdHash) }
                        .sortedWith(StoredCredential.NEWEST_FIRST)
                        .map { credentialEntry(it) }
                    begin(SUB_ENUMERATE_CREDENTIALS_BEGIN, creds, RESP_TOTAL_CREDENTIALS, grant.lease)
                }
                SUB_DELETE_CREDENTIAL -> {
                    val credential = findCredential(params!!, boundRpId)
                    store.delete(credential.id)
                    null
                }
                SUB_UPDATE_USER_INFORMATION -> {
                    val credential = findCredential(params!!, boundRpId)
                    val user = params.requireMap(PARAM_USER)
                    val userId = user.requireBytes("id")
                    if (!userId.contentEquals(credential.user.id)) {
                        throw CtapException(CtapStatus.ERR_INVALID_PARAMETER, "user.id does not match the credential")
                    }
                    // 指定のない name / displayName は削除する (CTAP 2.1 §6.8.6)
                    store.updateUser(credential.id, UserEntity(userId, user.optText("name"), user.optText("displayName")))
                    null
                }
                else -> error("unreachable")
            }
        } finally {
            grant.lease.complete(consumed = false)
        }
    }

    private fun begin(kind: Long, items: List<Map<Long, Any>>, totalKey: Long, lease: AuthorizationLease): Map<Long, Any> {
        if (items.isEmpty()) throw CtapException(CtapStatus.ERR_NO_CREDENTIALS)
        if (items.size > 1) state = Enumeration(kind, items, 1, monotonicClock(), lease, sessionEpoch())
        return LinkedHashMap(items.first()).apply { put(totalKey, items.size.toLong()) }
    }

    private fun next(previous: Enumeration?, kind: Long): Map<Long, Any> {
        val s = previous ?: throw CtapException(CtapStatus.ERR_NOT_ALLOWED, "no enumeration in progress")
        val reason = when {
            s.kind != kind -> "different enumeration"
            monotonicClock() - s.lastAt > STATE_TIMEOUT_MS -> "timeout"
            s.epoch != sessionEpoch() -> "transport reset"
            !s.lease.isValid() -> "authorization revoked"
            !clientPin.isTokenInUse() -> "token expired"
            s.next >= s.items.size -> "no more items"
            else -> null
        }
        if (reason != null) throw CtapException(CtapStatus.ERR_NOT_ALLOWED, reason)
        val item = s.items[s.next++]
        s.lastAt = monotonicClock()
        if (s.next < s.items.size) state = s
        return item
    }

    private fun credentialEntry(c: StoredCredential): Map<Long, Any> {
        val user = linkedMapOf<String, Any>("id" to c.user.id)
        c.user.name?.let { user["name"] = it }
        c.user.displayName?.let { user["displayName"] = it }
        return linkedMapOf(
            RESP_USER to user,
            RESP_CREDENTIAL_ID to linkedMapOf("id" to c.id, "type" to "public-key"),
            RESP_PUBLIC_KEY to EcKeys.coseKey(c.publicKeyX, c.publicKeyY),
            RESP_CRED_PROTECT to c.credProtect.toLong()
        )
    }

    private fun findCredential(params: Map<*, *>, boundRpId: String?): StoredCredential {
        val id = params.requireMap(PARAM_CREDENTIAL_ID).requireBytes("id")
        val credential = discoverable().firstOrNull { it.id.contentEquals(id) }
            ?: throw CtapException(CtapStatus.ERR_NO_CREDENTIALS)
        if (boundRpId != null && boundRpId != credential.rpId) throw CtapException(CtapStatus.ERR_PIN_AUTH_INVALID, "rpId mismatch")
        return credential
    }

    private fun discoverable(): List<StoredCredential> = store.list().filter { it.discoverable }

    private fun requireNoRpId(boundRpId: String?) {
        if (boundRpId != null) throw CtapException(CtapStatus.ERR_PIN_AUTH_INVALID, "token is bound to an rpId")
    }

    companion object {
        const val KEY_SUB_COMMAND: Long = 0x01
        const val KEY_SUB_COMMAND_PARAMS: Long = 0x02
        const val KEY_PIN_UV_AUTH_PROTOCOL: Long = 0x03
        const val KEY_PIN_UV_AUTH_PARAM: Long = 0x04

        const val PARAM_RP_ID_HASH: Long = 0x01
        const val PARAM_CREDENTIAL_ID: Long = 0x02
        const val PARAM_USER: Long = 0x03

        const val SUB_GET_CREDS_METADATA: Long = 0x01
        const val SUB_ENUMERATE_RPS_BEGIN: Long = 0x02
        const val SUB_GET_NEXT_RP: Long = 0x03
        const val SUB_ENUMERATE_CREDENTIALS_BEGIN: Long = 0x04
        const val SUB_GET_NEXT_CREDENTIAL: Long = 0x05
        const val SUB_DELETE_CREDENTIAL: Long = 0x06
        const val SUB_UPDATE_USER_INFORMATION: Long = 0x07

        const val RESP_EXISTING_COUNT: Long = 0x01
        const val RESP_REMAINING_COUNT: Long = 0x02
        const val RESP_RP: Long = 0x03
        const val RESP_RP_ID_HASH: Long = 0x04
        const val RESP_TOTAL_RPS: Long = 0x05
        const val RESP_USER: Long = 0x06
        const val RESP_CREDENTIAL_ID: Long = 0x07
        const val RESP_PUBLIC_KEY: Long = 0x08
        const val RESP_TOTAL_CREDENTIALS: Long = 0x09
        const val RESP_CRED_PROTECT: Long = 0x0A

        /** 列挙の続きを受け付ける時間 (CTAP 2.1 §6.0 の状態の破棄)。 */
        const val STATE_TIMEOUT_MS: Long = 30_000

        /**
         * getCredsMetadata で残り件数の見積もりに使う容量。保存数の上限は設けていない (Keystore の容量による) ため、
         * 見積もりの値としてのみ使う。
         */
        const val DISCOVERABLE_CAPACITY: Int = 1000
    }
}
