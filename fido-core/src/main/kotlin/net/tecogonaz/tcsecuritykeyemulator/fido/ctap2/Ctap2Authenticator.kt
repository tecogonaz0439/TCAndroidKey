// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.CborException
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.bytes
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.has
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.list
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.map
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.text
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * CTAP 2.0 / 2.1 認証器 (FIDO2 セキュリティキー) のコマンド処理本体。トランスポート (NFC / HID) には依存しない。
 *
 * 対応コマンド: GetInfo / MakeCredential / GetAssertion / GetNextAssertion / ClientPIN (getKeyAgreement、
 * getPinUvAuthTokenUsingUvWithPermissions) / Reset / Selection / CredentialManagement。拡張は credProtect・hmac-secret。
 * 署名アルゴリズムは ES256 (P-256) のみ。PIN は未対応で、ユーザー検証は端末内蔵 UV
 * (生体認証・画面ロック資格情報) として [AuthorizationPolicy] に委譲する。pinUvAuthToken を使った要求でも、
 * 登録・認証・資格情報の管理のたびに [AuthorizationPolicy] の許可を得る。
 *
 * 1 つのトランスポートにつき 1 インスタンスを使う (GetNextAssertion の状態を保持するため)。
 *
 * 認可された操作は [AuthorizationLease] で管理し、鍵の生成・署名の直前と応答を返す直前に有効性を確認する。
 * GetAssertion の後続 (GetNextAssertion) は、元の操作の Lease・取消トークン・チャネルが有効な間だけ実行できる。
 */
class Ctap2Authenticator(
    private val store: CredentialStore,
    private val policy: AuthorizationPolicy,
    private val configProvider: () -> AuthenticatorConfig,
    private val transportName: String,
    private val listener: AuthenticatorEventListener = AuthenticatorEventListener.NONE,
    /** イベントの時刻 (wall clock)。 */
    private val clock: () -> Long = System::currentTimeMillis,
    /** GetNextAssertion のタイマー用の単調時計 (ms)。時計の変更の影響を受けない。 */
    private val monotonicClock: () -> Long = { System.nanoTime() / 1_000_000 }
) {
    private class PendingAssertions(
        val credentials: List<StoredCredential>,
        var nextIndex: Int,
        val rpIdHash: ByteArray,
        val clientDataHash: ByteArray,
        val flags: Int,
        val userVerified: Boolean,
        /** 直前の GetAssertion / GetNextAssertion の成功時刻 (単調時計)。 */
        var lastAssertionAt: Long,
        /** 元の GetAssertion の認可。停止・前面離脱で無効になる。 */
        val lease: AuthorizationLease,
        /** 元の GetAssertion の取消トークン。切断・再同期で無効になる。 */
        val origin: KeepAlive,
        /** 元の GetAssertion を受信したチャネル (CTAPHID の CID。NFC は 0)。 */
        val channel: Int,
        /** 元の GetAssertion の hmac-secret 入力 (各 credential の出力に使う)。 */
        val hmacSecret: HmacSecretInput?
    )

    // resetSession() は UI スレッドから呼ばれることがあるため、モニターを使わず volatile で更新する。
    @Volatile
    private var pending: PendingAssertions? = null

    /** トランスポートのセッションの世代。[resetSession] で進め、pinUvAuthToken と列挙の途中状態を無効にする。 */
    @Volatile
    private var sessionEpoch = 0L

    /** PIN/UV Auth Protocol の状態 (鍵交換の鍵・pinUvAuthToken)。`process` の直列化の内側でのみ使う。 */
    private val clientPin = ClientPin(monotonicClock, { sessionEpoch })

    /** credentialManagement の列挙の途中状態。`process` の直列化の内側でのみ使う。 */
    private val credentialManagement = CredentialManagement(store, clientPin, monotonicClock) { sessionEpoch }

    /**
     * CTAP2 リクエスト (先頭 1 バイトがコマンド、以降が CBOR パラメータ) を処理し、
     * レスポンス (先頭 1 バイトがステータス、以降が CBOR) を返す。
     *
     * 例外は外へ投げない (すべて CTAP ステータスに変換する)。
     *
     * @param keepAlive この要求専用の keepalive / 取消トークン。
     * @param channel 要求を受信したチャネル (CTAPHID の CID)。GetNextAssertion の対応付けに使う。
     */
    @Synchronized
    fun process(request: ByteArray, keepAlive: KeepAlive = KeepAlive.NONE, channel: Int = 0): ByteArray {
        if (request.isEmpty()) return byteArrayOf(CtapStatus.ERR_INVALID_LENGTH.toByte())
        val command = request[0].toInt() and 0xFF
        if (command != CtapCommand.GET_NEXT_ASSERTION) pending = null
        if (command != CtapCommand.CREDENTIAL_MANAGEMENT) credentialManagement.reset()
        var rpId: String? = null
        var userName: String? = null
        return try {
            val params: Map<*, *>? = if (request.size > 1) {
                val decoded = try {
                    Cbor.decode(request, 1, request.size - 1)
                } catch (e: CborException) {
                    throw CtapException(CtapStatus.ERR_INVALID_CBOR, e.message ?: "invalid CBOR")
                }
                decoded as? Map<*, *> ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
            } else {
                null
            }
            val result: Any? = when (command) {
                CtapCommand.GET_INFO -> getInfo()
                CtapCommand.MAKE_CREDENTIAL -> {
                    val p = params ?: throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
                    rpId = (p.map(2))?.text("id")
                    userName = (p.map(3))?.text("name")
                    makeCredential(p, keepAlive)
                }
                CtapCommand.GET_ASSERTION -> {
                    val p = params ?: throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
                    rpId = p.text(1)
                    getAssertion(p, keepAlive, channel)
                }
                CtapCommand.GET_NEXT_ASSERTION -> getNextAssertion(keepAlive, channel)
                CtapCommand.CLIENT_PIN -> clientPin.process(
                    params ?: throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
                ) { authorizeOrThrow(it, keepAlive) }
                CtapCommand.CREDENTIAL_MANAGEMENT -> credentialManagement.process(
                    params ?: throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
                ) { authorizeOrThrow(it, keepAlive) }
                CtapCommand.RESET -> reset(keepAlive)
                CtapCommand.SELECTION -> selection(keepAlive)
                else -> throw CtapException(CtapStatus.ERR_INVALID_COMMAND)
            }
            emit(command, CtapStatus.OK, rpId, userName, null)
            if (result == null) byteArrayOf(0) else byteArrayOf(0) + Cbor.encode(result)
        } catch (e: CtapException) {
            emit(command, e.status, rpId, userName, e.message)
            byteArrayOf(e.status.toByte())
        } catch (e: Exception) {
            // Kotlin では IOException / KeyStoreException 等も素通りするため、ここで必ず止める
            // (トランスポートのワーカースレッドへ漏れるとアプリが終了する)。
            emit(command, CtapStatus.ERR_OTHER, rpId, userName, e.toString())
            byteArrayOf(CtapStatus.ERR_OTHER.toByte())
        }
    }

    /** トランスポートの切断時などに呼び、セッション状態を破棄する。ブロックしない。 */
    fun resetSession() {
        pending = null
        sessionEpoch++
    }

    private fun emit(command: Int, status: Int, rpId: String?, userName: String?, detail: String?) {
        runCatching {
            listener.onEvent(AuthenticatorEvent(clock(), transportName, command, status, rpId, userName, detail))
        }
    }

    // ------------------------------------------------------------------ GetInfo

    private fun getInfo(): Map<Long, Any> {
        val config = configProvider()
        return linkedMapOf(
            0x01L to listOf("FIDO_2_0", "FIDO_2_1"),
            0x02L to listOf(CredProtect.ID, HmacSecret.ID),
            0x03L to config.aaguid,
            0x04L to linkedMapOf(
                "rk" to true,
                "up" to true,
                "uv" to true,
                "plat" to false,
                "pinUvAuthToken" to true,
                "credMgmt" to true,
                // 本アプリはすべての登録で内蔵 UV (受付ゲート) を経るため、UV の指定を必須にしない
                "makeCredUvNotRqd" to true
            ),
            0x05L to config.maxMessageSize.toLong(),
            0x06L to clientPin.supportedProtocols.map { it.toLong() },
            0x09L to config.transports,
            0x0AL to listOf(linkedMapOf("alg" to CoseAlgorithm.ES256, "type" to "public-key"))
        )
    }

    // ------------------------------------------------------------------ MakeCredential

    private fun makeCredential(p: Map<*, *>, keepAlive: KeepAlive): Map<Long, Any> {
        val config = configProvider()
        val clientDataHash = requireClientDataHash(p, 1)
        val rp = requireMap(p, 2)
        val userMap = requireMap(p, 3)
        val credParams = requireList(p, 4)

        val rpId = rp.typedText("id") ?: throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
        val rpName = rp.typedText("name")
        val userId = userMap.typedBytes("id") ?: throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
        if (userId.isEmpty() || userId.size > 64) throw CtapException(CtapStatus.ERR_INVALID_PARAMETER)
        val user = UserEntity(userId, userMap.typedText("name"), userMap.typedText("displayName"))

        // pubKeyCredParams の構造 (型) は先に検証し、対応アルゴリズムの有無は excludeList の後で判定する。
        var es256 = false
        for (param in credParams) {
            val m = param as? Map<*, *> ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
            val type = m.typedText("type") ?: throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
            val alg = m["alg"] as? Long ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
            if (type == "public-key" && alg == CoseAlgorithm.ES256) es256 = true
        }

        val excludeIds = credentialIds(p.optList(5))
        // extensions: map であることを検証し、未知の拡張は無視する
        val extensions = p.optMap(6)
        val hmacSecret = HmacSecret.requested(extensions)
        val credProtect = CredProtect.requested(extensions)
        val options = p.optMap(7)
        val rk = options.option("rk") ?: false
        val uv = options.option("uv") ?: false
        val upOption = options.option("up")
        val pinUvAuthParam = p.optBytes(8)
        val pinUvAuthProtocol = p.optInt(9)

        val request = AuthorizationRequest(CtapOperation.MAKE_CREDENTIAL, rpId, user.name, true, uv)

        // CTAP 2.0 §5.1 の手順 1: excludeList の該当確認はアルゴリズムの判定より前。
        val excluded = if (excludeIds.isEmpty()) emptyList() else store.findByIds(rpId, excludeIds)
        if (excluded.isNotEmpty()) {
            // 仕様上はユーザー存在確認を経てから返す。
            val g = authorizeOrThrow(request, keepAlive)
            g.lease.complete(consumed = false)
            // credProtect レベル 3 の credential は UV 済みの場合のみ一致として扱う (CTAP 2.1 §6.1.2 手順 12)
            if (excluded.any { it.credProtect != CredProtect.USER_VERIFICATION_REQUIRED || g.userVerified }) {
                throw CtapException(CtapStatus.ERR_CREDENTIAL_EXCLUDED)
            }
        }
        if (!es256) throw CtapException(CtapStatus.ERR_UNSUPPORTED_ALGORITHM)
        // up:false は登録では無効 (CTAP 2.1 §6.1.2)。up:true は互換性のため受け付ける。
        if (upOption == false) throw CtapException(CtapStatus.ERR_INVALID_OPTION)

        val tokenUsed = verifyPinUvAuthParam(
            pinUvAuthParam, pinUvAuthProtocol, clientDataHash, ClientPin.PERMISSION_MC, rpId, request, keepAlive
        )

        val grant = authorizeOrThrow(request, keepAlive)
        var success = false
        var created: StoredCredential? = null
        try {
            ensureActive(grant.lease, keepAlive)
            // 上書き登録 (同一 RP・同一 user.id の discoverable) でも、旧 credential は新しい登録が
            // 完成してから削除する (新規作成の失敗で既存の鍵を失わない)。
            val credential = store.create(
                rpId, rpName, user, rk,
                CredentialOptions(hmacSecret = hmacSecret, credProtect = credProtect ?: CredProtect.USER_VERIFICATION_OPTIONAL)
            ).also { created = it }
            // 拡張の出力は要求された拡張のみ (CTAP 2.1 §6.1.2 手順 15)
            val outputs = linkedMapOf<String, Any>()
            if (credProtect != null) outputs[CredProtect.ID] = credential.credProtect.toLong()
            if (hmacSecret) outputs[HmacSecret.ID] = credential.hmacSecret
            val extensionOutputs = outputs.ifEmpty { null }
            // pinUvAuthParam の検証に成功した場合も UV 済み (CTAP 2.1 §6.1.2 手順 11.1.7)
            val userVerified = grant.userVerified || tokenUsed
            val flags = AuthDataFlags.UP or AuthDataFlags.AT or (if (userVerified) AuthDataFlags.UV else 0) or
                (if (extensionOutputs != null) AuthDataFlags.ED else 0)
            val authData = buildAuthData(rpIdHash(rpId), flags, credential.signCount, extensionOutputs) {
                it.write(config.aaguid)
                it.write((credential.id.size ushr 8) and 0xFF)
                it.write(credential.id.size and 0xFF)
                it.write(credential.id)
                it.write(Cbor.encode(EcKeys.coseKey(credential.publicKeyX, credential.publicKeyY)))
            }
            val (fmt, attStmt) = when (config.attestationMode) {
                AttestationMode.NONE -> "none" to emptyMap<String, Any>()
                AttestationMode.SELF -> {
                    ensureActive(grant.lease, keepAlive)
                    val sig = keyUse { store.sign(credential, authData + clientDataHash) }
                    "packed" to linkedMapOf("alg" to CoseAlgorithm.ES256, "sig" to sig)
                }
            }
            // 応答を返す直前にも確認する (停止後に登録結果を送出しない)。
            ensureActive(grant.lease, keepAlive)
            if (rk) replaceOlderDiscoverable(credential)
            if (tokenUsed) clientPin.onUserPresentOperation()
            success = true
            return linkedMapOf(1L to fmt, 2L to authData, 3L to attStmt)
        } finally {
            // 応答を返さない登録は残さない。
            if (!success) created?.let { c -> runCatching { store.delete(c.id) } }
            grant.lease.complete(consumed = success)
        }
    }

    // ------------------------------------------------------------------ GetAssertion

    private fun getAssertion(p: Map<*, *>, keepAlive: KeepAlive, channel: Int): Map<Long, Any> {
        val rpId = p.typedText(1) ?: throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
        val clientDataHash = requireClientDataHash(p, 2)
        // 空でない allowList が指定された場合は、対応する type の ID が 0 件でもそのリストに限定する
        // (discoverable credential の検索には切り替えない)。
        val rawAllowList = p.optList(3)
        val restrictToAllowList = !rawAllowList.isNullOrEmpty()
        val allowIds = credentialIds(rawAllowList)
        val extensions = p.optMap(4)
        val options = p.optMap(5)
        if (options.option("rk") != null) throw CtapException(CtapStatus.ERR_INVALID_OPTION)
        val up = options.option("up") ?: true
        val uv = options.option("uv") ?: false
        val pinUvAuthParam = p.optBytes(6)
        val pinUvAuthProtocol = p.optInt(7)
        // hmac-secret は UP を伴う認証でのみ使える (CTAP 2.1 §12.5)。入力の検証・salt の復号は認可の前に行う。
        if (HmacSecret.present(extensions) && !up) throw CtapException(CtapStatus.ERR_UNSUPPORTED_OPTION)
        val hmacSecret = HmacSecret.parse(extensions, clientPin)

        val request = AuthorizationRequest(CtapOperation.GET_ASSERTION, rpId, null, up, uv)
        val tokenUsed = verifyPinUvAuthParam(
            pinUvAuthParam, pinUvAuthProtocol, clientDataHash, ClientPin.PERMISSION_GA, rpId, request, keepAlive
        )
        // pinUvAuthParam と uv オプションは排他で、pinUvAuthParam を優先する (CTAP 2.1 §6.2)
        val uvRequested = uv && !tokenUsed

        // credential の有無は、認可 (受付状態の確認) を経てから返す (認可前の存在確認を防ぐ)。
        val grant = authorizeOrThrow(request, keepAlive)
        var success = false
        var userInteraction = false
        try {
            // UP と UV は独立に扱う (up:false, uv:true も有効な組み合わせ)。
            val userPresent = up && grant.userPresent
            if (uvRequested && !grant.userVerified) {
                throw CtapException(CtapStatus.ERR_OPERATION_DENIED, "user verification was not performed")
            }
            // silent assertion (up:false, uv:false) では UV を立てない。pinUvAuthParam の検証に成功した場合は UV 済み。
            val userVerified = tokenUsed || (grant.userVerified && (userPresent || uvRequested))
            // ワンタイムの消費は UP・UV のユーザー操作を伴う場合のみ (トークンだけの silent assertion は消費しない)
            userInteraction = userPresent || (uvRequested && grant.userVerified)

            val located = when {
                !restrictToAllowList -> store.findDiscoverable(rpId)
                allowIds.isEmpty() -> emptyList()
                else -> store.findByIds(rpId, allowIds)
            }
            val credentials = CredProtect.filter(located, userVerified, restrictToAllowList)
            if (credentials.isEmpty()) throw CtapException(CtapStatus.ERR_NO_CREDENTIALS)
            val flags = (if (userPresent) AuthDataFlags.UP else 0) or (if (userVerified) AuthDataFlags.UV else 0)
            val rpIdHash = rpIdHash(rpId)

            val first = credentials.first()
            val response = assertionResponse(
                first, rpIdHash, clientDataHash, flags, userVerified, !restrictToAllowList, grant.lease, keepAlive,
                hmacSecret
            )
            if (!restrictToAllowList && credentials.size > 1) {
                response[5L] = credentials.size.toLong()
                pending = PendingAssertions(
                    credentials, 1, rpIdHash, clientDataHash, flags, userVerified, monotonicClock(),
                    lease = grant.lease, origin = keepAlive, channel = channel, hmacSecret = hmacSecret
                )
            }
            if (tokenUsed && userPresent) clientPin.onUserPresentOperation()
            success = true
            return response
        } finally {
            grant.lease.complete(consumed = success && userInteraction)
        }
    }

    private fun getNextAssertion(keepAlive: KeepAlive, channel: Int): Map<Long, Any> {
        val state = pending ?: throw CtapException(CtapStatus.ERR_NOT_ALLOWED)
        val reason = when {
            state.channel != channel -> "different channel"
            // 直前の GetAssertion / GetNextAssertion からの経過時間 (CTAP 2.0 §5.3)
            monotonicClock() - state.lastAssertionAt > NEXT_ASSERTION_TIMEOUT_MS -> "timeout"
            state.nextIndex >= state.credentials.size -> "no more credentials"
            state.origin.isCancelled || keepAlive.isCancelled -> "transport reset or cancelled"
            !state.lease.isValid() -> "authorization revoked"
            else -> null
        }
        if (reason != null) {
            pending = null
            throw CtapException(CtapStatus.ERR_NOT_ALLOWED, reason)
        }
        val credential = state.credentials[state.nextIndex]
        val response = assertionResponse(
            credential, state.rpIdHash, state.clientDataHash, state.flags, state.userVerified, true,
            state.lease, keepAlive, state.hmacSecret
        )
        // 署名に成功してから位置とタイマーを進める。
        state.nextIndex++
        state.lastAssertionAt = monotonicClock()
        if (state.nextIndex >= state.credentials.size) pending = null
        return response
    }

    private fun assertionResponse(
        credential: StoredCredential,
        rpIdHash: ByteArray,
        clientDataHash: ByteArray,
        flags: Int,
        userVerified: Boolean,
        includeUser: Boolean,
        lease: AuthorizationLease,
        keepAlive: KeepAlive,
        hmacSecret: HmacSecretInput?
    ): MutableMap<Long, Any> {
        ensureActive(lease, keepAlive)
        val counter = store.incrementSignCount(credential)
        // CredRandom は応答の UV フラグに対応するものを使う。CredRandom のない credential では拡張を無視する。
        val hmacOutput = hmacSecret?.let { input ->
            keyUse { store.credRandom(credential, userVerified) }?.let { HmacSecret.output(input, it) }
        }
        val extensions = hmacOutput?.let { linkedMapOf<String, Any>(HmacSecret.ID to it) }
        val authData = buildAuthData(
            rpIdHash, flags or (if (extensions != null) AuthDataFlags.ED else 0), counter, extensions
        ) {}
        val signature = keyUse { store.sign(credential, authData + clientDataHash) }
        // 応答を返す直前にも確認する (停止後に署名を送出しない)。
        ensureActive(lease, keepAlive)
        val response = linkedMapOf<Long, Any>(
            1L to linkedMapOf("id" to credential.id, "type" to "public-key"),
            2L to authData,
            3L to signature
        )
        if (credential.discoverable && (includeUser || userVerified)) {
            val user = linkedMapOf<String, Any>("id" to credential.user.id)
            if (userVerified) {
                credential.user.name?.let { user["name"] = it }
                credential.user.displayName?.let { user["displayName"] = it }
            }
            response[4L] = user
        }
        return response
    }

    // ------------------------------------------------------------------ Reset / Selection

    private fun reset(keepAlive: KeepAlive): Map<Long, Any>? {
        val request = AuthorizationRequest(CtapOperation.RESET, null, null, true, true)
        if (!configProvider().allowReset) throw CtapException(CtapStatus.ERR_OPERATION_DENIED, "reset disabled in settings")
        val grant = authorizeOrThrow(request, keepAlive)
        var success = false
        try {
            ensureActive(grant.lease, keepAlive)
            store.deleteAll()
            clientPin.reset()
            success = true
        } finally {
            grant.lease.complete(consumed = success)
        }
        return null
    }

    private fun selection(keepAlive: KeepAlive): Map<Long, Any>? {
        val request = AuthorizationRequest(CtapOperation.SELECTION, null, null, true, false)
        authorizeOrThrow(request, keepAlive).lease.complete(consumed = false)
        return null
    }

    // ------------------------------------------------------------------ helpers

    private fun authorizeOrThrow(request: AuthorizationRequest, keepAlive: KeepAlive): AuthorizationResult.Granted =
        when (val r = policy.authorize(request, keepAlive)) {
            is AuthorizationResult.Granted -> r
            is AuthorizationResult.Denied -> throw CtapException(r.status, r.reason)
        }

    /**
     * [newCredential] と同じ RP・user.id で、それ以前に作成された discoverable credential を削除する。
     * 削除に失敗しても新しい登録は有効なまま (旧 credential が残るだけ) とする。
     */
    private fun replaceOlderDiscoverable(newCredential: StoredCredential) {
        store.findDiscoverable(newCredential.rpId)
            .filter {
                it.user.id.contentEquals(newCredential.user.id) && !it.id.contentEquals(newCredential.id) &&
                    it.createdAtMillis <= newCredential.createdAtMillis
            }
            .forEach { old -> runCatching { store.delete(old.id) } }
    }

    /** 鍵操作・応答の直前に、操作が取り消されていないこと・認可が失効していないことを確認する。 */
    private fun ensureActive(lease: AuthorizationLease, keepAlive: KeepAlive) {
        if (keepAlive.isCancelled) throw CtapException(CtapStatus.ERR_KEEPALIVE_CANCEL, "cancelled")
        if (!lease.isValid()) throw CtapException(CtapStatus.ERR_OPERATION_DENIED, "authorization revoked")
    }

    /**
     * pinUvAuthParam (CTAP 2.0 の pinAuth) を確認し、pinUvAuthToken で検証できた場合は true を返す。
     *
     * - なし: false (pinUvAuthToken を使わない要求)
     * - 長さ 0: プラットフォームによる「タッチ待ち」プローブ。存在確認後に `0x35 PIN_NOT_SET` (PIN 非対応のため)
     * - それ以外: [ClientPin.verifyForOperation] で検証する (失敗は `0x33`、プロトコルの省略は `0x14`、未対応は `0x02`)
     */
    private fun verifyPinUvAuthParam(
        param: ByteArray?,
        version: Long?,
        clientDataHash: ByteArray,
        permission: Int,
        rpId: String,
        request: AuthorizationRequest,
        keepAlive: KeepAlive
    ): Boolean {
        if (param == null) return false
        if (param.isEmpty()) {
            authorizeOrThrow(request.copy(requireUserVerification = false), keepAlive).lease.complete(consumed = false)
            throw CtapException(CtapStatus.ERR_PIN_NOT_SET)
        }
        clientPin.verifyForOperation(version, clientDataHash, param, permission, rpId)
        return true
    }

    /** 鍵の使用不可 (Keystore の認証期限切れ等) を `0x27` に変換する。 */
    private inline fun <T> keyUse(block: () -> T): T = try {
        block()
    } catch (e: KeyUseNotAuthorizedException) {
        throw CtapException(CtapStatus.ERR_OPERATION_DENIED, e.message ?: "key use not authorized")
    }

    /** authenticatorData を作る。[extensions] は ED フラグを立てた場合に末尾へ CBOR で付ける。 */
    private fun buildAuthData(
        rpIdHash: ByteArray,
        flags: Int,
        signCount: Long,
        extensions: Map<String, Any>?,
        attested: (ByteArrayOutputStream) -> Unit
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(rpIdHash)
        val hasAttested = (flags and AuthDataFlags.AT) != 0
        out.write(flags)
        for (i in 3 downTo 0) out.write(((signCount ushr (8 * i)) and 0xFF).toInt())
        if (hasAttested) attested(out)
        if ((flags and AuthDataFlags.ED) != 0) out.write(Cbor.encode(extensions ?: emptyMap<String, Any>()))
        return out.toByteArray()
    }

    private fun credentialIds(list: List<*>?): List<ByteArray> {
        if (list == null) return emptyList()
        return list.mapNotNull { item ->
            val m = item as? Map<*, *> ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
            val type = m.typedText("type") ?: throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
            val id = m.typedBytes("id") ?: throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
            if (type == "public-key") id else null
        }
    }

    /** clientDataHash は SHA-256 (32 バイト)。 */
    private fun requireClientDataHash(p: Map<*, *>, key: Int): ByteArray {
        val hash = requireBytes(p, key)
        if (hash.size != CLIENT_DATA_HASH_LENGTH) {
            throw CtapException(CtapStatus.ERR_INVALID_LENGTH, "clientDataHash must be 32 bytes")
        }
        return hash
    }

    private fun requireBytes(p: Map<*, *>, key: Int): ByteArray {
        if (!p.has(key)) throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
        return p.bytes(key) ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
    }

    private fun requireMap(p: Map<*, *>, key: Int): Map<*, *> {
        if (!p.has(key)) throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
        return p.map(key) ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
    }

    private fun requireList(p: Map<*, *>, key: Int): List<*> {
        if (!p.has(key)) throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
        return p.list(key) ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
    }

    private fun Map<*, *>.optList(key: Int): List<*>? =
        if (!has(key)) null else list(key) ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)

    private fun Map<*, *>.optMap(key: Int): Map<*, *>? =
        if (!has(key)) null else map(key) ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)

    private fun Map<*, *>.optInt(key: Int): Long? =
        if (!has(key)) null else this[key.toLong()] as? Long ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)

    private fun Map<*, *>.optBytes(key: Int): ByteArray? =
        if (!has(key)) null else bytes(key) ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)

    private fun Map<*, *>.typedText(key: Any): String? =
        if (!has(key)) null else text(key) ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)

    private fun Map<*, *>.typedBytes(key: Any): ByteArray? =
        if (!has(key)) null else bytes(key) ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)

    private fun Map<*, *>?.option(name: String): Boolean? {
        if (this == null || !has(name)) return null
        return this[name] as? Boolean ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
    }

    companion object {
        const val NEXT_ASSERTION_TIMEOUT_MS: Long = 30_000
        const val CLIENT_DATA_HASH_LENGTH: Int = 32

        fun rpIdHash(rpId: String): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray(Charsets.UTF_8))
    }
}
