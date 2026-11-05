// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

/**
 * ユーザー操作を伴う CTAP 操作の種類。
 *
 * - [PIN_UV_AUTH_TOKEN]: 内蔵 UV による pinUvAuthToken の発行 (ClientPIN 0x06)。ワンタイムは消費しない
 * - [CREDENTIAL_MANAGEMENT]: authenticatorCredentialManagement の各操作。ワンタイムは消費しない
 * - [CLIENT_PIN]: PIN の設定・変更 (ClientPIN 0x03 / 0x04)。ワンタイムは消費しない
 */
enum class CtapOperation {
    MAKE_CREDENTIAL, GET_ASSERTION, RESET, SELECTION, PIN_UV_AUTH_TOKEN, CREDENTIAL_MANAGEMENT, CLIENT_PIN
}

/**
 * 認証器が操作の実行可否を問い合わせるための要求。
 *
 * @property requireUserPresence ユーザー存在確認 (UP) が必要か。`false` は silent assertion を意味する。
 * @property requireUserVerification ユーザー検証 (UV, 指紋等) が要求されているか。
 */
data class AuthorizationRequest(
    val operation: CtapOperation,
    val rpId: String?,
    val userName: String?,
    val requireUserPresence: Boolean,
    val requireUserVerification: Boolean
)

/**
 * 認可された 1 つの操作 (MakeCredential / GetAssertion とそれに続く GetNextAssertion 群など) の有効性。
 *
 * - [isValid] は鍵操作の直前と応答を返す直前に確認する。受付の明示的な停止・アプリの前面離脱で false になる。
 *   ワンタイム認可の「消費」では false にならない (同一操作の GetNextAssertion を継続できるようにするため)。
 * - [complete] は操作の終了時に必ず 1 回呼ぶ (2 回目以降は無視される)。
 *   `consumed = true` はユーザー操作を伴う操作が成功したことを表し、ワンタイム認可を消費する。
 */
interface AuthorizationLease {
    fun isValid(): Boolean

    fun complete(consumed: Boolean)

    companion object {
        /** 有効性の管理を行わないポリシー用。 */
        val UNBOUND: AuthorizationLease = object : AuthorizationLease {
            override fun isValid(): Boolean = true
            override fun complete(consumed: Boolean) {}
        }
    }
}

sealed interface AuthorizationResult {
    /**
     * 実行を許可する。フラグは authenticatorData の UP / UV ビットに反映される。
     * [lease] は操作の終了時に [AuthorizationLease.complete] すること。
     */
    data class Granted(
        val userPresent: Boolean,
        val userVerified: Boolean,
        val lease: AuthorizationLease = AuthorizationLease.UNBOUND
    ) : AuthorizationResult

    /** 実行を拒否する。[status] が CTAP ステータスとしてクライアントへ返る。 */
    data class Denied(val status: Int, val reason: String) : AuthorizationResult
}

/**
 * トランスポートが 1 つの要求ごとに渡すコールバック。
 *
 * - [send] は長時間処理中に keepalive を送る (CTAPHID 用。NFC では何もしない)。
 * - [isCancelled] は、その要求がホストから取り消された (CTAPHID_CANCEL)、またはトランスポートが
 *   切断・再同期された場合に true になる。要求の受信時に作られ、トランスポート全体では共有しない。
 */
fun interface KeepAlive {
    /** @param status 1 = PROCESSING, 2 = UPNEEDED */
    fun send(status: Int)

    val isCancelled: Boolean get() = false

    companion object {
        const val STATUS_PROCESSING: Int = 1
        const val STATUS_UP_NEEDED: Int = 2
        val NONE: KeepAlive = KeepAlive { }
    }
}

/**
 * ユーザー存在確認・本人確認の判定ポリシー。
 *
 * Android 実装では「アプリが前面で起動中」かつ「生体認証等で本人確認済み (有効期限内)」の場合のみ許可する。
 * [authorize] はワーカースレッドから呼ばれ、トランスポートによってはユーザー操作を待つためにブロックしてよい。
 * 許可した場合は [AuthorizationResult.Granted.lease] で操作の有効性と終了を管理する。
 */
fun interface AuthorizationPolicy {
    fun authorize(request: AuthorizationRequest, keepAlive: KeepAlive): AuthorizationResult
}

/** 認証器の処理結果を UI / ログへ通知するイベント。 */
data class AuthenticatorEvent(
    val timestampMillis: Long,
    val transport: String,
    val command: Int,
    val status: Int,
    val rpId: String? = null,
    val userName: String? = null,
    val detail: String? = null
) {
    val isSuccess: Boolean get() = status == CtapStatus.OK
}

fun interface AuthenticatorEventListener {
    fun onEvent(event: AuthenticatorEvent)

    companion object {
        val NONE: AuthenticatorEventListener = AuthenticatorEventListener { }
    }
}

enum class AttestationMode {
    /** fmt "none"。プライバシー優先 (既定)。 */
    NONE,

    /** fmt "packed" の自己署名 (self attestation)。 */
    SELF
}

/**
 * 認証器の静的・動的設定。
 *
 * @property aaguid 認証器モデルを識別する 16 バイトの AAGUID。
 * @property transports getInfo で通知するトランスポート (例: "nfc")。
 * @property allowReset クライアントからの authenticatorReset (全削除) を許可するか。
 */
data class AuthenticatorConfig(
    val aaguid: ByteArray,
    val attestationMode: AttestationMode = AttestationMode.NONE,
    val transports: List<String> = listOf("nfc"),
    val allowReset: Boolean = false,
    val maxMessageSize: Int = 2048
) {
    init {
        require(aaguid.size == 16) { "AAGUID must be 16 bytes" }
    }

    override fun equals(other: Any?): Boolean =
        other is AuthenticatorConfig && aaguid.contentEquals(other.aaguid) &&
            attestationMode == other.attestationMode && transports == other.transports &&
            allowReset == other.allowReset && maxMessageSize == other.maxMessageSize

    override fun hashCode(): Int = aaguid.contentHashCode()
}
