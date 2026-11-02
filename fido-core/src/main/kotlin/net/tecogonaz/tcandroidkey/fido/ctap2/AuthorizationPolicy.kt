// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.fido.ctap2

/** ユーザー操作を伴う CTAP 操作の種類。 */
enum class CtapOperation { MAKE_CREDENTIAL, GET_ASSERTION, RESET, SELECTION }

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

sealed interface AuthorizationResult {
    /** 実行を許可する。フラグは authenticatorData の UP / UV ビットに反映される。 */
    data class Granted(val userPresent: Boolean, val userVerified: Boolean) : AuthorizationResult

    /** 実行を拒否する。[status] が CTAP ステータスとしてクライアントへ返る。 */
    data class Denied(val status: Int, val reason: String) : AuthorizationResult
}

/** 長時間処理中にトランスポートへ keepalive を送るためのコールバック (CTAPHID 用)。 */
fun interface KeepAlive {
    /** @param status 1 = PROCESSING, 2 = UPNEEDED */
    fun send(status: Int)

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
 */
interface AuthorizationPolicy {
    fun authorize(request: AuthorizationRequest, keepAlive: KeepAlive): AuthorizationResult

    /** 許可された操作が完了したときに呼ばれる (ワンタイム認可の消費などに用いる)。 */
    fun onOperationCompleted(request: AuthorizationRequest, success: Boolean) {}
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
