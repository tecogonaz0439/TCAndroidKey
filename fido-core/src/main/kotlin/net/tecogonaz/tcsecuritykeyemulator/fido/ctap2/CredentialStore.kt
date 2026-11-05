// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import java.math.BigInteger
import java.security.interfaces.ECPublicKey

/** WebAuthn の PublicKeyCredentialUserEntity。 */
data class UserEntity(
    val id: ByteArray,
    val name: String?,
    val displayName: String?
) {
    override fun equals(other: Any?): Boolean =
        other is UserEntity && id.contentEquals(other.id) && name == other.name && displayName == other.displayName

    override fun hashCode(): Int = id.contentHashCode() * 31 + (name?.hashCode() ?: 0)
}

/** 鍵の保管場所 (Android Keystore のセキュリティレベル)。 */
enum class KeySecurityLevel { STRONGBOX, TEE, SOFTWARE, UNKNOWN }

/**
 * 認証器に保存されたクレデンシャルのメタデータ。秘密鍵そのものは含まない。
 *
 * @property id クレデンシャル ID (WebAuthn の credential ID)。
 * @property discoverable resident key (discoverable credential) かどうか。
 * @property publicKeyX P-256 公開鍵の X 座標 (32 バイト)。
 * @property publicKeyY P-256 公開鍵の Y 座標 (32 バイト)。
 * @property hmacSecret hmac-secret 拡張 (CredRandom) が有効か。
 * @property credProtect credProtect の保護レベル (1〜3。既定 1)。
 * @property label 利用者が付けたタイトル (アプリ内の表示専用。CTAP の応答には使わない)。未設定は null で、[title] は [defaultTitle] になる。
 */
data class StoredCredential(
    val id: ByteArray,
    val rpId: String,
    val rpName: String?,
    val user: UserEntity,
    val discoverable: Boolean,
    val createdAtMillis: Long,
    val lastUsedAtMillis: Long?,
    val signCount: Long,
    val publicKeyX: ByteArray,
    val publicKeyY: ByteArray,
    val securityLevel: KeySecurityLevel,
    val hmacSecret: Boolean = false,
    val credProtect: Int = CredProtect.USER_VERIFICATION_OPTIONAL,
    val label: String? = null
) {
    val idHex: String get() = Hex.encode(id)

    /** 既定のタイトル: 登録時の rp.name (空でなければ)、なければ RP ID。 */
    val defaultTitle: String get() = rpName?.takeIf { it.isNotBlank() } ?: rpId

    /** 表示するタイトル: [label] (空でなければ)、なければ [defaultTitle]。 */
    val title: String get() = label?.takeIf { it.isNotBlank() } ?: defaultTitle

    /** 同じ credential (ID が同じ) か。内容 (署名カウンタ等) の違いは問わない。 */
    fun isSameCredential(other: StoredCredential): Boolean = id.contentEquals(other.id)

    /**
     * 全フィールドの内容で比較する。署名カウンタ・最終使用日時の更新も「変更」として扱われ、
     * StateFlow による UI への通知が抑止されないようにする (同一性の判定には [isSameCredential] を使う)。
     */
    override fun equals(other: Any?): Boolean = other is StoredCredential &&
        id.contentEquals(other.id) && rpId == other.rpId && rpName == other.rpName && user == other.user &&
        discoverable == other.discoverable && createdAtMillis == other.createdAtMillis &&
        lastUsedAtMillis == other.lastUsedAtMillis && signCount == other.signCount &&
        publicKeyX.contentEquals(other.publicKeyX) && publicKeyY.contentEquals(other.publicKeyY) &&
        securityLevel == other.securityLevel && hmacSecret == other.hmacSecret &&
        credProtect == other.credProtect && label == other.label

    override fun hashCode(): Int = id.contentHashCode()

    companion object {
        /** タイトルの最大長 (Unicode のコードポイント数)。 */
        const val MAX_LABEL_LENGTH: Int = 64

        /**
         * 入力されたタイトルを保存用に正規化する: 前後の空白と改行・制御文字を除き、[MAX_LABEL_LENGTH] コードポイントで切る。
         * 空になった場合は null (既定のタイトルに戻す)。
         */
        fun normalizeLabel(input: String?): String? {
            if (input == null) return null
            val cleaned = input.map { if (Character.isISOControl(it)) ' ' else it }.joinToString("").trim()
            if (cleaned.isEmpty()) return null
            if (cleaned.codePointCount(0, cleaned.length) <= MAX_LABEL_LENGTH) return cleaned
            return cleaned.substring(0, cleaned.offsetByCodePoints(0, MAX_LABEL_LENGTH)).trimEnd()
        }

        /** 新しい credential の作成日時: 現在時刻と、既存の最大値 + 1 の大きい方 (時計が巻き戻っても単調に増える)。 */
        fun nextCreatedAt(nowMillis: Long, existing: Collection<StoredCredential>): Long {
            val latest = existing.maxOfOrNull { it.createdAtMillis } ?: return nowMillis
            return maxOf(nowMillis, latest + 1)
        }

        /**
         * 作成日時の新しい順 (CTAP 2.0 §5.2 / 2.1 §6.2.2 の discoverable credential の順序)。
         * 同時刻の場合は credential ID の順で決定的にする。
         */
        val NEWEST_FIRST: Comparator<StoredCredential> =
            compareByDescending<StoredCredential> { it.createdAtMillis }.thenBy { it.idHex }
    }
}

/**
 * 登録時に指定する credential の属性。
 *
 * @property hmacSecret hmac-secret 拡張用の CredRandom を作る (DD-01 §11)。
 * @property credProtect credProtect の保護レベル (DD-01 §12.3)。
 * @property label 新しい credential のタイトル (上書き登録で旧 credential から引き継ぐ。DD-01 §3.2 手順 13)。
 */
data class CredentialOptions(
    val hmacSecret: Boolean = false,
    val credProtect: Int = CredProtect.USER_VERIFICATION_OPTIONAL,
    val label: String? = null
)

/**
 * クレデンシャル (秘密鍵 + メタデータ) の保管庫。
 *
 * Android 実装では秘密鍵を Android Keystore (TEE / StrongBox) に生成し、外部へは一切取り出さない。
 * 実装はスレッドセーフであること。
 */
interface CredentialStore {
    /**
     * 新しい ES256 鍵ペア (と [options] に応じた付随する鍵) を生成し、クレデンシャルとして保存する。
     * 作成日時 (createdAtMillis) は既存のどの credential より大きくする ([StoredCredential.nextCreatedAt])。
     * 上書き登録の判定 (DD-01 §3.2 手順 13) と discoverable の順序が、時計の巻き戻しで崩れないようにする。
     */
    fun create(
        rpId: String,
        rpName: String?,
        user: UserEntity,
        discoverable: Boolean,
        options: CredentialOptions = CredentialOptions()
    ): StoredCredential

    /** 指定 RP のうち、ID が [ids] のいずれかと一致するクレデンシャルを返す。 */
    fun findByIds(rpId: String, ids: List<ByteArray>): List<StoredCredential>

    /** 指定 RP の discoverable credential を作成日時の新しい順 ([StoredCredential.NEWEST_FIRST]) に返す。 */
    fun findDiscoverable(rpId: String): List<StoredCredential>


    /** クレデンシャルの秘密鍵で [data] に署名し、DER 形式の ECDSA 署名を返す。 */
    fun sign(credential: StoredCredential, data: ByteArray): ByteArray

    /**
     * hmac-secret 拡張の CredRandom (32 バイト) を返す。[userVerified] で UV あり用 / なし用を選ぶ。
     * credential に CredRandom がない場合は null (拡張を無視する)。
     * 鍵を使えない場合は [KeyUseNotAuthorizedException] を投げる。
     */
    fun credRandom(credential: StoredCredential, userVerified: Boolean): ByteArray?

    /** 署名カウンタを 1 増やし、更新後の値を返す。 */
    fun incrementSignCount(credential: StoredCredential): Long

    fun list(): List<StoredCredential>

    /**
     * credential のユーザー情報 (name・displayName) を [user] に置き換える (credentialManagement の updateUserInformation)。
     * user.id は変えない。該当する credential がなければ false。
     */
    fun updateUser(id: ByteArray, user: UserEntity): Boolean

    /**
     * credential のタイトルを [label] に置き換える (アプリの画面からの編集。null は既定のタイトルに戻す)。
     * [label] は [StoredCredential.normalizeLabel] で正規化して保存する。該当する credential がなければ false。
     */
    fun updateLabel(id: ByteArray, label: String?): Boolean

    fun delete(id: ByteArray): Boolean
    fun deleteAll()
}

/** ストアが鍵の利用を拒否した (Keystore のユーザー認証期限切れ等) ことを示す例外。 */
class KeyUseNotAuthorizedException(message: String, cause: Throwable? = null) : Exception(message, cause)

object Hex {
    private val DIGITS = "0123456789abcdef".toCharArray()

    fun encode(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(DIGITS[(b.toInt() ushr 4) and 0xF]).append(DIGITS[b.toInt() and 0xF])
        }
        return sb.toString()
    }

    fun decode(hex: String): ByteArray {
        val clean = hex.filterNot { it.isWhitespace() }
        require(clean.length % 2 == 0) { "odd length hex" }
        return ByteArray(clean.length / 2) { i ->
            ((Character.digit(clean[2 * i], 16) shl 4) or Character.digit(clean[2 * i + 1], 16)).toByte()
        }
    }
}

object EcKeys {
    /** P-256 公開鍵からアフィン座標 (各 32 バイト) を取り出す。 */
    fun coordinates(key: ECPublicKey): Pair<ByteArray, ByteArray> =
        toFixed32(key.w.affineX) to toFixed32(key.w.affineY)

    private fun toFixed32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size)
            else -> ByteArray(32 - raw.size) + raw
        }
    }

    /** COSE_Key (EC2 / P-256 / ES256) 形式の公開鍵マップを返す。 */
    fun coseKey(x: ByteArray, y: ByteArray): Map<Long, Any> = linkedMapOf(
        1L to 2L,                    // kty: EC2
        3L to CoseAlgorithm.ES256,   // alg: ES256
        -1L to 1L,                   // crv: P-256
        -2L to x,
        -3L to y
    )
}
