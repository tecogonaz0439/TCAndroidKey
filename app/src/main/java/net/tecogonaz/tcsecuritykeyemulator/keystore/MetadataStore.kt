// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.keystore

import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.CredProtect
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Hex
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.KeySecurityLevel
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.StoredCredential
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.UserEntity
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException

/**
 * クレデンシャルのメタデータ (RP ID・ユーザー名・署名カウンタ等) を暗号化して保存する。
 *
 * 暗号鍵は Android Keystore の AES-256-GCM 鍵 (ユーザー認証不要・端末外へ取り出し不可)。暗号化と保存は [KeystoreEncryptedFile]。
 * 秘密鍵そのものは Keystore 内にあり、このファイルには含まれない。
 *
 * AES-GCM により暗号文の改ざん・破損は検出するが、以前に保存した正当なファイルへの巻き戻しは検出しない。
 * ファイルがない場合は空として扱い、ファイルがあるのに読めない場合は [IOException] を投げる
 * (呼び出し側は空のストアとして上書きしてはならない)。
 */
internal class MetadataStore(directory: File) {
    private val file = KeystoreEncryptedFile(directory, FILE_NAME, KEY_ALIAS, "metadata")

    fun load(): List<StoredCredential> {
        val bytes = file.read() ?: return emptyList()
        return try {
            val array = JSONArray(String(bytes, Charsets.UTF_8))
            (0 until array.length()).map { fromJson(array.getJSONObject(it)) }
        } catch (e: Exception) {
            throw IOException("metadata file cannot be read: ${e.javaClass.simpleName}", e)
        }
    }

    fun save(credentials: Collection<StoredCredential>) {
        val array = JSONArray()
        credentials.forEach { array.put(toJson(it)) }
        file.write(array.toString().toByteArray(Charsets.UTF_8))
    }

    fun deleteFile() {
        file.deleteFile()
    }

    /** メタデータの暗号鍵を削除する (初期化用。次回の保存で新しい鍵を生成する)。 */
    fun deleteKey() {
        file.deleteKey()
    }

    private fun toJson(c: StoredCredential): JSONObject = JSONObject().apply {
        put("id", Hex.encode(c.id))
        put("rpId", c.rpId)
        c.rpName?.let { put("rpName", it) }
        put("userId", Hex.encode(c.user.id))
        c.user.name?.let { put("userName", it) }
        c.user.displayName?.let { put("userDisplayName", it) }
        put("discoverable", c.discoverable)
        put("createdAt", c.createdAtMillis)
        c.lastUsedAtMillis?.let { put("lastUsedAt", it) }
        put("signCount", c.signCount)
        put("x", Hex.encode(c.publicKeyX))
        put("y", Hex.encode(c.publicKeyY))
        put("securityLevel", c.securityLevel.name)
        // 任意項目 (ない場合は false。古い版のファイルもそのまま読める)
        if (c.hmacSecret) put("hmacSecret", true)
        if (c.credProtect != CredProtect.USER_VERIFICATION_OPTIONAL) put("credProtect", c.credProtect)
    }

    private fun fromJson(o: JSONObject): StoredCredential = StoredCredential(
        id = Hex.decode(o.getString("id")),
        rpId = o.getString("rpId"),
        rpName = o.optStringOrNull("rpName"),
        user = UserEntity(
            id = Hex.decode(o.getString("userId")),
            name = o.optStringOrNull("userName"),
            displayName = o.optStringOrNull("userDisplayName")
        ),
        discoverable = o.getBoolean("discoverable"),
        createdAtMillis = o.getLong("createdAt"),
        lastUsedAtMillis = if (o.has("lastUsedAt")) o.getLong("lastUsedAt") else null,
        signCount = o.getLong("signCount"),
        publicKeyX = Hex.decode(o.getString("x")),
        publicKeyY = Hex.decode(o.getString("y")),
        securityLevel = runCatching { KeySecurityLevel.valueOf(o.getString("securityLevel")) }
            .getOrDefault(KeySecurityLevel.UNKNOWN),
        hmacSecret = o.optBoolean("hmacSecret", false),
        credProtect = o.optInt("credProtect", CredProtect.USER_VERIFICATION_OPTIONAL)
    )

    private fun JSONObject.optStringOrNull(name: String): String? = if (has(name)) getString(name) else null

    companion object {
        const val ANDROID_KEYSTORE = KeystoreEncryptedFile.ANDROID_KEYSTORE

        /** メタデータの暗号鍵のエイリアスとファイル名 (変更しない識別子)。 */
        private const val KEY_ALIAS = "tcsecuritykeyemulator_metadata_v1"
        private const val FILE_NAME = "credentials.bin"
    }
}
