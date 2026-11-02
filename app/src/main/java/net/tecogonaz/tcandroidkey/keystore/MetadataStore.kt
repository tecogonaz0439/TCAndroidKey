// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import net.tecogonaz.tcandroidkey.fido.ctap2.Hex
import net.tecogonaz.tcandroidkey.fido.ctap2.KeySecurityLevel
import net.tecogonaz.tcandroidkey.fido.ctap2.StoredCredential
import net.tecogonaz.tcandroidkey.fido.ctap2.UserEntity
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * クレデンシャルのメタデータ (RP ID・ユーザー名・署名カウンタ等) を暗号化して保存する。
 *
 * 暗号鍵は Android Keystore の AES-256-GCM 鍵 (ユーザー認証不要・端末外へ取り出し不可)。
 * 秘密鍵そのものは Keystore 内にあり、このファイルには含まれない。
 */
internal class MetadataStore(directory: File) {
    private val file = AtomicFile(File(directory, FILE_NAME))

    fun load(): List<StoredCredential> {
        val bytes = try {
            file.readFully()
        } catch (e: java.io.FileNotFoundException) {
            return emptyList()
        }
        if (bytes.size <= IV_LENGTH) return emptyList()
        val iv = bytes.copyOfRange(0, IV_LENGTH)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        val json = String(cipher.doFinal(bytes, IV_LENGTH, bytes.size - IV_LENGTH), Charsets.UTF_8)
        val array = JSONArray(json)
        return (0 until array.length()).map { fromJson(array.getJSONObject(it)) }
    }

    fun save(credentials: Collection<StoredCredential>) {
        val array = JSONArray()
        credentials.forEach { array.put(toJson(it)) }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val iv = cipher.iv
        check(iv.size == IV_LENGTH) { "unexpected IV length" }
        val encrypted = cipher.doFinal(array.toString().toByteArray(Charsets.UTF_8))
        val out = file.startWrite()
        try {
            out.write(iv)
            out.write(encrypted)
            file.finishWrite(out)
        } catch (e: Exception) {
            file.failWrite(out)
            throw e
        }
    }

    fun deleteFile() {
        file.delete()
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
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
            .getOrDefault(KeySecurityLevel.UNKNOWN)
    )

    private fun JSONObject.optStringOrNull(name: String): String? = if (has(name)) getString(name) else null

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "tcandroidkey_metadata_v1"
        private const val FILE_NAME = "credentials.bin"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12
    }
}
