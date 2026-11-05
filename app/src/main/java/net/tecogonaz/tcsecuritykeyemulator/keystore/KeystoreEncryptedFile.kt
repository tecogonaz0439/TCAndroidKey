// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore の AES-256-GCM 鍵で暗号化して保存するファイル (DD-06 §3.1)。
 * クレデンシャルのメタデータ ([MetadataStore]) と PIN ([KeystorePinStore]) で共通に使う。
 *
 * - 形式: GCM IV (12 バイト、Keystore が生成) ‖ 暗号文 ‖ 認証タグ (128 bit)
 * - 鍵: エイリアス [keyAlias]、`PURPOSE_ENCRYPT | PURPOSE_DECRYPT`、GCM / NoPadding、ユーザー認証不要。最初の書き込みで生成する
 * - 書き込みは [AtomicFile] による原子的な置き換え
 * - ファイルがなければ [read] は null。ファイルがあるのに読めない場合 (切り詰め、鍵がない、GCM タグの不一致) は [IOException]
 *   (呼び出し側は空として上書きしてはならない)
 *
 * @param label 例外のメッセージに使う名前 (例 "metadata")
 */
internal class KeystoreEncryptedFile(
    directory: File,
    fileName: String,
    private val keyAlias: String,
    private val label: String
) {
    private val file = AtomicFile(File(directory, fileName))

    /** 復号した内容を返す。ファイルがなければ null。 */
    fun read(): ByteArray? {
        val bytes = try {
            file.readFully()
        } catch (e: FileNotFoundException) {
            return null
        }
        if (bytes.size <= IV_LENGTH) throw IOException("$label file is truncated (${bytes.size} bytes)")
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            val key = existingKey() ?: throw IOException("$label key is missing")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes.copyOfRange(0, IV_LENGTH)))
            cipher.doFinal(bytes, IV_LENGTH, bytes.size - IV_LENGTH)
        } catch (e: IOException) {
            throw e
        } catch (e: Exception) {
            throw IOException("$label file cannot be read: ${e.javaClass.simpleName}", e)
        }
    }

    /** [plaintext] を暗号化して原子的に保存する。失敗した場合は例外 (既存のファイルは変わらない)。 */
    fun write(plaintext: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val iv = cipher.iv
        check(iv.size == IV_LENGTH) { "unexpected IV length" }
        val encrypted = cipher.doFinal(plaintext)
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

    /** 暗号鍵を削除する (初期化用。次回の書き込みで新しい鍵を生成する)。 */
    fun deleteKey() {
        runCatching { keyStore().deleteEntry(keyAlias) }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun existingKey(): SecretKey? = keyStore().getKey(keyAlias, null) as? SecretKey

    private fun key(): SecretKey {
        existingKey()?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12
    }
}
