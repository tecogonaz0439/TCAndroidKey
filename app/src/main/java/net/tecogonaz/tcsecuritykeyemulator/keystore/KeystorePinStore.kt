// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.keystore

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Hex
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.PinCheck
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.PinStatus
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.PinStore
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * clientPIN の保存先 (DD-06 §3.4、DD-07 §7)。`LEFT(SHA-256(PIN), 16)` と残りの試行回数を、Keystore の AES-256-GCM 鍵
 * (`tcsecuritykeyemulator_pin_v1`、ユーザー認証不要) で暗号化して `files/pin.bin` に保存する。
 *
 * - ファイルがなければ未設定。ファイルがあるのに読めなければ UNAVAILABLE とし、上書きしない ([clear] による初期化のみ可能)
 * - 試行回数は照合の前に減らして保存する (保存できなければ照合しない)
 * - 状態の変更は保存に成功してからメモリと [status] に反映する
 */
class KeystorePinStore(context: Context) : PinStore {
    private data class Record(val pinHash: ByteArray, val retries: Int)

    private val file = AtomicFile(File(context.applicationContext.filesDir, FILE_NAME))
    private var loaded = false
    private var record: Record? = null
    private var error: String? = null

    private val _state = MutableStateFlow(PinStatus(PinStatus.State.NOT_SET, PinStore.MAX_RETRIES))

    /** UI 表示用の状態。 */
    val state: StateFlow<PinStatus> = _state.asStateFlow()

    /** 読み込めない場合の理由 (UI 表示用)。 */
    val lastError: String? @Synchronized get() = error

    @Synchronized
    override fun status(): PinStatus {
        ensureLoaded()
        return currentStatus()
    }

    @Synchronized
    override fun setPin(pinHash: ByteArray): Boolean {
        requireAvailable()
        if (record != null) return false
        commit(Record(pinHash.copyOf(), PinStore.MAX_RETRIES))
        return true
    }

    @Synchronized
    override fun check(pinHash: ByteArray): PinCheck {
        val current = requireAvailable() ?: throw IllegalStateException("PIN is not set")
        if (current.retries <= 0) return PinCheck.Blocked
        val decremented = current.copy(retries = current.retries - 1)
        commit(decremented)
        if (!MessageDigest.isEqual(current.pinHash, pinHash)) return PinCheck.Mismatch(decremented.retries)
        commit(current.copy(retries = PinStore.MAX_RETRIES))
        return PinCheck.Match
    }

    @Synchronized
    override fun changePin(pinHash: ByteArray) {
        requireAvailable()
        commit(Record(pinHash.copyOf(), PinStore.MAX_RETRIES))
    }

    /** PIN を消す。読み込めない状態からの初期化にも使う (暗号鍵も作り直す)。 */
    @Synchronized
    override fun clear() {
        file.delete()
        runCatching { keyStore().deleteEntry(KEY_ALIAS) }
        record = null
        error = null
        loaded = true
        publish()
    }

    private fun ensureLoaded() {
        if (loaded) return
        try {
            record = read()
            error = null
            loaded = true
        } catch (e: Exception) {
            // 次の操作で再試行する (一時的な失敗なら回復する)
            error = e.message ?: e.javaClass.simpleName
        }
        publish()
    }

    private fun requireAvailable(): Record? {
        ensureLoaded()
        if (!loaded) throw IOException("PIN storage unavailable: $error")
        return record
    }

    private fun currentStatus(): PinStatus = when {
        !loaded -> PinStatus(PinStatus.State.UNAVAILABLE, 0)
        record == null -> PinStatus(PinStatus.State.NOT_SET, PinStore.MAX_RETRIES)
        else -> PinStatus(PinStatus.State.SET, record!!.retries)
    }

    private fun publish() {
        _state.value = currentStatus()
    }

    /** [next] を保存し、成功した場合のみメモリと状態に反映する。 */
    private fun commit(next: Record) {
        write(next)
        record = next
        publish()
    }

    private fun read(): Record? {
        val bytes = try {
            file.readFully()
        } catch (e: FileNotFoundException) {
            return null
        }
        if (bytes.size <= IV_LENGTH) throw IOException("PIN file is truncated")
        val key = existingKey() ?: throw IOException("PIN key is missing")
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes.copyOfRange(0, IV_LENGTH)))
            val json = JSONObject(String(cipher.doFinal(bytes, IV_LENGTH, bytes.size - IV_LENGTH), Charsets.UTF_8))
            val hash = Hex.decode(json.getString("hash"))
            val retries = json.getInt("retries")
            if (hash.size != 16 || retries !in 0..PinStore.MAX_RETRIES) throw IOException("PIN file is invalid")
            Record(hash, retries)
        } catch (e: IOException) {
            throw e
        } catch (e: Exception) {
            throw IOException("PIN file cannot be read: ${e.javaClass.simpleName}", e)
        }
    }

    private fun write(r: Record) {
        val json = JSONObject().put("hash", Hex.encode(r.pinHash)).put("retries", r.retries)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val iv = cipher.iv
        check(iv.size == IV_LENGTH) { "unexpected IV length" }
        val encrypted = cipher.doFinal(json.toString().toByteArray(Charsets.UTF_8))
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

    private fun keyStore(): KeyStore = KeyStore.getInstance(MetadataStore.ANDROID_KEYSTORE).apply { load(null) }

    private fun existingKey(): SecretKey? = keyStore().getKey(KEY_ALIAS, null) as? SecretKey

    private fun key(): SecretKey {
        existingKey()?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, MetadataStore.ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    companion object {
        /** PIN の暗号鍵のエイリアス (変更しない識別子)。 */
        const val KEY_ALIAS = "tcsecuritykeyemulator_pin_v1"
        private const val FILE_NAME = "pin.bin"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12
    }
}
