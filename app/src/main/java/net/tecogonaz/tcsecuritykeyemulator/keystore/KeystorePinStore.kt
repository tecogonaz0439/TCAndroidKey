// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.keystore

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Hex
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.PinCheck
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.PinStatus
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.PinStore
import org.json.JSONObject
import java.io.IOException
import java.security.MessageDigest

/**
 * clientPIN の保存先 (DD-06 §3.4、DD-07 §7)。`LEFT(SHA-256(PIN), 16)` と残りの試行回数を、Keystore の AES-256-GCM 鍵
 * (`tcsecuritykeyemulator_pin_v1`、ユーザー認証不要) で暗号化して `files/pin.bin` に保存する ([KeystoreEncryptedFile])。
 *
 * - ファイルがなければ未設定。ファイルがあるのに読めなければ UNAVAILABLE とし、上書きしない ([clear] による初期化のみ可能)
 * - 試行回数は照合の前に減らして保存する (保存できなければ照合しない)。一致した後の回復の保存に失敗した場合は、
 *   照合の成功として扱い、試行回数は保存済みの値 (減った値) のままにする (次に一致した照合で回復する)
 * - 状態の変更は保存に成功してからメモリと [status] に反映する
 */
class KeystorePinStore(context: Context) : PinStore {
    private data class Record(val pinHash: ByteArray, val retries: Int)

    private val file = KeystoreEncryptedFile(context.applicationContext.filesDir, FILE_NAME, KEY_ALIAS, "PIN")
    private var loaded = false
    private var record: Record? = null
    private var error: String? = null

    @Volatile
    override var revision: Long = 0
        private set

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
        revision++
        return true
    }

    @Synchronized
    override fun check(pinHash: ByteArray): PinCheck {
        val current = requireAvailable() ?: throw IllegalStateException("PIN is not set")
        if (current.retries <= 0) return PinCheck.Blocked
        val decremented = current.copy(retries = current.retries - 1)
        commit(decremented)
        if (!MessageDigest.isEqual(current.pinHash, pinHash)) return PinCheck.Mismatch(decremented.retries)
        // 正しい PIN を、回復の保存の失敗 (一時的な書き込みの失敗など) で 0x7F にしない。
        // commit は保存に成功した場合のみメモリに反映するため、失敗時もメモリとディスクは一致したまま (減った値) になる。
        runCatching { commit(current.copy(retries = PinStore.MAX_RETRIES)) }
        return PinCheck.Match
    }

    @Synchronized
    override fun changePin(pinHash: ByteArray) {
        requireAvailable()
        commit(Record(pinHash.copyOf(), PinStore.MAX_RETRIES))
        revision++
    }

    /** PIN を消す。読み込めない状態からの初期化にも使う (暗号鍵も作り直す)。 */
    @Synchronized
    override fun clear() {
        file.deleteFile()
        file.deleteKey()
        record = null
        error = null
        loaded = true
        revision++
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
        val bytes = file.read() ?: return null
        return try {
            val json = JSONObject(String(bytes, Charsets.UTF_8))
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
        file.write(json.toString().toByteArray(Charsets.UTF_8))
    }

    companion object {
        /** PIN の暗号鍵のエイリアス (変更しない識別子)。 */
        const val KEY_ALIAS = "tcsecuritykeyemulator_pin_v1"
        private const val FILE_NAME = "pin.bin"
    }
}
