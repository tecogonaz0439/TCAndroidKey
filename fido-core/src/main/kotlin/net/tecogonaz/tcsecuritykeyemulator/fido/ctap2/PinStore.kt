// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import java.security.MessageDigest

/**
 * clientPIN の状態。
 *
 * @property retries 残りの試行回数 (最大 [PinStore.MAX_RETRIES])。PIN が未設定の場合は最大値。
 */
data class PinStatus(val state: State, val retries: Int) {
    enum class State {
        NOT_SET,
        SET,

        /** 保存データを読み込めない。PIN が設定されている可能性があるため、設定済みとして扱い、PIN の操作を拒否する。 */
        UNAVAILABLE
    }

    /** GetInfo の clientPin (true = 設定済み) に使う。読み込めない場合も true。 */
    val isSet: Boolean get() = state != State.NOT_SET
}

/** PIN の照合結果。 */
sealed interface PinCheck {
    data object Match : PinCheck

    data class Mismatch(val retries: Int) : PinCheck

    /** 残りの試行回数が 0 (照合しない)。 */
    data object Blocked : PinCheck
}

/**
 * clientPIN の保存先 (DD-01 §13.1)。PIN そのものではなく `LEFT(SHA-256(PIN), 16)` と残りの試行回数を保存する。
 *
 * 全トランスポートで 1 つを共有するため、実装はスレッドセーフであること。
 * 保存データを読み込めない場合、[status] は UNAVAILABLE を返し、その他の操作は例外を投げる (空として扱わない)。
 */
interface PinStore {
    fun status(): PinStatus

    /**
     * PIN の状態の版。[setPin]・[changePin]・[clear] (Reset・アプリでの全削除・PIN の消去) のたびに増える ([check] では増えない)。
     * 各トランスポートの認証器は pinUvAuthToken の発行時の版を記録し、版が変わったらトークンを使えなくする (DD-01 §12.1)。
     */
    val revision: Long

    /** 未設定の場合のみ PIN を設定し、試行回数を最大にする。設定済みなら false。 */
    fun setPin(pinHash: ByteArray): Boolean

    /**
     * 試行回数を 1 減らして保存してから、[pinHash] と照合する (CTAP 2.1 §6.5.5.5 等の手順)。
     * 一致すれば試行回数を最大に戻す。残りが 0 なら照合せずに [PinCheck.Blocked]。
     */
    fun check(pinHash: ByteArray): PinCheck

    /** PIN を置き換え、試行回数を最大にする ([check] の成功後に使う)。 */
    fun changePin(pinHash: ByteArray)

    /** PIN を消す (Reset・アプリでの全削除・PIN の消去)。読み込めない状態からの初期化にも使う。 */
    fun clear()

    companion object {
        /** 試行回数の上限 (CTAP 2.1 §6.5.2.2: 8 以下)。 */
        const val MAX_RETRIES: Int = 8

        /** PIN の保存形式 `LEFT(SHA-256(PIN), 16)`。 */
        fun hash(pinUtf8: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(pinUtf8).copyOf(16)
    }
}

/** メモリ上の [PinStore] (単体テスト・既定値用)。 */
class InMemoryPinStore : PinStore {
    private var pinHash: ByteArray? = null
    private var retries = PinStore.MAX_RETRIES

    @Volatile
    override var revision: Long = 0
        private set

    @Synchronized
    override fun status(): PinStatus =
        PinStatus(if (pinHash == null) PinStatus.State.NOT_SET else PinStatus.State.SET, retries)

    @Synchronized
    override fun setPin(pinHash: ByteArray): Boolean {
        if (this.pinHash != null) return false
        this.pinHash = pinHash.copyOf()
        retries = PinStore.MAX_RETRIES
        revision++
        return true
    }

    @Synchronized
    override fun check(pinHash: ByteArray): PinCheck {
        val stored = this.pinHash ?: throw IllegalStateException("PIN is not set")
        if (retries <= 0) return PinCheck.Blocked
        retries--
        if (!MessageDigest.isEqual(stored, pinHash)) return PinCheck.Mismatch(retries)
        retries = PinStore.MAX_RETRIES
        return PinCheck.Match
    }

    @Synchronized
    override fun changePin(pinHash: ByteArray) {
        this.pinHash = pinHash.copyOf()
        retries = PinStore.MAX_RETRIES
        revision++
    }

    @Synchronized
    override fun clear() {
        pinHash = null
        retries = PinStore.MAX_RETRIES
        revision++
    }
}
