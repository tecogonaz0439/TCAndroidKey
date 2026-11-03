// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.nfc

import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.KeepAlive
import java.io.ByteArrayOutputStream

/**
 * FIDO NFC プロトコル (CTAP 2.1 §11.3) の ISO 7816-4 APDU 処理。
 *
 * - SELECT (AID A0000006472F0001) → バージョン文字列 "FIDO_2_0" を返す
 * - NFCCTAP_MSG (CLA 80, INS 10) → CTAP2 リクエストを [ctapHandler] へ渡す
 * - コマンドチェイニング (CLA bit 0x10) に対応。チェーン中に別の命令・不正な APDU が来たらチェーンを破棄する
 * - 短い APDU の要求には 256 バイト単位のレスポンスチェイニング (SW 61XX + GET RESPONSE) で応答する。
 *   GET RESPONSE は CLA 00 / 80 のどちらも受け付ける (クライアント実装により異なるため)
 * - 拡張長 APDU の要求には、拡張長の応答として全体を一度に返す (CTAP 2.1 §11.3.6)。
 *   Le が明示的に応答より短い場合のみ Le 単位でチェイニングする
 *
 * U2F (CTAP1) の APDU には応答しない (INS not supported)。
 * HostApduService の 1 回のフィールド接続 (activate〜deactivate) につき状態を持つため、
 * 切断時は [reset] を呼ぶこと。
 */
class NfcCtapProcessor(
    /** CTAP2 リクエストの処理。第 2 引数はその APDU 専用の取消トークン (切断で取り消される)。 */
    private val ctapHandler: (ByteArray, KeepAlive) -> ByteArray,
    /** SELECT を受理してよいか (アプリ前面・本人確認済みなど)。false の場合 6A82 を返す。 */
    private val selectGate: () -> Boolean = { true },
    private val maxCommandSize: Int = 8192,
    private val versionString: String = VERSION_FIDO_2_0
) {
    private var selected = false
    private val chainBuffer = ByteArrayOutputStream()
    private var chaining = false
    private var pendingResponse: ByteArray? = null
    private var pendingOffset = 0

    /** 現在の状態で FIDO アプレットが選択済みか。 */
    val isSelected: Boolean get() = selected

    @Synchronized
    fun reset() {
        selected = false
        chaining = false
        chainBuffer.reset()
        pendingResponse = null
        pendingOffset = 0
    }

    /**
     * @param keepAlive この APDU 専用の取消トークン。NFC では keepalive は送らず、切断の検出にのみ使う。
     */
    @Synchronized
    fun process(apduBytes: ByteArray, keepAlive: KeepAlive = KeepAlive.NONE): ByteArray {
        val apdu = try {
            Apdu.parse(apduBytes)
        } catch (e: IllegalArgumentException) {
            abortChain()
            return sw(SW_WRONG_LENGTH)
        }

        if (apdu.cla == 0x00 && apdu.ins == INS_SELECT) return handleSelect(apdu)
        if (!selected) return sw(SW_FILE_NOT_FOUND)

        val claBase = apdu.cla and 0xEF
        val isChained = (apdu.cla and 0x10) != 0

        // GET RESPONSE (レスポンスチェイニングの続き)。未対応命令の判定より先に処理し、保持中の応答を捨てない。
        if ((claBase == 0x00 || claBase == 0x80) && !isChained && apdu.ins == INS_GET_RESPONSE) {
            abortChain()
            if (apdu.p1 != 0 || apdu.p2 != 0) return sw(SW_INCORRECT_P1P2)
            if (apdu.data.isNotEmpty()) return sw(SW_WRONG_LENGTH)
            return nextChunk(if (apdu.le <= 0) SHORT_MAX_LE else apdu.le)
        }
        // 他のコマンドが来たら未送信のレスポンスは破棄する
        pendingResponse = null

        if (claBase != 0x80) {
            abortChain()
            return sw(if (claBase == 0x00) SW_INS_NOT_SUPPORTED else SW_CLA_NOT_SUPPORTED)
        }
        if (apdu.ins != INS_NFCCTAP_MSG) {
            abortChain()
            return sw(if (apdu.ins == INS_NFCCTAP_GETRESPONSE) SW_CONDITIONS_NOT_SATISFIED else SW_INS_NOT_SUPPORTED)
        }
        return handleCtapMsg(apdu, isChained, keepAlive)
    }

    /** コマンドチェーンの途中状態を破棄する (残骸を次の要求へ混入させない)。 */
    private fun abortChain() {
        chaining = false
        chainBuffer.reset()
    }

    private fun handleSelect(apdu: Apdu): ByteArray {
        reset()
        if (apdu.p1 != 0x04 || !apdu.data.contentEquals(FIDO_AID)) return sw(SW_FILE_NOT_FOUND)
        if (!selectGate()) return sw(SW_FILE_NOT_FOUND)
        selected = true
        return versionString.toByteArray(Charsets.US_ASCII) + sw(SW_OK)
    }

    private fun handleCtapMsg(apdu: Apdu, isChained: Boolean, keepAlive: KeepAlive): ByteArray {
        if (chainBuffer.size() + apdu.data.size > maxCommandSize) {
            abortChain()
            return sw(SW_WRONG_LENGTH)
        }
        chainBuffer.write(apdu.data)
        if (isChained) {
            chaining = true
            return sw(SW_OK)
        }
        val request = chainBuffer.toByteArray()
        chainBuffer.reset()
        chaining = false
        if (request.isEmpty()) return sw(SW_WRONG_LENGTH)
        val response = ctapHandler(request, keepAlive)
        pendingResponse = response
        pendingOffset = 0
        val chunkSize = if (apdu.extended) {
            // 拡張長: Le 省略・0000 (65536) は「全体」。明示的に短い Le の場合のみ分割する
            if (apdu.le <= 0 || apdu.le >= EXTENDED_MAX_LE) response.size else apdu.le
        } else {
            if (apdu.le <= 0) SHORT_MAX_LE else minOf(apdu.le, SHORT_MAX_LE)
        }
        return nextChunk(chunkSize)
    }

    private fun nextChunk(chunkSize: Int): ByteArray {
        val response = pendingResponse ?: return sw(SW_CONDITIONS_NOT_SATISFIED)
        val remaining = response.size - pendingOffset
        val n = minOf(chunkSize, remaining)
        val chunk = response.copyOfRange(pendingOffset, pendingOffset + n)
        pendingOffset += n
        val left = response.size - pendingOffset
        return if (left <= 0) {
            pendingResponse = null
            chunk + sw(SW_OK)
        } else {
            chunk + byteArrayOf(0x61, (if (left >= 256) 0x00 else left).toByte())
        }
    }

    companion object {
        const val VERSION_FIDO_2_0: String = "FIDO_2_0"
        const val VERSION_U2F_V2: String = "U2F_V2"

        val FIDO_AID: ByteArray = byteArrayOf(
            0xA0.toByte(), 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
        )

        const val INS_SELECT: Int = 0xA4
        const val INS_GET_RESPONSE: Int = 0xC0
        const val INS_NFCCTAP_MSG: Int = 0x10
        const val INS_NFCCTAP_GETRESPONSE: Int = 0x11

        const val SW_OK: Int = 0x9000
        const val SW_WRONG_LENGTH: Int = 0x6700
        const val SW_CONDITIONS_NOT_SATISFIED: Int = 0x6985
        const val SW_INCORRECT_P1P2: Int = 0x6A86
        const val SW_FILE_NOT_FOUND: Int = 0x6A82
        const val SW_INS_NOT_SUPPORTED: Int = 0x6D00
        const val SW_CLA_NOT_SUPPORTED: Int = 0x6E00

        /** 短い APDU の最大レスポンス長 (Le = 00 → 256)。 */
        const val SHORT_MAX_LE: Int = 256

        /** 拡張長 APDU の最大レスポンス長 (Le = 0000 → 65536)。 */
        const val EXTENDED_MAX_LE: Int = 65536

        fun sw(code: Int): ByteArray = byteArrayOf((code ushr 8).toByte(), code.toByte())
    }
}

/** ISO 7816-4 コマンド APDU (短い形式 / 拡張長形式)。 */
internal class Apdu(
    val cla: Int,
    val ins: Int,
    val p1: Int,
    val p2: Int,
    val data: ByteArray,
    /** 期待レスポンス長。省略時は 0、Le=00 (short) は 256、Le=0000 (extended) は 65536。 */
    val le: Int,
    val extended: Boolean
) {
    companion object {
        fun parse(b: ByteArray): Apdu {
            require(b.size >= 4) { "APDU too short" }
            val cla = b[0].toInt() and 0xFF
            val ins = b[1].toInt() and 0xFF
            val p1 = b[2].toInt() and 0xFF
            val p2 = b[3].toInt() and 0xFF
            if (b.size == 4) return Apdu(cla, ins, p1, p2, ByteArray(0), 0, false)
            val b4 = b[4].toInt() and 0xFF
            if (b.size == 5) {
                // Case 2 short: Le only
                return Apdu(cla, ins, p1, p2, ByteArray(0), if (b4 == 0) 256 else b4, false)
            }
            if (b4 != 0) {
                // Case 3/4 short
                val lc = b4
                require(b.size == 5 + lc || b.size == 6 + lc) { "bad short Lc" }
                val data = b.copyOfRange(5, 5 + lc)
                val le = if (b.size == 6 + lc) {
                    val v = b[5 + lc].toInt() and 0xFF
                    if (v == 0) 256 else v
                } else 0
                return Apdu(cla, ins, p1, p2, data, le, false)
            }
            // Extended length (b4 == 0)
            require(b.size >= 7) { "bad extended APDU" }
            val l = ((b[5].toInt() and 0xFF) shl 8) or (b[6].toInt() and 0xFF)
            if (b.size == 7) {
                // Case 2 extended: Le only
                return Apdu(cla, ins, p1, p2, ByteArray(0), if (l == 0) 65536 else l, true)
            }
            val lc = l
            require(lc > 0) { "bad extended Lc" }
            require(b.size == 7 + lc || b.size == 9 + lc) { "bad extended Lc length" }
            val data = b.copyOfRange(7, 7 + lc)
            val le = if (b.size == 9 + lc) {
                val v = ((b[7 + lc].toInt() and 0xFF) shl 8) or (b[8 + lc].toInt() and 0xFF)
                if (v == 0) 65536 else v
            } else 0
            return Apdu(cla, ins, p1, p2, data, le, true)
        }
    }
}
