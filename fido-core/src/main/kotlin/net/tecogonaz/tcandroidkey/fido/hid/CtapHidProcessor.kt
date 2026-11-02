// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.fido.hid

import net.tecogonaz.tcandroidkey.fido.ctap2.KeepAlive
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

/**
 * CTAPHID プロトコル (CTAP 2.1 §11.2) のフレーミング処理。
 *
 * 64 バイト固定長の HID レポートを受け取り、メッセージを組み立てて CTAP2 (CBOR) 処理へ渡す。
 * Bluetooth HID Device プロファイル (実験的) で使用する。CTAP1/U2F (CTAPHID_MSG) は非対応。
 *
 * CBOR 要求ごとに操作 ([Operation]) を作り、keepalive の送信と取消トークンを兼ねて [ctapHandler] へ渡す。
 * - CTAPHID_CANCEL: 実行中の操作を取り消す。応答 (通常は CTAP2_ERR_KEEPALIVE_CANCEL) は元の要求に対して返す。
 * - 割当済み CID への CTAPHID_INIT / [reset]: そのチャネル (reset は全チャネル) の操作を破棄し、応答も送らない。
 *
 * @param ctapHandler CBOR リクエストの処理 (CID, リクエスト, 操作)。ユーザー操作待ちでブロックしてよい
 *                    ([worker] 上で実行される)。
 * @param sendReport 64 バイトの入力レポートをホストへ送信する。
 * @param worker CBOR 処理を実行するエグゼキュータ (シングルスレッド推奨)。
 */
class CtapHidProcessor(
    private val ctapHandler: (Int, ByteArray, KeepAlive) -> ByteArray,
    private val sendReport: (ByteArray) -> Unit,
    private val worker: Executor,
    private val clock: () -> Long = System::currentTimeMillis,
    private val random: SecureRandom = SecureRandom()
) {
    private class Assembly(
        val cid: Int,
        val cmd: Int,
        val total: Int,
        val buffer: ByteArrayOutputStream,
        var nextSeq: Int,
        var lastPacketAt: Long
    )

    /** 1 つの CBOR 要求の処理。keepalive の送信先と取消状態を持つ。 */
    private inner class Operation(val cid: Int) : KeepAlive {
        /** CTAPHID_CANCEL を受けた (応答は返す)。 */
        @Volatile
        var cancelled = false

        /** INIT / reset で破棄された (応答も keepalive も送らない)。 */
        @Volatile
        var abandoned = false

        override val isCancelled: Boolean get() = cancelled || abandoned

        override fun send(status: Int) {
            if (!abandoned) sendMessage(cid, CMD_KEEPALIVE, byteArrayOf(status.toByte()))
        }
    }

    private val lock = Any()
    private val sendLock = Any()
    private val channels = HashSet<Int>()
    private var assembly: Assembly? = null

    /** 実行中 (または実行待ち) の操作。[lock] で保護する。 */
    private var busy: Operation? = null

    /**
     * チャネルごとの直近の操作 (完了済みを含む)。[lock] で保護する。
     * 完了済みの GetAssertion に続く GetNextAssertion も、INIT / reset 後は無効にするために保持する。
     */
    private val lastOperation = HashMap<Int, Operation>()

    /** ホストから受信した出力レポート (64 バイト) を処理する。 */
    fun onReport(report: ByteArray) {
        if (report.size < 5) return
        synchronized(lock) { handleReport(report) }
    }

    /** 接続断・停止などでトランスポート状態を破棄する。実行中の操作は取り消し、その応答は送らない。 */
    fun reset() {
        synchronized(lock) {
            assembly = null
            channels.clear()
            lastOperation.values.forEach { it.abandoned = true }
            lastOperation.clear()
            busy?.abandoned = true
            busy = null
        }
    }

    private fun handleReport(r: ByteArray) {
        val cid = readInt(r, 0)
        val b4 = r[4].toInt() and 0xFF
        val now = clock()
        assembly?.let {
            if (now - it.lastPacketAt > TRANSACTION_TIMEOUT_MS) {
                assembly = null
                sendError(it.cid, ERR_MSG_TIMEOUT)
            }
        }

        if ((b4 and 0x80) == 0) {
            // continuation packet
            val a = assembly ?: return
            if (a.cid != cid) return
            if (b4 != a.nextSeq) {
                assembly = null
                sendError(cid, ERR_INVALID_SEQ)
                return
            }
            a.nextSeq++
            a.lastPacketAt = now
            val remaining = a.total - a.buffer.size()
            a.buffer.write(r, 5, minOf(remaining, r.size - 5, CONT_DATA))
            if (a.buffer.size() >= a.total) {
                assembly = null
                dispatch(a.cid, a.cmd, a.buffer.toByteArray())
            }
            return
        }

        if (r.size < 7) return
        val cmd = b4
        val len = ((r[5].toInt() and 0xFF) shl 8) or (r[6].toInt() and 0xFF)
        if (cid == 0) {
            sendError(cid, ERR_INVALID_CHANNEL)
            return
        }
        when (cmd) {
            CMD_INIT -> {
                handleInit(cid, len, r)
                return
            }
            CMD_CANCEL -> {
                busy?.takeIf { it.cid == cid }?.cancelled = true
                return
            }
        }
        if (cid == BROADCAST_CID || cid !in channels) {
            sendError(cid, ERR_INVALID_CHANNEL)
            return
        }
        if (busy != null) {
            sendError(cid, ERR_CHANNEL_BUSY)
            return
        }
        val current = assembly
        if (current != null && current.cid != cid) {
            sendError(cid, ERR_CHANNEL_BUSY)
            return
        }
        if (len > MAX_MESSAGE_SIZE) {
            assembly = null
            sendError(cid, ERR_INVALID_LEN)
            return
        }
        val buffer = ByteArrayOutputStream(len)
        buffer.write(r, 7, minOf(len, r.size - 7, INIT_DATA))
        if (buffer.size() >= len) {
            assembly = null
            dispatch(cid, cmd, buffer.toByteArray())
        } else {
            assembly = Assembly(cid, cmd, len, buffer, 0, now)
        }
    }

    private fun handleInit(cid: Int, len: Int, r: ByteArray) {
        if (len != 8) {
            sendError(cid, ERR_INVALID_LEN)
            return
        }
        val nonce = r.copyOfRange(7, 15)
        if (assembly?.cid == cid) assembly = null
        val newCid = if (cid == BROADCAST_CID) allocateCid() else cid
        if (cid != BROADCAST_CID && cid !in channels) {
            sendError(cid, ERR_INVALID_CHANNEL)
            return
        }
        if (cid != BROADCAST_CID) {
            // 割当済みチャネルの再同期: そのチャネルの処理と状態を破棄する。
            lastOperation.remove(cid)?.abandoned = true
            if (busy?.cid == cid) {
                busy?.abandoned = true
                busy = null
            }
        }
        val payload = ByteArrayOutputStream()
        payload.write(nonce)
        writeInt(payload, newCid)
        payload.write(PROTOCOL_VERSION)
        payload.write(DEVICE_VERSION_MAJOR)
        payload.write(DEVICE_VERSION_MINOR)
        payload.write(DEVICE_VERSION_BUILD)
        payload.write(CAPABILITY_WINK or CAPABILITY_CBOR or CAPABILITY_NMSG)
        sendMessage(cid, CMD_INIT, payload.toByteArray())
    }

    private fun allocateCid(): Int {
        if (channels.size > MAX_CHANNELS) channels.clear()
        while (true) {
            val c = random.nextInt()
            if (c != 0 && c != BROADCAST_CID && channels.add(c)) return c
        }
    }

    private fun dispatch(cid: Int, cmd: Int, payload: ByteArray) {
        when (cmd) {
            CMD_PING -> sendMessage(cid, CMD_PING, payload)
            CMD_WINK -> sendMessage(cid, CMD_WINK, ByteArray(0))
            // LOCK は未実装 (任意機能)。成功を装わずに未対応として返す。
            CMD_CBOR -> {
                if (payload.isEmpty()) {
                    sendError(cid, ERR_INVALID_LEN)
                    return
                }
                val op = Operation(cid)
                busy = op
                lastOperation[cid] = op
                try {
                    worker.execute { runOperation(op, payload) }
                } catch (e: RejectedExecutionException) {
                    busy = null
                    sendError(cid, ERR_OTHER)
                }
            }
            else -> sendError(cid, ERR_INVALID_CMD)
        }
    }

    private fun runOperation(op: Operation, payload: ByteArray) {
        var response: ByteArray? = null
        try {
            if (!op.abandoned) {
                response = try {
                    ctapHandler(op.cid, payload, op)
                } catch (e: Exception) {
                    byteArrayOf(ERR_OTHER.toByte())
                }
            }
        } finally {
            synchronized(lock) { if (busy === op) busy = null }
        }
        if (response != null && !op.abandoned) sendMessage(op.cid, CMD_CBOR, response)
    }

    private fun sendError(cid: Int, code: Int) = sendMessage(cid, CMD_ERROR, byteArrayOf(code.toByte()))

    /** メッセージを初期化パケット + 継続パケットに分割して送信する。 */
    fun sendMessage(cid: Int, cmd: Int, payload: ByteArray) {
        synchronized(sendLock) {
            var offset = 0
            val first = ByteArray(REPORT_SIZE)
            putInt(first, 0, cid)
            first[4] = (cmd or 0x80).toByte()
            first[5] = (payload.size ushr 8).toByte()
            first[6] = payload.size.toByte()
            val n0 = minOf(INIT_DATA, payload.size)
            System.arraycopy(payload, 0, first, 7, n0)
            offset += n0
            sendReport(first)
            var seq = 0
            while (offset < payload.size) {
                val pkt = ByteArray(REPORT_SIZE)
                putInt(pkt, 0, cid)
                pkt[4] = seq.toByte()
                val n = minOf(CONT_DATA, payload.size - offset)
                System.arraycopy(payload, offset, pkt, 5, n)
                offset += n
                seq++
                sendReport(pkt)
            }
        }
    }

    companion object {
        const val REPORT_SIZE: Int = 64
        const val INIT_DATA: Int = REPORT_SIZE - 7
        const val CONT_DATA: Int = REPORT_SIZE - 5
        const val MAX_MESSAGE_SIZE: Int = INIT_DATA + 128 * CONT_DATA
        const val BROADCAST_CID: Int = -1 // 0xFFFFFFFF
        const val TRANSACTION_TIMEOUT_MS: Long = 3_000
        private const val MAX_CHANNELS = 64

        const val CMD_PING: Int = 0x81
        const val CMD_MSG: Int = 0x83
        const val CMD_LOCK: Int = 0x84
        const val CMD_INIT: Int = 0x86
        const val CMD_WINK: Int = 0x88
        const val CMD_CBOR: Int = 0x90
        const val CMD_CANCEL: Int = 0x91
        const val CMD_KEEPALIVE: Int = 0xBB
        const val CMD_ERROR: Int = 0xBF

        const val ERR_INVALID_CMD: Int = 0x01
        const val ERR_INVALID_PAR: Int = 0x02
        const val ERR_INVALID_LEN: Int = 0x03
        const val ERR_INVALID_SEQ: Int = 0x04
        const val ERR_MSG_TIMEOUT: Int = 0x05
        const val ERR_CHANNEL_BUSY: Int = 0x06
        const val ERR_INVALID_CHANNEL: Int = 0x0B
        const val ERR_OTHER: Int = 0x7F

        const val PROTOCOL_VERSION: Int = 2
        const val DEVICE_VERSION_MAJOR: Int = 1
        const val DEVICE_VERSION_MINOR: Int = 0
        const val DEVICE_VERSION_BUILD: Int = 0
        const val CAPABILITY_WINK: Int = 0x01
        const val CAPABILITY_CBOR: Int = 0x04
        const val CAPABILITY_NMSG: Int = 0x08

        /**
         * FIDO HID レポートディスクリプタ (Usage Page 0xF1D0, 64 バイト入出力, レポート ID なし)。
         */
        val REPORT_DESCRIPTOR: ByteArray = byteArrayOf(
            0x06, 0xD0.toByte(), 0xF1.toByte(), // Usage Page (FIDO Alliance)
            0x09, 0x01,                         // Usage (CTAPHID)
            0xA1.toByte(), 0x01,                // Collection (Application)
            0x09, 0x20,                         //   Usage (Input Report Data)
            0x15, 0x00,                         //   Logical Minimum (0)
            0x26, 0xFF.toByte(), 0x00,          //   Logical Maximum (255)
            0x75, 0x08,                         //   Report Size (8)
            0x95.toByte(), 0x40,                //   Report Count (64)
            0x81.toByte(), 0x02,                //   Input (Data, Var, Abs)
            0x09, 0x21,                         //   Usage (Output Report Data)
            0x15, 0x00,                         //   Logical Minimum (0)
            0x26, 0xFF.toByte(), 0x00,          //   Logical Maximum (255)
            0x75, 0x08,                         //   Report Size (8)
            0x95.toByte(), 0x40,                //   Report Count (64)
            0x91.toByte(), 0x02,                //   Output (Data, Var, Abs)
            0xC0.toByte()                       // End Collection
        )

        private fun readInt(b: ByteArray, off: Int): Int =
            ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
                ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

        private fun putInt(b: ByteArray, off: Int, v: Int) {
            b[off] = (v ushr 24).toByte()
            b[off + 1] = (v ushr 16).toByte()
            b[off + 2] = (v ushr 8).toByte()
            b[off + 3] = v.toByte()
        }

        private fun writeInt(out: ByteArrayOutputStream, v: Int) {
            out.write(v ushr 24); out.write(v ushr 16); out.write(v ushr 8); out.write(v)
        }
    }
}
