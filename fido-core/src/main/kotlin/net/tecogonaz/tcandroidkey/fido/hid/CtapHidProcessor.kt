// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.fido.hid

import net.tecogonaz.tcandroidkey.fido.ctap2.KeepAlive
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.concurrent.Executor

/**
 * CTAPHID プロトコル (CTAP 2.1 §11.2) のフレーミング処理。
 *
 * 64 バイト固定長の HID レポートを受け取り、メッセージを組み立てて CTAP2 (CBOR) 処理へ渡す。
 * Bluetooth HID Device プロファイル (実験的) で使用する。CTAP1/U2F (CTAPHID_MSG) は非対応。
 *
 * @param ctapHandler CBOR リクエストの処理。ユーザー操作待ちでブロックしてよい ([worker] 上で実行される)。
 * @param sendReport 64 バイトの入力レポートをホストへ送信する。
 * @param onCancel ホストから CTAPHID_CANCEL を受けたときに呼ばれる (ユーザー操作待ちの中断用)。
 * @param worker CBOR 処理を実行するエグゼキュータ (シングルスレッド推奨)。
 */
class CtapHidProcessor(
    private val ctapHandler: (ByteArray, KeepAlive) -> ByteArray,
    private val sendReport: (ByteArray) -> Unit,
    private val onCancel: () -> Unit,
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

    private val lock = Any()
    private val sendLock = Any()
    private val channels = HashSet<Int>()
    private var assembly: Assembly? = null

    @Volatile
    private var busyCid: Int? = null

    /** ホストから受信した出力レポート (64 バイト) を処理する。 */
    fun onReport(report: ByteArray) {
        if (report.size < 5) return
        synchronized(lock) { handleReport(report) }
    }

    /** 接続断などでトランスポート状態を破棄する。 */
    fun reset() {
        synchronized(lock) {
            assembly = null
            channels.clear()
        }
    }

    private fun handleReport(r: ByteArray) {
        val cid = readInt(r, 0)
        val b4 = r[4].toInt() and 0xFF
        val now = clock()
        assembly?.let { if (now - it.lastPacketAt > TRANSACTION_TIMEOUT_MS) assembly = null }

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
                if (busyCid == cid) onCancel()
                return
            }
        }
        if (cid == BROADCAST_CID || cid !in channels) {
            sendError(cid, ERR_INVALID_CHANNEL)
            return
        }
        if (busyCid != null) {
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
            CMD_LOCK -> sendMessage(cid, CMD_LOCK, ByteArray(0))
            CMD_CBOR -> {
                if (payload.isEmpty()) {
                    sendError(cid, ERR_INVALID_LEN)
                    return
                }
                busyCid = cid
                worker.execute {
                    val keepAlive = KeepAlive { status -> sendMessage(cid, CMD_KEEPALIVE, byteArrayOf(status.toByte())) }
                    val response = try {
                        ctapHandler(payload, keepAlive)
                    } catch (e: RuntimeException) {
                        byteArrayOf(0x7F)
                    }
                    busyCid = null
                    sendMessage(cid, CMD_CBOR, response)
                }
            }
            else -> sendError(cid, ERR_INVALID_CMD)
        }
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
