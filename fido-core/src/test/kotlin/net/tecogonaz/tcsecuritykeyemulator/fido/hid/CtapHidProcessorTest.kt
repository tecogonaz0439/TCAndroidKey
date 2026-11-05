// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.hid

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AuthenticatorConfig
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Ctap2Authenticator
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.KeepAlive
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.FakePolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executor

class CtapHidProcessorTest {

    private val sent = mutableListOf<ByteArray>()
    private val auth = Ctap2Authenticator(InMemoryCredentialStore(), FakePolicy(), { AuthenticatorConfig(ByteArray(16)) }, "hid")
    private val direct = Executor { it.run() }
    private val processor = CtapHidProcessor(
        ctapHandler = { cid, req, ka -> ka.send(KeepAlive.STATUS_PROCESSING); auth.process(req, ka, cid) },
        sendReport = { sent += it },
        worker = direct
    )

    private fun initPacket(cid: Int, cmd: Int, payload: ByteArray, total: Int = payload.size): ByteArray {
        val r = ByteArray(64)
        r[0] = (cid ushr 24).toByte(); r[1] = (cid ushr 16).toByte(); r[2] = (cid ushr 8).toByte(); r[3] = cid.toByte()
        r[4] = cmd.toByte()
        r[5] = (total ushr 8).toByte(); r[6] = total.toByte()
        System.arraycopy(payload, 0, r, 7, minOf(57, payload.size))
        return r
    }

    private fun contPacket(cid: Int, seq: Int, payload: ByteArray): ByteArray {
        val r = ByteArray(64)
        r[0] = (cid ushr 24).toByte(); r[1] = (cid ushr 16).toByte(); r[2] = (cid ushr 8).toByte(); r[3] = cid.toByte()
        r[4] = seq.toByte()
        System.arraycopy(payload, 0, r, 5, minOf(59, payload.size))
        return r
    }

    private fun send(cid: Int, cmd: Int, payload: ByteArray) {
        processor.onReport(initPacket(cid, cmd, payload))
        var off = 57
        var seq = 0
        while (off < payload.size) {
            processor.onReport(contPacket(cid, seq++, payload.copyOfRange(off, payload.size)))
            off += 59
        }
    }

    /** 送信済みパケットからメッセージ (cmd, payload) を順に復元する。 */
    private fun messages(): List<Pair<Int, ByteArray>> {
        val result = mutableListOf<Pair<Int, ByteArray>>()
        var i = 0
        while (i < sent.size) {
            val p = sent[i]
            val cmd = p[4].toInt() and 0xFF
            val len = ((p[5].toInt() and 0xFF) shl 8) or (p[6].toInt() and 0xFF)
            val out = ByteArrayOutputStream()
            out.write(p, 7, minOf(57, len))
            i++
            while (out.size() < len) {
                out.write(sent[i], 5, minOf(59, len - out.size()))
                i++
            }
            result += cmd to out.toByteArray()
        }
        return result
    }

    private fun init(): Int {
        val nonce = ByteArray(8) { (it + 1).toByte() }
        send(CtapHidProcessor.BROADCAST_CID, CtapHidProcessor.CMD_INIT, nonce)
        val (cmd, payload) = messages().last()
        assertEquals(CtapHidProcessor.CMD_INIT, cmd)
        assertArrayEquals(nonce, payload.copyOfRange(0, 8))
        assertEquals(17, payload.size)
        assertTrue((payload[16].toInt() and CtapHidProcessor.CAPABILITY_CBOR) != 0)
        sent.clear()
        return ((payload[8].toInt() and 0xFF) shl 24) or ((payload[9].toInt() and 0xFF) shl 16) or
            ((payload[10].toInt() and 0xFF) shl 8) or (payload[11].toInt() and 0xFF)
    }

    @Test
    fun initAllocatesChannelAndPingEchoesMultiPacketPayload() {
        val cid = init()
        val data = ByteArray(300) { (it * 7).toByte() }
        send(cid, CtapHidProcessor.CMD_PING, data)
        val (cmd, payload) = messages().single()
        assertEquals(CtapHidProcessor.CMD_PING, cmd)
        assertArrayEquals(data, payload)
    }

    @Test
    fun cborGetInfoWithKeepalive() {
        val cid = init()
        send(cid, CtapHidProcessor.CMD_CBOR, byteArrayOf(0x04))
        val msgs = messages()
        assertEquals(CtapHidProcessor.CMD_KEEPALIVE, msgs[0].first)
        val (cmd, payload) = msgs.last()
        assertEquals(CtapHidProcessor.CMD_CBOR, cmd)
        assertEquals(0, payload[0].toInt())
        val info = Cbor.decode(payload, 1, payload.size - 1) as Map<*, *>
        assertEquals(listOf("FIDO_2_0", "FIDO_2_1"), info[1L])
    }

    @Test
    fun unknownChannelIsRejected() {
        send(0x12345678, CtapHidProcessor.CMD_PING, byteArrayOf(1))
        val (cmd, payload) = messages().single()
        assertEquals(CtapHidProcessor.CMD_ERROR, cmd)
        assertEquals(CtapHidProcessor.ERR_INVALID_CHANNEL, payload[0].toInt())
    }

    @Test
    fun ctap1MsgIsNotSupported() {
        val cid = init()
        send(cid, CtapHidProcessor.CMD_MSG, byteArrayOf(0, 3, 0, 0))
        val (cmd, payload) = messages().single()
        assertEquals(CtapHidProcessor.CMD_ERROR, cmd)
        assertEquals(CtapHidProcessor.ERR_INVALID_CMD, payload[0].toInt())
    }

    @Test
    fun wrongSequenceAbortsTransaction() {
        val cid = init()
        processor.onReport(initPacket(cid, CtapHidProcessor.CMD_PING, ByteArray(57), total = 100))
        processor.onReport(contPacket(cid, 5, ByteArray(43)))
        val (cmd, payload) = messages().single()
        assertEquals(CtapHidProcessor.CMD_ERROR, cmd)
        assertEquals(CtapHidProcessor.ERR_INVALID_SEQ, payload[0].toInt())
    }

    // ------------------------------------------------------------------ 取消・再同期・例外 (S-03, F-12)

    /** execute された処理を手動で実行するエグゼキュータ。 */
    private class ManualExecutor : Executor {
        val tasks = ArrayDeque<Runnable>()
        override fun execute(command: Runnable) { tasks += command }
        fun runAll() { while (tasks.isNotEmpty()) tasks.removeFirst().run() }
    }

    private inner class Harness(val handler: (Int, ByteArray, KeepAlive) -> ByteArray) {
        val out = mutableListOf<ByteArray>()
        val worker = ManualExecutor()
        val p = CtapHidProcessor(handler, { out += it }, worker)

        fun init(cid: Int = CtapHidProcessor.BROADCAST_CID): Int {
            p.onReport(initPacket(cid, CtapHidProcessor.CMD_INIT, ByteArray(8)))
            val r = out.last()
            return ((r[15].toInt() and 0xFF) shl 24) or ((r[16].toInt() and 0xFF) shl 16) or
                ((r[17].toInt() and 0xFF) shl 8) or (r[18].toInt() and 0xFF)
        }

        fun cmds(): List<Int> = out.map { it[4].toInt() and 0xFF }
    }

    @Test
    fun cancelReceivedBeforeTheWorkerStartsIsNotLost() {
        var seenCancelled: Boolean? = null
        val h = Harness { _, _, ka ->
            seenCancelled = ka.isCancelled
            byteArrayOf(if (ka.isCancelled) 0x2D else 0x00)
        }
        val cid = h.init()
        h.out.clear()
        h.p.onReport(initPacket(cid, CtapHidProcessor.CMD_CBOR, byteArrayOf(0x02, 0xA0.toByte())))
        h.p.onReport(initPacket(cid, CtapHidProcessor.CMD_CANCEL, ByteArray(0)))
        h.worker.runAll()
        assertEquals(true, seenCancelled)
        val last = h.out.last()
        assertEquals(CtapHidProcessor.CMD_CBOR, last[4].toInt() and 0xFF)
        assertEquals(0x2D, last[7].toInt())
    }

    @Test
    fun cancelOnAnotherChannelIsIgnored() {
        var seenCancelled: Boolean? = null
        val h = Harness { _, _, ka -> seenCancelled = ka.isCancelled; byteArrayOf(0) }
        val cid = h.init()
        val other = h.init()
        h.p.onReport(initPacket(cid, CtapHidProcessor.CMD_CBOR, byteArrayOf(0x04)))
        h.p.onReport(initPacket(other, CtapHidProcessor.CMD_CANCEL, ByteArray(0)))
        h.worker.runAll()
        assertEquals(false, seenCancelled)
    }

    @Test
    fun initOnTheBusyChannelAbandonsTheOperation() {
        var calls = 0
        val h = Harness { _, _, _ -> calls++; byteArrayOf(0) }
        val cid = h.init()
        h.p.onReport(initPacket(cid, CtapHidProcessor.CMD_CBOR, byteArrayOf(0x04)))
        h.init(cid) // 再同期
        h.out.clear()
        h.worker.runAll()
        assertEquals("abandoned operation is not executed", 0, calls)
        assertTrue("no response for the abandoned request", h.out.isEmpty())
        // 再同期後は BUSY にならない
        h.p.onReport(initPacket(cid, CtapHidProcessor.CMD_CBOR, byteArrayOf(0x04)))
        h.worker.runAll()
        assertEquals(listOf(CtapHidProcessor.CMD_CBOR), h.cmds())
        assertEquals(1, calls)
    }

    @Test
    fun resetDuringAnOperationSuppressesItsResponse() {
        lateinit var h: Harness
        h = Harness { _, _, ka ->
            h.p.reset() // 処理中に切断
            ka.send(KeepAlive.STATUS_UP_NEEDED)
            assertTrue(ka.isCancelled)
            byteArrayOf(0)
        }
        val cid = h.init()
        h.p.onReport(initPacket(cid, CtapHidProcessor.CMD_CBOR, byteArrayOf(0x04)))
        h.out.clear()
        h.worker.runAll()
        assertTrue("neither keepalive nor response after reset", h.out.isEmpty())
    }

    @Test
    fun checkedExceptionFromTheHandlerReturnsErrorAndClearsBusy() {
        val h = Harness { _, _, _ -> throw java.io.IOException("boom") }
        val cid = h.init()
        h.out.clear()
        h.p.onReport(initPacket(cid, CtapHidProcessor.CMD_CBOR, byteArrayOf(0x04)))
        h.worker.runAll()
        assertEquals(CtapHidProcessor.CMD_CBOR, h.out.last()[4].toInt() and 0xFF)
        assertEquals(CtapHidProcessor.ERR_OTHER, h.out.last()[7].toInt() and 0xFF)
        h.out.clear()
        h.p.onReport(initPacket(cid, CtapHidProcessor.CMD_PING, byteArrayOf(1)))
        assertEquals(listOf(CtapHidProcessor.CMD_PING), h.cmds())
    }

    @Test
    fun otherChannelIsBusyWhileAnOperationIsPending() {
        val h = Harness { _, _, _ -> byteArrayOf(0) }
        val cid = h.init()
        val other = h.init()
        h.p.onReport(initPacket(cid, CtapHidProcessor.CMD_CBOR, byteArrayOf(0x04)))
        h.out.clear()
        h.p.onReport(initPacket(other, CtapHidProcessor.CMD_PING, byteArrayOf(1)))
        assertEquals(CtapHidProcessor.ERR_CHANNEL_BUSY, h.out.single()[7].toInt())
    }

    @Test
    fun lockIsNotImplemented() {
        val cid = init()
        send(cid, CtapHidProcessor.CMD_LOCK, byteArrayOf(5))
        val (cmd, payload) = messages().single()
        assertEquals(CtapHidProcessor.CMD_ERROR, cmd)
        assertEquals(CtapHidProcessor.ERR_INVALID_CMD, payload[0].toInt())
    }

    @Test
    fun channelIsPassedToTheAuthenticator() {
        var seen = 0
        val h = Harness { c, _, _ -> seen = c; byteArrayOf(0) }
        val cid = h.init()
        h.p.onReport(initPacket(cid, CtapHidProcessor.CMD_CBOR, byteArrayOf(0x04)))
        h.worker.runAll()
        assertEquals(cid, seen)
    }
}
