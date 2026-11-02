// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.nfc

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import net.tecogonaz.tcandroidkey.AppContainer
import net.tecogonaz.tcandroidkey.appContainer
import net.tecogonaz.tcandroidkey.data.LogLevel
import net.tecogonaz.tcandroidkey.fido.ctap2.Ctap2Authenticator
import net.tecogonaz.tcandroidkey.fido.nfc.NfcCtapProcessor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * NFC カードエミュレーション (HCE) で FIDO アプレット (AID A0000006472F0001) として振る舞うサービス。
 *
 * 読み取り機 (PC/SC リーダー、他の Android 端末等) からの APDU を [NfcCtapProcessor] で処理する。
 * CTAP 処理 (Keystore 署名など) は時間がかかる場合があるため、メインスレッドではなくワーカーで実行し、
 * [sendResponseApdu] で非同期に応答する。
 *
 * アプリ前面表示中かつ本人確認済みでない場合は SELECT を拒否する (= セキュリティキーとして見えない)。
 */
class FidoHostApduService : HostApduService() {
    private lateinit var container: AppContainer
    private lateinit var authenticator: Ctap2Authenticator
    private lateinit var processor: NfcCtapProcessor
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "fido-nfc").apply { isDaemon = true }
    }

    override fun onCreate() {
        super.onCreate()
        container = appContainer
        val policy = container.session.policy(TRANSPORT, blocking = false)
        authenticator = container.newAuthenticator(TRANSPORT, listOf("nfc"), policy)
        processor = NfcCtapProcessor(
            ctapHandler = { authenticator.process(it) },
            selectGate = { container.session.nfcSelectGate() }
        )
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? {
        worker.execute {
            val response = try {
                processor.process(commandApdu)
            } catch (e: Exception) {
                container.eventLog.log(LogLevel.ERROR, TRANSPORT, "APDU processing failed: $e")
                NfcCtapProcessor.sw(0x6F00)
            }
            runCatching { sendResponseApdu(response) }
        }
        return null
    }

    override fun onDeactivated(reason: Int) {
        worker.execute {
            val wasSelected = processor.isSelected
            processor.reset()
            authenticator.resetSession()
            if (wasSelected) {
                val why = if (reason == HostApduService.DEACTIVATION_LINK_LOSS) "link loss" else "deselected"
                container.eventLog.log(LogLevel.INFO, TRANSPORT, "reader disconnected ($why)")
            }
        }
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    companion object {
        const val TRANSPORT: String = "NFC"
    }
}
