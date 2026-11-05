// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.has
import net.tecogonaz.tcsecuritykeyemulator.fido.pin.PinUvAuthProtocol
import net.tecogonaz.tcsecuritykeyemulator.fido.pin.PinUvAuthProtocolException

/**
 * authenticatorClientPIN (0x06) と、PIN/UV Auth Protocol の状態 (鍵交換の鍵) の管理。
 *
 * 対応するサブコマンドは getKeyAgreement (0x02) のみ (hmac-secret 拡張の鍵交換用)。
 * PIN の設定・トークンの発行は未対応で、GetInfo に clientPin を含めない。
 *
 * [Ctap2Authenticator] のインスタンスごとに 1 つ持ち、`process` の直列化の内側で使う (スレッドセーフではない)。
 */
class ClientPin(
    /** 対応するプロトコルの番号 (GetInfo の pinUvAuthProtocols の順)。 */
    val supportedProtocols: List<Int> = SUPPORTED_PROTOCOLS
) {
    private val protocols: Map<Int, PinUvAuthProtocol> =
        supportedProtocols.associateWith { PinUvAuthProtocol.create(it.toLong())!! }

    /** 鍵交換の鍵を作り直す (Reset に相当)。 */
    fun regenerate() {
        protocols.values.forEach { it.regenerate() }
    }

    /**
     * 番号に対応するプロトコルを返す。未対応の番号は `0x02 INVALID_PARAMETER`。
     * [version] が null の場合は Protocol 1 (CTAP 2.1 §12.5 の hmac-secret の既定値)。
     * Protocol 1 に対応しない場合の省略は [absentStatus]。
     */
    fun protocol(version: Long?, absentStatus: Int = CtapStatus.ERR_MISSING_PARAMETER): PinUvAuthProtocol {
        if (version == null) {
            return protocols[1] ?: throw CtapException(absentStatus, "pinUvAuthProtocol is missing")
        }
        return protocols[version.toInt().takeIf { it.toLong() == version } ?: -1]
            ?: throw CtapException(CtapStatus.ERR_INVALID_PARAMETER, "unsupported pinUvAuthProtocol $version")
    }

    /**
     * プラットフォームの鍵交換の公開鍵から共有鍵を導出する。
     * 公開鍵が不正な場合は `0x02 INVALID_PARAMETER` (CTAP 2.1 §6.5.5.5 等の decapsulate の失敗と同じ)。
     */
    fun sharedSecret(protocol: PinUvAuthProtocol, keyAgreement: Map<*, *>): ByteArray = try {
        protocol.decapsulate(keyAgreement)
    } catch (e: PinUvAuthProtocolException) {
        throw CtapException(CtapStatus.ERR_INVALID_PARAMETER, e.message ?: "invalid key agreement")
    }

    /** authenticatorClientPIN の処理。 */
    fun process(p: Map<*, *>): Map<Long, Any> {
        val version = p.requireLong(KEY_PIN_UV_AUTH_PROTOCOL)
        val subCommand = p.requireLong(KEY_SUB_COMMAND)
        val protocol = protocol(version)
        return when (subCommand) {
            SUB_GET_KEY_AGREEMENT -> linkedMapOf(RESP_KEY_AGREEMENT to protocol.getPublicKey())
            else -> throw CtapException(CtapStatus.ERR_INVALID_SUBCOMMAND, "unsupported clientPIN subcommand $subCommand")
        }
    }

    private fun Map<*, *>.requireLong(key: Long): Long {
        if (!has(key)) throw CtapException(CtapStatus.ERR_MISSING_PARAMETER)
        return this[key] as? Long ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
    }

    companion object {
        /** GetInfo の pinUvAuthProtocols (0x06) に広告するプロトコル。 */
        val SUPPORTED_PROTOCOLS: List<Int> = listOf(1)

        const val KEY_PIN_UV_AUTH_PROTOCOL: Long = 0x01
        const val KEY_SUB_COMMAND: Long = 0x02
        const val KEY_KEY_AGREEMENT: Long = 0x03

        const val SUB_GET_KEY_AGREEMENT: Long = 0x02

        const val RESP_KEY_AGREEMENT: Long = 0x01
    }
}
