// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.has
import net.tecogonaz.tcsecuritykeyemulator.fido.pin.Hkdf
import net.tecogonaz.tcsecuritykeyemulator.fido.pin.PinUvAuthProtocol
import net.tecogonaz.tcsecuritykeyemulator.fido.pin.PinUvAuthProtocolException

/**
 * GetAssertion の hmac-secret 入力を検証・復号した結果。
 * GetNextAssertion でも同じ salt と共有鍵で各 credential の出力を作る。
 */
class HmacSecretInput(
    val protocol: PinUvAuthProtocol,
    val sharedSecret: ByteArray,
    /** salt1 (と salt2)。各 32 バイト。 */
    val salts: List<ByteArray>
)

/** hmac-secret 拡張 (CTAP 2.1 §12.5、DD-01 §11)。 */
object HmacSecret {
    const val ID: String = "hmac-secret"

    private const val KEY_KEY_AGREEMENT: Long = 0x01
    private const val KEY_SALT_ENC: Long = 0x02
    private const val KEY_SALT_AUTH: Long = 0x03
    private const val KEY_PIN_UV_AUTH_PROTOCOL: Long = 0x04
    private const val SALT_LENGTH = 32

    /** MakeCredential の extensions に `"hmac-secret": true` があるか。値が真偽値でなければ `0x11`。 */
    fun requested(extensions: Map<*, *>?): Boolean {
        return extensions?.optBool(ID) ?: false
    }

    /** GetAssertion の extensions に hmac-secret の入力があるか。 */
    fun present(extensions: Map<*, *>?): Boolean = extensions != null && extensions.has(ID)

    /**
     * GetAssertion の hmac-secret 入力を検証して salt を復号する。入力がなければ null。
     *
     * | 条件 | ステータス |
     * |---|---|
     * | 入力が map でない、各項目の型が不正 | `0x11` |
     * | keyAgreement・saltEnc・saltAuth の欠落 | `0x14` |
     * | 未対応の pinUvAuthProtocol、鍵交換の公開鍵の不正 | `0x02` |
     * | pinUvAuthProtocol の省略で Protocol 1 に未対応 | `0x33` |
     * | saltAuth の不一致 | `0x33` |
     * | saltEnc を復号できない、復号結果が 32 / 64 バイトでない | `0x02` |
     */
    fun parse(extensions: Map<*, *>?, clientPin: ClientPin): HmacSecretInput? {
        if (!present(extensions)) return null
        val input = extensions!!.requireMap(ID)
        val keyAgreement = input.requireMap(KEY_KEY_AGREEMENT)
        val saltEnc = input.requireBytes(KEY_SALT_ENC)
        val saltAuth = input.requireBytes(KEY_SALT_AUTH)
        val version = input.optLong(KEY_PIN_UV_AUTH_PROTOCOL)
        val protocol = clientPin.protocol(version, absentStatus = CtapStatus.ERR_PIN_AUTH_INVALID)
        val sharedSecret = clientPin.sharedSecret(protocol, keyAgreement)
        if (!protocol.verify(sharedSecret, saltEnc, saltAuth)) {
            throw CtapException(CtapStatus.ERR_PIN_AUTH_INVALID, "saltAuth mismatch")
        }
        val salts = try {
            protocol.decrypt(sharedSecret, saltEnc)
        } catch (e: PinUvAuthProtocolException) {
            throw CtapException(CtapStatus.ERR_INVALID_PARAMETER, e.message ?: "saltEnc cannot be decrypted")
        }
        if (salts.size != SALT_LENGTH && salts.size != 2 * SALT_LENGTH) {
            throw CtapException(CtapStatus.ERR_INVALID_PARAMETER, "salts must be 32 or 64 bytes")
        }
        return HmacSecretInput(
            protocol, sharedSecret,
            (0 until salts.size / SALT_LENGTH).map { salts.copyOfRange(it * SALT_LENGTH, (it + 1) * SALT_LENGTH) }
        )
    }

    /** 各 salt の `HMAC-SHA-256(CredRandom, salt)` を連結し、共有鍵で暗号化した出力。 */
    fun output(input: HmacSecretInput, credRandom: ByteArray): ByteArray {
        val outputs = input.salts.fold(ByteArray(0)) { acc, salt -> acc + Hkdf.hmacSha256(credRandom, salt) }
        return input.protocol.encrypt(input.sharedSecret, outputs)
    }
}
