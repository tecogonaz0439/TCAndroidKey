// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.testutil

import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.EcKeys
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * テスト用のプラットフォーム (クライアント) 側の PIN/UV Auth Protocol。
 *
 * 製品コード (`fido.pin`) を使わずに CTAP 2.1 §6.5.6 / §6.5.7 の定義どおりに実装し、照合の基準にする。
 */
class TestPlatform(val version: Int) {
    val keyPair: KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    /** プラットフォームの公開鍵 (COSE_Key)。 */
    val keyAgreement: Map<Long, Any>
        get() {
            val (x, y) = EcKeys.coordinates(keyPair.public as ECPublicKey)
            return linkedMapOf(1L to 2L, 3L to -25L, -1L to 1L, -2L to x, -3L to y)
        }

    /** プラットフォームの秘密鍵のスカラー (外部検証器への出力用)。 */
    val privateScalar: ByteArray
        get() = toFixed32((keyPair.private as ECPrivateKey).s)

    fun sharedSecret(authenticatorKey: Map<*, *>): ByteArray {
        val peer = KeyFactory.getInstance("EC").generatePublic(
            ECPublicKeySpec(
                ECPoint(BigInteger(1, authenticatorKey[-2L] as ByteArray), BigInteger(1, authenticatorKey[-3L] as ByteArray)),
                (keyPair.public as ECPublicKey).params
            )
        )
        val z = KeyAgreement.getInstance("ECDH").run {
            init(keyPair.private)
            doPhase(peer, true)
            generateSecret()
        }
        return when (version) {
            1 -> MessageDigest.getInstance("SHA-256").digest(z)
            else -> hkdf32(z, "CTAP2 HMAC key") + hkdf32(z, "CTAP2 AES key")
        }
    }

    fun encrypt(secret: ByteArray, plaintext: ByteArray): ByteArray = when (version) {
        1 -> aes(Cipher.ENCRYPT_MODE, secret, ByteArray(16), plaintext)
        else -> {
            val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
            iv + aes(Cipher.ENCRYPT_MODE, secret.copyOfRange(32, 64), iv, plaintext)
        }
    }

    fun decrypt(secret: ByteArray, ciphertext: ByteArray): ByteArray = when (version) {
        1 -> aes(Cipher.DECRYPT_MODE, secret, ByteArray(16), ciphertext)
        else -> aes(
            Cipher.DECRYPT_MODE, secret.copyOfRange(32, 64), ciphertext.copyOfRange(0, 16),
            ciphertext.copyOfRange(16, ciphertext.size)
        )
    }

    fun authenticate(key: ByteArray, message: ByteArray): ByteArray = when (version) {
        1 -> hmac(key, message).copyOf(16)
        else -> hmac(key.copyOf(32), message)
    }

    private fun hkdf32(ikm: ByteArray, info: String): ByteArray {
        val prk = hmac(ByteArray(32), ikm)
        return hmac(prk, info.toByteArray() + byteArrayOf(1))
    }

    private fun hmac(key: ByteArray, message: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(message)

    private fun aes(mode: Int, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("AES/CBC/NoPadding").run {
            init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            doFinal(data)
        }

    private fun toFixed32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size)
            else -> ByteArray(32 - raw.size) + raw
        }
    }
}
