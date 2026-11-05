// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.pin

import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.EcKeys
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * PIN/UV Auth Protocol の認証器側 (CTAP 2.1 §6.5.4)。
 *
 * 鍵交換の鍵ペア (P-256) を保持し、プラットフォームとの共有鍵の導出・暗号化・HMAC を行う。
 * 鍵ペアはメモリ上のソフトウェア鍵で、[regenerate] (電源投入・Reset に相当) で作り直す。
 * スレッドセーフではない (呼び出し側の `Ctap2Authenticator.process` が直列化する)。
 *
 * - [PinUvAuthProtocolOne]: CTAP 2.0 / 2.1 の Protocol 1
 * - [PinUvAuthProtocolTwo]: CTAP 2.1 の Protocol 2
 */
sealed class PinUvAuthProtocol(protected val random: SecureRandom) {
    /** pinUvAuthProtocol の番号 (1 または 2)。 */
    abstract val version: Int

    private var keyPair: KeyPair = generateKeyPair()

    /** 鍵交換の鍵ペアを作り直す。以前の公開鍵で導出した共有鍵は使えなくなる。 */
    fun regenerate() {
        keyPair = generateKeyPair()
    }

    /** 鍵交換の公開鍵 (COSE_Key)。getKeyAgreement の応答に使う。 */
    fun getPublicKey(): Map<Long, Any> {
        val (x, y) = EcKeys.coordinates(keyPair.public as ECPublicKey)
        return CoseEcdhKey.encode(x, y)
    }

    /**
     * プラットフォームの公開鍵 [peerCoseKey] と ECDH を行い、共有鍵を返す。
     * @throws PinUvAuthProtocolException 公開鍵が不正な場合
     */
    fun decapsulate(peerCoseKey: Map<*, *>): ByteArray {
        val peer = CoseEcdhKey.decode(peerCoseKey)
        val z = try {
            KeyAgreement.getInstance("ECDH").run {
                init(keyPair.private)
                doPhase(peer, true)
                generateSecret()
            }
        } catch (e: Exception) {
            throw PinUvAuthProtocolException("ECDH failed: ${e.javaClass.simpleName}")
        }
        return kdf(fixed32(z))
    }

    /** 共有鍵 [key] で [plaintext] (16 バイトの倍数) を暗号化する。 */
    abstract fun encrypt(key: ByteArray, plaintext: ByteArray): ByteArray

    /**
     * 共有鍵 [key] で [ciphertext] を復号する。
     * @throws PinUvAuthProtocolException 長さが不正な場合
     */
    abstract fun decrypt(key: ByteArray, ciphertext: ByteArray): ByteArray

    /** 共有鍵または pinUvAuthToken の [key] で [message] の HMAC を計算する (プラットフォームの authenticate と同じ値)。 */
    abstract fun authenticate(key: ByteArray, message: ByteArray): ByteArray

    /** [signature] が [message] の正しい HMAC かを定数時間で比較する。長さが違えば false。 */
    fun verify(key: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        MessageDigest.isEqual(authenticate(key, message), signature)

    /** ECDH の結果 (x 座標) から共有鍵を導出する。 */
    protected abstract fun kdf(z: ByteArray): ByteArray

    protected fun aesCbc(mode: Int, key: ByteArray, iv: ByteArray, data: ByteArray, offset: Int, length: Int): ByteArray =
        Cipher.getInstance("AES/CBC/NoPadding").run {
            init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            doFinal(data, offset, length)
        }

    protected fun requireBlocks(length: Int, what: String) {
        if (length <= 0 || length % BLOCK_SIZE != 0) {
            throw PinUvAuthProtocolException("$what must be a non-empty multiple of 16 bytes (was $length)")
        }
    }

    protected fun requireKeyLength(key: ByteArray, expected: Int) {
        if (key.size != expected) throw PinUvAuthProtocolException("key must be $expected bytes (was ${key.size})")
    }

    private fun generateKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"), random)
            generateKeyPair()
        }

    private fun fixed32(z: ByteArray): ByteArray = when {
        z.size == 32 -> z
        z.size < 32 -> ByteArray(32 - z.size) + z
        else -> throw PinUvAuthProtocolException("unexpected ECDH output length ${z.size}")
    }

    companion object {
        const val BLOCK_SIZE = 16

        /** 番号に対応するプロトコルを生成する。未対応の番号は null。 */
        fun create(version: Long, random: SecureRandom = SecureRandom()): PinUvAuthProtocol? = when (version) {
            1L -> PinUvAuthProtocolOne(random)
            2L -> PinUvAuthProtocolTwo(random)
            else -> null
        }
    }
}

/**
 * Protocol 1: 共有鍵 = SHA-256(Z) (32 バイト)、AES-256-CBC (IV はすべて 0)、HMAC-SHA-256 の先頭 16 バイト。
 * pinUvAuthToken は 16 または 32 バイトを受け付ける。
 */
class PinUvAuthProtocolOne(random: SecureRandom = SecureRandom()) : PinUvAuthProtocol(random) {
    override val version: Int = 1

    override fun kdf(z: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(z)

    override fun encrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
        requireKeyLength(key, SHARED_SECRET_LENGTH)
        requireBlocks(plaintext.size, "plaintext")
        return aesCbc(Cipher.ENCRYPT_MODE, key, ZERO_IV, plaintext, 0, plaintext.size)
    }

    override fun decrypt(key: ByteArray, ciphertext: ByteArray): ByteArray {
        requireKeyLength(key, SHARED_SECRET_LENGTH)
        requireBlocks(ciphertext.size, "ciphertext")
        return aesCbc(Cipher.DECRYPT_MODE, key, ZERO_IV, ciphertext, 0, ciphertext.size)
    }

    override fun authenticate(key: ByteArray, message: ByteArray): ByteArray {
        if (key.size != 16 && key.size != 32) throw PinUvAuthProtocolException("key must be 16 or 32 bytes")
        return Hkdf.hmacSha256(key, message).copyOf(SIGNATURE_LENGTH)
    }

    companion object {
        const val SHARED_SECRET_LENGTH = 32
        const val SIGNATURE_LENGTH = 16
        private val ZERO_IV = ByteArray(BLOCK_SIZE)
    }
}

/**
 * Protocol 2: 共有鍵 = HMAC 鍵 (32) ‖ AES 鍵 (32)。いずれも HKDF-SHA-256 (salt は 32 バイトの 0) で導出する。
 * 暗号化は AES-256-CBC でランダムな IV を先頭に付ける。HMAC は 32 バイト。pinUvAuthToken は 32 バイト。
 */
class PinUvAuthProtocolTwo(random: SecureRandom = SecureRandom()) : PinUvAuthProtocol(random) {
    override val version: Int = 2

    override fun kdf(z: ByteArray): ByteArray =
        Hkdf.derive(HKDF_SALT, z, INFO_HMAC, 32) + Hkdf.derive(HKDF_SALT, z, INFO_AES, 32)

    override fun encrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
        requireKeyLength(key, SHARED_SECRET_LENGTH)
        requireBlocks(plaintext.size, "plaintext")
        val iv = ByteArray(BLOCK_SIZE).also { random.nextBytes(it) }
        return iv + aesCbc(Cipher.ENCRYPT_MODE, aesKey(key), iv, plaintext, 0, plaintext.size)
    }

    override fun decrypt(key: ByteArray, ciphertext: ByteArray): ByteArray {
        requireKeyLength(key, SHARED_SECRET_LENGTH)
        if (ciphertext.size < BLOCK_SIZE) throw PinUvAuthProtocolException("ciphertext is shorter than the IV")
        requireBlocks(ciphertext.size - BLOCK_SIZE, "ciphertext")
        val iv = ciphertext.copyOfRange(0, BLOCK_SIZE)
        return aesCbc(Cipher.DECRYPT_MODE, aesKey(key), iv, ciphertext, BLOCK_SIZE, ciphertext.size - BLOCK_SIZE)
    }

    /** [key] が共有鍵 (64 バイト) なら先頭の HMAC 鍵、pinUvAuthToken (32 バイト) ならそのまま使う。 */
    override fun authenticate(key: ByteArray, message: ByteArray): ByteArray {
        if (key.size != SHARED_SECRET_LENGTH && key.size != TOKEN_LENGTH) {
            throw PinUvAuthProtocolException("key must be 32 or 64 bytes")
        }
        return Hkdf.hmacSha256(key.copyOf(32), message)
    }

    private fun aesKey(sharedSecret: ByteArray): ByteArray = sharedSecret.copyOfRange(32, 64)

    companion object {
        const val SHARED_SECRET_LENGTH = 64
        const val TOKEN_LENGTH = 32
        private val HKDF_SALT = ByteArray(32)
        private val INFO_HMAC = "CTAP2 HMAC key".toByteArray(Charsets.US_ASCII)
        private val INFO_AES = "CTAP2 AES key".toByteArray(Charsets.US_ASCII)
    }
}
