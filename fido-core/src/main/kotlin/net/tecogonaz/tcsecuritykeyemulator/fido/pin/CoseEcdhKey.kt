// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.pin

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * 鍵交換用の COSE_Key (CTAP 2.1 §6.5.6 getPublicKey の形式)。
 *
 * `{1: 2 (EC2), 3: -25 (ECDH-ES+HKDF-256), -1: 1 (P-256), -2: x, -3: y}`。
 * alg の -25 は仕様上の固定値で、実際に使う鍵導出はプロトコルごとに異なる。
 */
object CoseEcdhKey {
    const val KTY_EC2: Long = 2
    const val ALG_ECDH_ES_HKDF_256: Long = -25
    const val CRV_P256: Long = 1
    private const val COORDINATE_LENGTH = 32

    // P-256 (secp256r1) のパラメータ (SEC 2 §2.4.2)
    private val P = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    private val A = P.subtract(BigInteger.valueOf(3))
    private val B = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)

    fun encode(x: ByteArray, y: ByteArray): Map<Long, Any> = linkedMapOf(
        1L to KTY_EC2,
        3L to ALG_ECDH_ES_HKDF_256,
        -1L to CRV_P256,
        -2L to x,
        -3L to y
    )

    /**
     * プラットフォームの公開鍵 (COSE_Key) を検証して P-256 の公開鍵に変換する。
     *
     * kty・crv が EC2 / P-256 であること、座標が 32 バイトであること、点が曲線上にあることを確認する。
     * alg は省略を許し、指定されていれば -25 であること。
     */
    fun decode(cose: Map<*, *>): ECPublicKey {
        if (cose[1L] != KTY_EC2) throw PinUvAuthProtocolException("key agreement kty must be EC2")
        if (cose[-1L] != CRV_P256) throw PinUvAuthProtocolException("key agreement curve must be P-256")
        if (cose.containsKey(3L) && cose[3L] != ALG_ECDH_ES_HKDF_256) {
            throw PinUvAuthProtocolException("key agreement alg must be -25")
        }
        val xBytes = cose[-2L] as? ByteArray ?: throw PinUvAuthProtocolException("key agreement x is missing")
        val yBytes = cose[-3L] as? ByteArray ?: throw PinUvAuthProtocolException("key agreement y is missing")
        if (xBytes.size != COORDINATE_LENGTH || yBytes.size != COORDINATE_LENGTH) {
            throw PinUvAuthProtocolException("key agreement coordinates must be 32 bytes")
        }
        val x = BigInteger(1, xBytes)
        val y = BigInteger(1, yBytes)
        if (!isOnCurve(x, y)) throw PinUvAuthProtocolException("key agreement point is not on P-256")
        return try {
            KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), p256Spec())) as ECPublicKey
        } catch (e: Exception) {
            throw PinUvAuthProtocolException("key agreement key is invalid: ${e.javaClass.simpleName}")
        }
    }

    /** y² = x³ + ax + b (mod p) を満たし、座標が体の範囲内にあるか。 */
    fun isOnCurve(x: BigInteger, y: BigInteger): Boolean {
        if (x.signum() < 0 || x >= P || y.signum() < 0 || y >= P) return false
        val left = y.multiply(y).mod(P)
        val right = x.multiply(x).multiply(x).add(A.multiply(x)).add(B).mod(P)
        return left == right
    }

    fun p256Spec(): ECParameterSpec =
        AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
}

/** PIN/UV Auth Protocol の入力が不正であることを示す例外。呼び出し側で CTAP のステータスに変換する。 */
class PinUvAuthProtocolException(message: String) : Exception(message)
