// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.pin

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** HKDF-SHA-256 (RFC 5869)。PIN/UV Auth Protocol 2 の鍵導出に使う。 */
object Hkdf {
    private const val ALGORITHM = "HmacSHA256"
    private const val HASH_LENGTH = 32

    /** HKDF-Extract。空の [salt] は「ハッシュ長の 0」として扱う (RFC 5869 §2.2)。 */
    fun extract(salt: ByteArray, ikm: ByteArray): ByteArray =
        hmacSha256(if (salt.isEmpty()) ByteArray(HASH_LENGTH) else salt, ikm)

    /** HKDF-Expand。[length] は 255 × 32 バイト以下。 */
    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * HASH_LENGTH) { "invalid HKDF output length: $length" }
        val mac = Mac.getInstance(ALGORITHM).apply { init(SecretKeySpec(prk, ALGORITHM)) }
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            val n = minOf(previous.size, length - offset)
            System.arraycopy(previous, 0, out, offset, n)
            offset += n
            counter++
        }
        return out
    }

    fun derive(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int): ByteArray =
        expand(extract(salt, ikm), info, length)

    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray =
        Mac.getInstance(ALGORITHM).apply { init(SecretKeySpec(key, ALGORITHM)) }.doFinal(message)
}
