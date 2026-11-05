// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.pin

import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Hex
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestPlatform
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger

class PinUvAuthProtocolTest {
    private val protocols: List<() -> PinUvAuthProtocol> = listOf({ PinUvAuthProtocolOne() }, { PinUvAuthProtocolTwo() })

    // ------------------------------------------------------------------ HKDF (RFC 5869 付録 A.1〜A.3)

    @Test
    fun hkdfMatchesRfc5869TestVectors() {
        data class Case(val ikm: String, val salt: String, val info: String, val length: Int, val prk: String, val okm: String)
        val cases = listOf(
            Case(
                "0b".repeat(22), "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            ),
            Case(
                range(0x00, 0x4f), range(0x60, 0xaf), range(0xb0, 0xff), 82,
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
                    "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
                    "cc30c58179ec3e87c14c01d5c1f3434f1d87"
            ),
            Case(
                "0b".repeat(22), "", "", 42,
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
            )
        )
        for (c in cases) {
            val prk = Hkdf.extract(Hex.decode(c.salt), Hex.decode(c.ikm))
            assertEquals(c.prk, Hex.encode(prk))
            assertEquals(c.okm, Hex.encode(Hkdf.expand(prk, Hex.decode(c.info), c.length)))
        }
    }

    // ------------------------------------------------------------------ 共有鍵・暗号化・HMAC

    @Test
    fun sharedSecretMatchesThePlatformSide() {
        for (create in protocols) {
            val auth = create()
            val platform = TestPlatform(auth.version)
            val secret = auth.decapsulate(platform.keyAgreement)
            assertArrayEquals("protocol ${auth.version}", platform.sharedSecret(auth.getPublicKey()), secret)
            assertEquals(if (auth.version == 1) 32 else 64, secret.size)
        }
    }

    @Test
    fun encryptionRoundTripsWithThePlatform() {
        for (create in protocols) {
            val auth = create()
            val platform = TestPlatform(auth.version)
            val secret = auth.decapsulate(platform.keyAgreement)
            val platformSecret = platform.sharedSecret(auth.getPublicKey())
            val message = ByteArray(64) { it.toByte() }

            // 認証器 → プラットフォーム
            assertArrayEquals(message, platform.decrypt(platformSecret, auth.encrypt(secret, message)))
            // プラットフォーム → 認証器
            assertArrayEquals(message, auth.decrypt(secret, platform.encrypt(platformSecret, message)))
        }
    }

    @Test
    fun protocolOneUsesAZeroIvAndProtocolTwoARandomIv() {
        val message = ByteArray(32) { 7 }
        val one = PinUvAuthProtocolOne()
        val s1 = one.decapsulate(TestPlatform(1).keyAgreement)
        assertArrayEquals(one.encrypt(s1, message), one.encrypt(s1, message))
        assertEquals(32, one.encrypt(s1, message).size)

        val two = PinUvAuthProtocolTwo()
        val s2 = two.decapsulate(TestPlatform(2).keyAgreement)
        assertFalse(two.encrypt(s2, message).contentEquals(two.encrypt(s2, message)))
        assertEquals(48, two.encrypt(s2, message).size)
    }

    @Test
    fun authenticateMatchesThePlatformAndVerifyRejectsTampering() {
        for (create in protocols) {
            val auth = create()
            val platform = TestPlatform(auth.version)
            val secret = auth.decapsulate(platform.keyAgreement)
            val message = "clientDataHash-or-salt".toByteArray()
            val mac = platform.authenticate(platform.sharedSecret(auth.getPublicKey()), message)
            assertEquals(if (auth.version == 1) 16 else 32, mac.size)
            assertArrayEquals(mac, auth.authenticate(secret, message))
            assertTrue(auth.verify(secret, message, mac))

            val tampered = mac.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
            assertFalse(auth.verify(secret, message, tampered))
            assertFalse(auth.verify(secret, message, mac.copyOf(mac.size - 1)))
            assertFalse(auth.verify(secret, message + 0, mac))
        }
    }

    @Test
    fun tokensCanBeUsedAsHmacKeys() {
        val token = ByteArray(32) { (it * 3).toByte() }
        val message = ByteArray(32) { 1 }
        val expected = Hkdf.hmacSha256(token, message)
        assertArrayEquals(expected.copyOf(16), PinUvAuthProtocolOne().authenticate(token, message))
        // Protocol 1 は 16 バイトのトークンも受け付ける
        val shortToken = token.copyOf(16)
        assertArrayEquals(
            Hkdf.hmacSha256(shortToken, message).copyOf(16),
            PinUvAuthProtocolOne().authenticate(shortToken, message)
        )
        assertArrayEquals(expected, PinUvAuthProtocolTwo().authenticate(token, message))
        expectFailure { PinUvAuthProtocolTwo().authenticate(token.copyOf(16), message) }
    }

    @Test
    fun regenerateChangesTheKeyAgreementKey() {
        for (create in protocols) {
            val auth = create()
            val platform = TestPlatform(auth.version)
            val before = auth.getPublicKey()
            val secretBefore = auth.decapsulate(platform.keyAgreement)
            auth.regenerate()
            assertNotEquals(Hex.encode(before[-2L] as ByteArray), Hex.encode(auth.getPublicKey()[-2L] as ByteArray))
            assertFalse(secretBefore.contentEquals(auth.decapsulate(platform.keyAgreement)))
        }
    }

    @Test
    fun publicKeyIsACoseEcdhKey() {
        val key = PinUvAuthProtocolTwo().getPublicKey()
        assertEquals(2L, key[1L])
        assertEquals(-25L, key[3L])
        assertEquals(1L, key[-1L])
        assertEquals(32, (key[-2L] as ByteArray).size)
        assertEquals(32, (key[-3L] as ByteArray).size)
        assertTrue(CoseEcdhKey.isOnCurve(BigInteger(1, key[-2L] as ByteArray), BigInteger(1, key[-3L] as ByteArray)))
    }

    // ------------------------------------------------------------------ 不正な入力

    @Test
    fun invalidPeerKeysAreRejected() {
        val valid = TestPlatform(2).keyAgreement
        val offCurveY = (valid[-3L] as ByteArray).copyOf().also { it[31] = (it[31].toInt() xor 1).toByte() }
        val invalid = listOf(
            valid + (-3L to offCurveY),                    // 曲線外の点
            valid + (1L to 1L),                            // kty = OKP
            valid + (-1L to 2L),                           // crv = P-384
            valid + (3L to -7L),                           // alg が -25 でない
            valid + (-2L to ByteArray(31)),                // 座標の長さ
            valid - (-3L),                                 // y がない
            valid + (-2L to "x"),                          // 型の不正
            valid + (-2L to ByteArray(32) { 0xFF.toByte() }) // p 以上の座標
        )
        for (key in invalid) {
            for (create in protocols) expectFailure { create().decapsulate(key) }
        }
        // alg は省略できる
        PinUvAuthProtocolTwo().decapsulate(valid - 3L)
    }

    @Test
    fun invalidCiphertextLengthsAreRejected() {
        val one = PinUvAuthProtocolOne()
        val s1 = one.decapsulate(TestPlatform(1).keyAgreement)
        for (n in listOf(0, 15, 17, 33)) expectFailure { one.decrypt(s1, ByteArray(n)) }
        expectFailure { one.encrypt(s1, ByteArray(20)) }
        expectFailure { one.decrypt(ByteArray(16), ByteArray(16)) }

        val two = PinUvAuthProtocolTwo()
        val s2 = two.decapsulate(TestPlatform(2).keyAgreement)
        for (n in listOf(0, 15, 16, 31, 33)) expectFailure { two.decrypt(s2, ByteArray(n)) }
        expectFailure { two.decrypt(s2.copyOf(32), ByteArray(32)) }
    }

    @Test
    fun createReturnsNullForUnknownVersions() {
        assertEquals(1, PinUvAuthProtocol.create(1)?.version)
        assertEquals(2, PinUvAuthProtocol.create(2)?.version)
        assertEquals(null, PinUvAuthProtocol.create(3))
        assertEquals(null, PinUvAuthProtocol.create(0))
    }

    private fun expectFailure(block: () -> Unit) {
        try {
            block()
            fail("expected PinUvAuthProtocolException")
        } catch (_: PinUvAuthProtocolException) {
        }
    }

    private fun range(from: Int, to: Int): String = Hex.encode(ByteArray(to - from + 1) { (from + it).toByte() })
}
