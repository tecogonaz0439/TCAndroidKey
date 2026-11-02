// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.fido.cbor

import net.tecogonaz.tcandroidkey.fido.ctap2.Hex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CborTest {

    @Test
    fun encodesIntegersInShortestForm() {
        assertEquals("00", Hex.encode(Cbor.encode(0)))
        assertEquals("17", Hex.encode(Cbor.encode(23)))
        assertEquals("1818", Hex.encode(Cbor.encode(24)))
        assertEquals("1903e8", Hex.encode(Cbor.encode(1000)))
        assertEquals("1a000f4240", Hex.encode(Cbor.encode(1_000_000)))
        assertEquals("20", Hex.encode(Cbor.encode(-1)))
        assertEquals("26", Hex.encode(Cbor.encode(-7)))
        assertEquals("3863", Hex.encode(Cbor.encode(-100)))
    }

    @Test
    fun encodesMapKeysInCtapCanonicalOrder() {
        // RFC 8949 / CTAP2 の例: 整数キーが先、続いて短いテキストキー
        val m = linkedMapOf<Any, Any>("b" to 1, 3 to 1, "aa" to 1, -1 to 1, 1 to 1)
        val encoded = Cbor.encode(m)
        // a5 01 01 03 01 20 01 61 62 01 62 61 61 01
        assertEquals("a5010103012001616201626161 01".replace(" ", ""), Hex.encode(encoded))
    }

    @Test
    fun roundTripsNestedStructures() {
        val value = linkedMapOf<Any, Any?>(
            1L to "text",
            2L to byteArrayOf(1, 2, 3),
            3L to listOf(1L, -2L, true, false, null),
            4L to linkedMapOf("k" to linkedMapOf("n" to 5L))
        )
        val decoded = Cbor.decode(Cbor.encode(value)) as Map<*, *>
        assertEquals("text", decoded[1L])
        assertArrayEquals(byteArrayOf(1, 2, 3), decoded[2L] as ByteArray)
        assertEquals(listOf(1L, -2L, true, false, null), decoded[3L])
        assertEquals(5L, ((decoded[4L] as Map<*, *>)["k"] as Map<*, *>)["n"])
    }

    @Test
    fun decodesKnownCtapGetInfoLikeVector() {
        // {1: ["FIDO_2_0"], 3: h'00..'}
        val bytes = Hex.decode("a20181684649444f5f325f30035000000000000000000000000000000000")
        val m = Cbor.decode(bytes) as Map<*, *>
        assertEquals(listOf("FIDO_2_0"), m[1L])
        assertEquals(16, (m[3L] as ByteArray).size)
    }

    @Test(expected = CborException::class)
    fun rejectsTruncatedInput() {
        Cbor.decode(Hex.decode("a201"))
    }

    @Test(expected = CborException::class)
    fun rejectsIndefiniteLength() {
        Cbor.decode(Hex.decode("9fff"))
    }

    @Test(expected = CborException::class)
    fun rejectsTrailingBytes() {
        Cbor.decode(Hex.decode("0000"))
    }

    @Test
    fun decodeFirstReportsConsumedLength() {
        val (v, n) = Cbor.decodeFirst(Hex.decode("1903e8ff"))
        assertEquals(1000L, v)
        assertEquals(3, n)
    }

    @Test
    fun rejectsHugeDeclaredLengths() {
        val r = runCatching { Cbor.decode(Hex.decode("5affffffff")) }
        assertTrue(r.exceptionOrNull() is CborException)
    }

    // ------------------------------------------------------------------ レビュー指摘 F-11

    private fun rejects(hex: String) {
        try {
            Cbor.decode(net.tecogonaz.tcandroidkey.fido.ctap2.Hex.decode(hex))
            org.junit.Assert.fail("should reject $hex")
        } catch (e: CborException) {
            // expected
        }
    }

    @Test
    fun rejectsNonCanonicalIntegerAndLengthEncodings() {
        rejects("1801")             // 1 を 1 バイト引数で表現
        rejects("190017")           // 23 を 2 バイトで表現
        rejects("1A0000FFFF")       // 65535 を 4 バイトで表現
        rejects("1B00000000FFFFFFFF")
        rejects("5801AA")           // 長さ 1 のバイト列を 1 バイト長で表現
        rejects("B8010000")           // マップ長の非最短表現
        org.junit.Assert.assertEquals(24L, Cbor.decode(net.tecogonaz.tcandroidkey.fido.ctap2.Hex.decode("1818")))
        org.junit.Assert.assertEquals(256L, Cbor.decode(net.tecogonaz.tcandroidkey.fido.ctap2.Hex.decode("190100")))
    }

    @Test
    fun rejectsTags() {
        rejects("C0A0")
        rejects("D82401")
    }

    @Test
    fun rejectsInvalidUtf8() {
        rejects("61FF")
        rejects("62C328") // 不完全な 2 バイト文字
        org.junit.Assert.assertEquals("é", Cbor.decode(net.tecogonaz.tcandroidkey.fido.ctap2.Hex.decode("62C3A9")))
    }
}
