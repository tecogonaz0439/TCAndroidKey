// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.fido.cbor

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * CTAP2 で必要な範囲の CBOR (RFC 8949) エンコーダ／デコーダ。
 *
 * デコード結果は次の Kotlin 型で表現する。
 * - 整数: [Long]
 * - バイト列: [ByteArray]
 * - テキスト: [String]
 * - 配列: [List]
 * - マップ: [Map] (挿入順を保持する [LinkedHashMap])
 * - 真偽値: [Boolean]、null: `null`
 * - 浮動小数点: [Double]
 *
 * エンコードは CTAP2 canonical CBOR 形式 (最短長の整数表現、マップキーの正規順序) で行う。
 *
 * デコードは CTAP2 の要求に合わせて次を拒否する: 不定長、最短でない整数・長さの表現、タグ、
 * 不正な UTF-8、重複キー、末尾の余分なデータ、深すぎる入れ子。
 * マップキーの並び順は検証しない (クライアントの互換性を優先する)。
 */
class CborException(message: String) : Exception(message)

object Cbor {
    private const val MAX_DEPTH = 16

    // ------------------------------------------------------------------ encode

    fun encode(value: Any?): ByteArray {
        val out = ByteArrayOutputStream()
        encodeTo(out, value)
        return out.toByteArray()
    }

    private fun encodeTo(out: ByteArrayOutputStream, value: Any?) {
        when (value) {
            null -> out.write(0xF6)
            is Boolean -> out.write(if (value) 0xF5 else 0xF4)
            is Int -> encodeInteger(out, value.toLong())
            is Long -> encodeInteger(out, value)
            is Short -> encodeInteger(out, value.toLong())
            is Byte -> encodeInteger(out, value.toLong())
            is ByteArray -> {
                writeHead(out, 2, value.size.toLong())
                out.write(value)
            }
            is String -> {
                val bytes = value.toByteArray(Charsets.UTF_8)
                writeHead(out, 3, bytes.size.toLong())
                out.write(bytes)
            }
            is List<*> -> {
                writeHead(out, 4, value.size.toLong())
                value.forEach { encodeTo(out, it) }
            }
            is Map<*, *> -> {
                val entries = value.entries.map { (k, v) -> encode(k) to v }
                    .sortedWith { a, b -> compareCanonical(a.first, b.first) }
                for (i in 1 until entries.size) {
                    if (entries[i - 1].first.contentEquals(entries[i].first)) {
                        throw CborException("duplicate map key")
                    }
                }
                writeHead(out, 5, entries.size.toLong())
                entries.forEach { (k, v) ->
                    out.write(k)
                    encodeTo(out, v)
                }
            }
            is Double -> {
                out.write(0xFB)
                val bits = value.toRawBits()
                for (i in 7 downTo 0) out.write(((bits ushr (8 * i)) and 0xFF).toInt())
            }
            else -> throw CborException("unsupported type: ${value::class.java.name}")
        }
    }

    /**
     * CTAP2 canonical 順序: メジャータイプ → エンコード長 → バイト列の辞書順。
     */
    private fun compareCanonical(a: ByteArray, b: ByteArray): Int {
        val ma = (a[0].toInt() and 0xFF) ushr 5
        val mb = (b[0].toInt() and 0xFF) ushr 5
        if (ma != mb) return ma.compareTo(mb)
        if (a.size != b.size) return a.size.compareTo(b.size)
        for (i in a.indices) {
            val x = a[i].toInt() and 0xFF
            val y = b[i].toInt() and 0xFF
            if (x != y) return x.compareTo(y)
        }
        return 0
    }

    private fun encodeInteger(out: ByteArrayOutputStream, v: Long) {
        if (v >= 0) writeHead(out, 0, v) else writeHead(out, 1, -1 - v)
    }

    private fun writeHead(out: ByteArrayOutputStream, major: Int, arg: Long) {
        val mt = major shl 5
        when {
            arg < 0 -> throw CborException("argument out of range")
            arg < 24 -> out.write(mt or arg.toInt())
            arg <= 0xFF -> {
                out.write(mt or 24); out.write(arg.toInt())
            }
            arg <= 0xFFFF -> {
                out.write(mt or 25)
                out.write((arg ushr 8).toInt() and 0xFF); out.write(arg.toInt() and 0xFF)
            }
            arg <= 0xFFFFFFFFL -> {
                out.write(mt or 26)
                for (i in 3 downTo 0) out.write(((arg ushr (8 * i)) and 0xFF).toInt())
            }
            else -> {
                out.write(mt or 27)
                for (i in 7 downTo 0) out.write(((arg ushr (8 * i)) and 0xFF).toInt())
            }
        }
    }

    // ------------------------------------------------------------------ decode

    /** 先頭の 1 データ項目をデコードする。末尾に余剰バイトがある場合はエラーとする。 */
    fun decode(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Any? {
        val reader = Reader(data, offset, offset + length)
        val value = reader.readItem(0)
        if (reader.pos != offset + length) throw CborException("trailing bytes")
        return value
    }

    /** 先頭の 1 データ項目をデコードし、値と消費バイト数を返す。 */
    fun decodeFirst(data: ByteArray, offset: Int = 0): Pair<Any?, Int> {
        val reader = Reader(data, offset, data.size)
        val value = reader.readItem(0)
        return value to (reader.pos - offset)
    }

    private class Reader(val data: ByteArray, var pos: Int, val end: Int) {
        fun readByte(): Int {
            if (pos >= end) throw CborException("unexpected end of data")
            return data[pos++].toInt() and 0xFF
        }

        fun readArg(info: Int): Long {
            val v: Long = when {
                info < 24 -> return info.toLong()
                info == 24 -> readByte().toLong()
                info == 25 -> ((readByte() shl 8) or readByte()).toLong()
                info == 26 -> {
                    var x = 0L
                    repeat(4) { x = (x shl 8) or readByte().toLong() }
                    x
                }
                info == 27 -> {
                    var x = 0L
                    repeat(8) { x = (x shl 8) or readByte().toLong() }
                    if (x < 0) throw CborException("integer too large")
                    x
                }
                else -> throw CborException("indefinite length or reserved info $info not supported")
            }
            // 最短表現でない符号化 (例: 18 01) は canonical CBOR ではないため拒否する。
            val minimum = when (info) {
                24 -> 24L
                25 -> 0x100L
                26 -> 0x1_0000L
                else -> 0x1_0000_0000L
            }
            if (v < minimum) throw CborException("non-canonical integer encoding")
            return v
        }

        fun readText(len: Long): String {
            val bytes = readBytes(len)
            return try {
                Charsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString()
            } catch (e: CharacterCodingException) {
                throw CborException("invalid UTF-8 in text string")
            }
        }

        fun readBytes(len: Long): ByteArray {
            if (len < 0 || len > (end - pos)) throw CborException("length exceeds data")
            val r = data.copyOfRange(pos, pos + len.toInt())
            pos += len.toInt()
            return r
        }

        fun readItem(depth: Int): Any? {
            if (depth > MAX_DEPTH) throw CborException("nesting too deep")
            val ib = readByte()
            val major = ib ushr 5
            val info = ib and 0x1F
            return when (major) {
                0 -> readArg(info)
                1 -> -1 - readArg(info)
                2 -> readBytes(readArg(info))
                3 -> readText(readArg(info))
                4 -> {
                    val n = readArg(info)
                    if (n > end - pos) throw CborException("array length exceeds data")
                    List(n.toInt()) { readItem(depth + 1) }
                }
                5 -> {
                    val n = readArg(info)
                    if (n > end - pos) throw CborException("map length exceeds data")
                    val map = LinkedHashMap<Any?, Any?>()
                    repeat(n.toInt()) {
                        val k = readItem(depth + 1)
                        if (k is ByteArray || k is List<*> || k is Map<*, *>) {
                            throw CborException("unsupported map key type")
                        }
                        if (map.containsKey(k)) throw CborException("duplicate map key")
                        map[k] = readItem(depth + 1)
                    }
                    map
                }
                6 -> throw CborException("tags are not allowed in CTAP2 CBOR")
                7 -> when (info) {
                    20 -> false
                    21 -> true
                    22, 23 -> null
                    25 -> halfToDouble(((readByte() shl 8) or readByte()))
                    26 -> {
                        var v = 0
                        repeat(4) { v = (v shl 8) or readByte() }
                        Float.fromBits(v).toDouble()
                    }
                    27 -> {
                        var v = 0L
                        repeat(8) { v = (v shl 8) or readByte().toLong() }
                        Double.fromBits(v)
                    }
                    else -> throw CborException("unsupported simple value $info")
                }
                else -> throw CborException("invalid major type")
            }
        }

        private fun halfToDouble(h: Int): Double {
            val exp = (h ushr 10) and 0x1F
            val mant = h and 0x3FF
            val v = when (exp) {
                0 -> mant * Math.pow(2.0, -24.0)
                31 -> if (mant == 0) Double.POSITIVE_INFINITY else Double.NaN
                else -> (mant + 1024) * Math.pow(2.0, exp - 25.0)
            }
            return if ((h and 0x8000) != 0) -v else v
        }
    }
}

// -------------------------------------------------------------- typed access helpers

/** CTAP の整数キー付きマップから値を取り出すためのヘルパー。 */
fun Map<*, *>.int(key: Any): Long? = this[normalizeKey(key)] as? Long
fun Map<*, *>.bytes(key: Any): ByteArray? = this[normalizeKey(key)] as? ByteArray
fun Map<*, *>.text(key: Any): String? = this[normalizeKey(key)] as? String
fun Map<*, *>.map(key: Any): Map<*, *>? = this[normalizeKey(key)] as? Map<*, *>
fun Map<*, *>.list(key: Any): List<*>? = this[normalizeKey(key)] as? List<*>
fun Map<*, *>.bool(key: Any): Boolean? = this[normalizeKey(key)] as? Boolean
fun Map<*, *>.has(key: Any): Boolean = containsKey(normalizeKey(key))

private fun normalizeKey(key: Any): Any = if (key is Int) key.toLong() else key
