// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.bool
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.bytes
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.has
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.int
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.list
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.map
import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.text

// CTAP2 のパラメータ (デコード済みの CBOR マップ) の取得。キーは整数 (Int / Long) または文字列。
// すべてのコマンド・拡張で、欠落は `0x14 MISSING_PARAMETER`、型の不正は `0x11 CBOR_UNEXPECTED_TYPE` に統一する。

internal fun Map<*, *>.requireLong(key: Any): Long = require(key) { int(it) }

internal fun Map<*, *>.requireBytes(key: Any): ByteArray = require(key) { bytes(it) }

internal fun Map<*, *>.requireText(key: Any): String = require(key) { text(it) }

internal fun Map<*, *>.requireMap(key: Any): Map<*, *> = require(key) { map(it) }

internal fun Map<*, *>.requireList(key: Any): List<*> = require(key) { list(it) }

internal fun Map<*, *>.optLong(key: Any): Long? = opt(key) { int(it) }

internal fun Map<*, *>.optBytes(key: Any): ByteArray? = opt(key) { bytes(it) }

internal fun Map<*, *>.optText(key: Any): String? = opt(key) { text(it) }

internal fun Map<*, *>.optMap(key: Any): Map<*, *>? = opt(key) { map(it) }

internal fun Map<*, *>.optList(key: Any): List<*>? = opt(key) { list(it) }

internal fun Map<*, *>.optBool(key: Any): Boolean? = opt(key) { bool(it) }

private inline fun <T> Map<*, *>.require(key: Any, get: Map<*, *>.(Any) -> T?): T {
    if (!has(key)) throw CtapException(CtapStatus.ERR_MISSING_PARAMETER, "parameter $key is missing")
    return get(key) ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "parameter $key has an unexpected type")
}

private inline fun <T> Map<*, *>.opt(key: Any, get: Map<*, *>.(Any) -> T?): T? {
    if (!has(key)) return null
    return get(key) ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "parameter $key has an unexpected type")
}
