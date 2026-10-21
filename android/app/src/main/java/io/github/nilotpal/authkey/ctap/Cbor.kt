package io.github.nilotpal.authkey.ctap

import java.io.ByteArrayOutputStream

/**
 * Minimal CBOR (RFC 8949) for CTAP2: unsigned/negative integers, byte and text
 * strings, arrays, maps, booleans and null.
 *
 * Decoded values: Long, ByteArray, String, Boolean, null, List<Any?>, Map<Any?, Any?>.
 * Maps are encoded in CTAP2 canonical order (integer keys ascending, then text
 * keys by length and bytes), which the device's parser relies on.
 */
object Cbor {

    fun encode(value: Any?): ByteArray = ByteArrayOutputStream().also { write(it, value) }.toByteArray()

    fun decode(data: ByteArray): Any? = Reader(data).read()

    /** Decodes one item from the front of [data]; returns it and the bytes it used. */
    fun decodePrefix(data: ByteArray): Pair<Any?, Int> {
        val r = Reader(data)
        val v = r.read()
        return v to r.pos
    }

    private fun head(out: ByteArrayOutputStream, major: Int, n: Long) {
        val m = major shl 5
        when {
            n < 24 -> out.write(m or n.toInt())
            n < 0x100 -> { out.write(m or 24); out.write(n.toInt()) }
            n < 0x10000 -> { out.write(m or 25); for (s in intArrayOf(8, 0)) out.write((n shr s).toInt() and 0xFF) }
            n < 0x100000000L -> { out.write(m or 26); for (s in intArrayOf(24, 16, 8, 0)) out.write((n shr s).toInt() and 0xFF) }
            else -> { out.write(m or 27); for (s in 56 downTo 0 step 8) out.write((n shr s).toInt() and 0xFF) }
        }
    }

    private fun write(out: ByteArrayOutputStream, v: Any?) {
        when (v) {
            null -> out.write(0xF6)
            is Boolean -> out.write(if (v) 0xF5 else 0xF4)
            is Int, is Long -> {
                val n = (v as Number).toLong()
                if (n >= 0) head(out, 0, n) else head(out, 1, -1 - n)
            }
            is ByteArray -> { head(out, 2, v.size.toLong()); out.write(v) }
            is String -> { val b = v.toByteArray(Charsets.UTF_8); head(out, 3, b.size.toLong()); out.write(b) }
            is List<*> -> { head(out, 4, v.size.toLong()); v.forEach { write(out, it) } }
            is Map<*, *> -> {
                head(out, 5, v.size.toLong())
                val ints = v.keys.filterIsInstance<Number>().sortedBy { it.toLong() }
                val texts = v.keys.filterIsInstance<String>()
                    .sortedWith(compareBy<String>({ it.toByteArray().size }, { it }))
                for (k in ints + texts) { write(out, k); write(out, v[k]) }
            }
            else -> throw IllegalArgumentException("can't CBOR-encode ${v::class.java}")
        }
    }

    private class Reader(val d: ByteArray) {
        var pos = 0

        private fun byte(): Int {
            if (pos >= d.size) throw IllegalArgumentException("truncated CBOR")
            return d[pos++].toInt() and 0xFF
        }

        private fun arg(info: Int): Long = when {
            info < 24 -> info.toLong()
            info == 24 -> byte().toLong()
            info == 25 -> ((byte() shl 8) or byte()).toLong()
            info == 26 -> (0 until 4).fold(0L) { a, _ -> (a shl 8) or byte().toLong() }
            info == 27 -> (0 until 8).fold(0L) { a, _ -> (a shl 8) or byte().toLong() }
            else -> throw IllegalArgumentException("unsupported CBOR length")
        }

        fun read(): Any? {
            val b = byte()
            val major = b shr 5
            val info = b and 0x1F
            return when (major) {
                0 -> arg(info)
                1 -> -1 - arg(info)
                2 -> { val n = arg(info).toInt(); d.copyOfRange(pos, pos + n).also { pos += n } }
                3 -> { val n = arg(info).toInt(); String(d, pos, n, Charsets.UTF_8).also { pos += n } }
                4 -> List(arg(info).toInt()) { read() }
                5 -> { val n = arg(info).toInt(); LinkedHashMap<Any?, Any?>().apply { repeat(n) { put(read(), read()) } } }
                7 -> when (info) {
                    20 -> false
                    21 -> true
                    22, 23 -> null
                    else -> throw IllegalArgumentException("unsupported CBOR simple value $info")
                }
                else -> throw IllegalArgumentException("unsupported CBOR major type $major")
            }
        }
    }
}

/** Typed access to CTAP response maps (integer keys arrive as Long). */
fun Map<*, *>.int(key: Int): Any? = this[key.toLong()]
