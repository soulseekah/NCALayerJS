// Minimal DER encoder. Every function returns a complete TLV as a Buffer,
// so values can be nested directly: seq(int(1), oid('1.2.3')).

import { TAG } from './ber.mjs';

/**
 * Encodes a DER length.
 *
 * @param {number} n Content length.
 * @returns {Buffer}
 */
function encodeLength(n) {
	if (n < 0x80) {
		return Buffer.from([n]);
	}
	const bytes = [];
	for (let v = n; v > 0; v = Math.floor(v / 256)) {
		bytes.unshift(v & 0xff);
	}
	return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/**
 * Encodes a TLV with the given tag byte.
 *
 * @param {number} tag Tag byte, including class and constructed bits.
 * @param {Uint8Array} content Content bytes.
 * @returns {Buffer}
 */
export function tlv(tag, content) {
	return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

/**
 * Encodes a SEQUENCE.
 *
 * @param {...Buffer} items Encoded elements, in order. Null items are skipped.
 * @returns {Buffer}
 */
export function seq(...items) {
	return tlv(TAG.SEQUENCE, Buffer.concat(items.filter(Boolean)));
}

/**
 * Encodes a SET OF, sorting elements by their encoding as DER requires.
 *
 * @param {...Buffer} items Encoded elements.
 * @returns {Buffer}
 */
export function setOf(...items) {
	return tlv(TAG.SET, Buffer.concat([...items].sort(Buffer.compare)));
}

/**
 * Encodes a non-negative INTEGER.
 *
 * @param {bigint|number} value Value, at least 0.
 * @returns {Buffer}
 */
export function int(value) {
	const n = BigInt(value);
	if (n < 0n) {
		throw new Error('DER: negative integers are not supported');
	}
	let hex = n.toString(16);
	if (hex.length % 2) {
		hex = '0' + hex;
	}
	let bytes = Buffer.from(hex, 'hex');
	// A set top bit would make the value negative.
	if (bytes[0] & 0x80) {
		bytes = Buffer.concat([Buffer.from([0]), bytes]);
	}
	return tlv(TAG.INTEGER, bytes);
}

/**
 * Encodes an OBJECT IDENTIFIER.
 *
 * @param {string} dotted OID in dotted form.
 * @returns {Buffer}
 */
export function oid(dotted) {
	const arcs = dotted.split('.').map(Number);
	if (arcs.length < 2 || arcs.some((a) => !Number.isSafeInteger(a) || a < 0) || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39)) {
		throw new Error(`DER: invalid OID ${dotted}`);
	}
	const out = [];
	for (const v of [arcs[0] * 40 + arcs[1], ...arcs.slice(2)]) {
		const chunk = [v & 0x7f];
		for (let rest = Math.floor(v / 128); rest > 0; rest = Math.floor(rest / 128)) {
			chunk.unshift((rest & 0x7f) | 0x80);
		}
		out.push(...chunk);
	}
	return tlv(TAG.OID, Buffer.from(out));
}

/**
 * Encodes an OCTET STRING.
 *
 * @param {Uint8Array} bytes Content.
 * @returns {Buffer}
 */
export function octetString(bytes) {
	return tlv(TAG.OCTET_STRING, bytes);
}

/**
 * Encodes NULL.
 *
 * @returns {Buffer}
 */
export function nul() {
	return Buffer.from([TAG.NULL, 0]);
}

/**
 * Encodes a time as UTCTime (years 1950 to 2049) or GeneralizedTime,
 * as RFC 5280 section 4.1.2.5 requires.
 *
 * @param {Date} date Time, encoded in UTC with whole seconds.
 * @returns {Buffer}
 */
export function time(date) {
	const year = date.getUTCFullYear();
	if (year >= 1950 && year < 2050) {
		return tlv(0x17, Buffer.from(timeDigits(date).slice(2), 'ascii'));
	}
	return generalizedTime(date);
}

/**
 * Encodes a time as GeneralizedTime, which timestamp tokens require.
 *
 * @param {Date} date Time, encoded in UTC with whole seconds.
 * @returns {Buffer}
 */
export function generalizedTime(date) {
	return tlv(0x18, Buffer.from(timeDigits(date), 'ascii'));
}

/**
 * Formats a date as YYYYMMDDHHMMSSZ in UTC.
 *
 * @param {Date} date Time.
 * @returns {string}
 */
function timeDigits(date) {
	const pad = (n) => String(n).padStart(2, '0');
	return String(date.getUTCFullYear()).padStart(4, '0') + pad(date.getUTCMonth() + 1) + pad(date.getUTCDate()) +
		pad(date.getUTCHours()) + pad(date.getUTCMinutes()) + pad(date.getUTCSeconds()) + 'Z';
}

/**
 * Encodes a BOOLEAN.
 *
 * @param {boolean} value Value.
 * @returns {Buffer}
 */
export function boolean(value) {
	return tlv(0x01, Buffer.from([value ? 0xff : 0x00]));
}

/**
 * Wraps encoded content in a constructed context-specific tag [n].
 * Used for EXPLICIT tags and for IMPLICIT tags over SET or SEQUENCE.
 *
 * @param {number} n Tag number, 0 to 30.
 * @param {...Buffer} items Encoded elements.
 * @returns {Buffer}
 */
export function context(n, ...items) {
	return tlv(0xa0 | n, Buffer.concat(items));
}

/**
 * Wraps an AlgorithmIdentifier with NULL parameters, as Kalkan writes them.
 *
 * @param {string} dotted Algorithm OID.
 * @returns {Buffer}
 */
export function algorithm(dotted) {
	return seq(oid(dotted), nul());
}
