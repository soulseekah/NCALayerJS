// Minimal BER/DER reader. Supports indefinite lengths, which Kalkan uses
// in PKCS#12 files. Only low tag numbers (0..30) are supported.

export const TAG = {
	BOOLEAN: 0x01,
	INTEGER: 0x02,
	BIT_STRING: 0x03,
	OCTET_STRING: 0x04,
	NULL: 0x05,
	OID: 0x06,
	UTF8_STRING: 0x0c,
	UTC_TIME: 0x17,
	GENERALIZED_TIME: 0x18,
	SEQUENCE: 0x30,
	SET: 0x31,
};

/**
 * Parses one BER element.
 *
 * @param {Uint8Array} buf Input buffer.
 * @param {number} pos Offset of the tag byte.
 * @returns {{tag: number, value: Buffer|null, children: Array|null, raw: Buffer, end: number}}
 *   Primitive nodes have value, constructed nodes have children. Raw holds
 *   the full encoding including the header.
 */
export function parseBer(buf, pos = 0) {
	buf = Buffer.isBuffer(buf) ? buf : Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
	if (pos >= buf.length) {
		throw new Error(`BER: unexpected end of data at ${pos}`);
	}
	const tag = buf[pos];
	if ((tag & 0x1f) === 0x1f) {
		throw new Error('BER: high tag numbers are not supported');
	}
	const constructed = (tag & 0x20) !== 0;
	let p = pos + 1;
	let len = buf[p++];
	const indefinite = len === 0x80;
	if (!indefinite && (len & 0x80)) {
		const n = len & 0x7f;
		if (n > 4) {
			throw new Error('BER: length too large');
		}
		len = 0;
		for (let i = 0; i < n; i++) {
			len = len * 256 + buf[p++];
		}
	}
	if (!constructed) {
		if (indefinite) {
			throw new Error('BER: indefinite length on a primitive element');
		}
		if (p + len > buf.length) {
			throw new Error('BER: element exceeds buffer');
		}
		return { tag, value: buf.subarray(p, p + len), children: null, raw: buf.subarray(pos, p + len), end: p + len };
	}
	const children = [];
	if (indefinite) {
		while (!(buf[p] === 0 && buf[p + 1] === 0)) {
			const child = parseBer(buf, p);
			children.push(child);
			p = child.end;
		}
		return { tag, value: null, children, raw: buf.subarray(pos, p + 2), end: p + 2 };
	}
	const end = p + len;
	if (end > buf.length) {
		throw new Error('BER: element exceeds buffer');
	}
	while (p < end) {
		const child = parseBer(buf, p);
		children.push(child);
		p = child.end;
	}
	if (p !== end) {
		throw new Error('BER: child overruns parent');
	}
	return { tag, value: null, children, raw: buf.subarray(pos, end), end };
}

/**
 * Returns the bytes of an OCTET STRING, joining constructed parts.
 *
 * @param {object} node Parsed BER node.
 * @returns {Buffer}
 */
export function octets(node) {
	if (node.value) {
		return node.value;
	}
	return Buffer.concat(node.children.map(octets));
}

/**
 * Decodes an OBJECT IDENTIFIER node to dotted form.
 *
 * @param {object} node Parsed BER node with tag 0x06.
 * @returns {string}
 */
export function oid(node) {
	if (node.tag !== TAG.OID) {
		throw new Error(`BER: expected OID, got tag 0x${node.tag.toString(16)}`);
	}
	const bytes = node.value;
	const parts = [];
	let v = 0;
	for (const b of bytes) {
		v = v * 128 + (b & 0x7f);
		if (!(b & 0x80)) {
			if (!parts.length) {
				// First arc is 0, 1 or 2; arc 2 takes all values from 80.
				const first = Math.min(Math.floor(v / 40), 2);
				parts.push(first, v - first * 40);
			} else {
				parts.push(v);
			}
			v = 0;
		}
	}
	return parts.join('.');
}

/**
 * Converts bytes to an unsigned BigInt.
 *
 * @param {Uint8Array} bytes Input bytes.
 * @param {boolean} littleEndian Byte order of the input.
 * @returns {bigint}
 */
export function toBigInt(bytes, littleEndian = false) {
	const ordered = littleEndian ? Buffer.from(bytes).reverse() : Buffer.from(bytes);
	return ordered.length ? BigInt('0x' + ordered.toString('hex')) : 0n;
}

/**
 * Converts an unsigned BigInt to a fixed number of bytes.
 *
 * @param {bigint} n Value, must fit in size bytes.
 * @param {number} size Output length.
 * @param {boolean} littleEndian Byte order of the output.
 * @returns {Buffer}
 */
export function fromBigInt(n, size, littleEndian = false) {
	if (n < 0n) {
		throw new Error('fromBigInt: negative value');
	}
	const hex = n.toString(16).padStart(size * 2, '0');
	if (hex.length > size * 2) {
		throw new Error(`fromBigInt: value does not fit in ${size} bytes`);
	}
	const out = Buffer.from(hex, 'hex');
	return littleEndian ? out.reverse() : out;
}

/**
 * Parses UTCTime or GeneralizedTime in the forms DER allows: UTC with a
 * trailing Z, and for GeneralizedTime optional fractional seconds, which
 * timestamp authorities use.
 *
 * @param {object} node Parsed time node.
 * @returns {Date}
 */
export function parseTime(node) {
	const s = node.value.toString('ascii');
	let m;
	if (node.tag === TAG.UTC_TIME) {
		m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
	} else if (node.tag === TAG.GENERALIZED_TIME) {
		m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z$/.exec(s);
	}
	if (!m) {
		throw new Error(`BER: unsupported time ${s}`);
	}
	let year = Number(m[1]);
	if (node.tag === TAG.UTC_TIME) {
		year += year < 50 ? 2000 : 1900;
	}
	const ms = m[7] ? Math.floor(Number('0.' + m[7]) * 1000) : 0;
	return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]), ms));
}
