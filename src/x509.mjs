// Reads the X.509 certificate fields needed for signing and verification.

import { parseBer, octets, oid, toBigInt, parseTime, TAG } from './ber.mjs';

export const OID = {
	COMMON_NAME: '2.5.4.3',
	SURNAME: '2.5.4.4',
	SERIAL_NUMBER: '2.5.4.5',
	COUNTRY: '2.5.4.6',
	ORGANIZATION: '2.5.4.10',
	ORGANIZATIONAL_UNIT: '2.5.4.11',
	GIVEN_NAME: '2.5.4.42',
	KEY_USAGE: '2.5.29.15',
	EXT_KEY_USAGE: '2.5.29.37',
};

// KeyUsage bit names, RFC 5280 section 4.2.1.3, in bit order.
const KEY_USAGE_BITS = [
	'digitalSignature',
	'nonRepudiation',
	'keyEncipherment',
	'dataEncipherment',
	'keyAgreement',
	'keyCertSign',
	'cRLSign',
	'encipherOnly',
	'decipherOnly',
];

/**
 * Decodes the attributes of a Name in order.
 *
 * @param {object} name Parsed Name node.
 * @returns {Array<{oid: string, value: string}>}
 */
function nameAttributes(name) {
	const out = [];
	for (const rdn of name.children) {
		for (const atv of rdn.children) {
			const value = atv.children[1];
			// BMPString is UTF-16BE; the other string types are ASCII or UTF-8.
			const text = value.tag === 0x1e
				? Buffer.from(value.value).swap16().toString('utf16le')
				: value.value.toString('utf8');
			out.push({ oid: oid(atv.children[0]), value: text });
		}
	}
	return out;
}

/**
 * Returns the decoded value of an extension.
 *
 * @param {object} tbs Parsed TBSCertificate node.
 * @param {string} type Extension OID.
 * @returns {object|null} Parsed extnValue, or null when absent.
 */
function extension(tbs, type) {
	const exts = tbs.children.find((n) => n.tag === 0xa3);
	for (const ext of exts ? exts.children[0].children : []) {
		if (oid(ext.children[0]) === type) {
			// Extension: extnID, critical (optional), extnValue.
			return parseBer(octets(ext.children[ext.children.length - 1]));
		}
	}
	return null;
}

/**
 * Reads the extended key usage OIDs.
 *
 * @param {object} tbs Parsed TBSCertificate node.
 * @returns {Array<string>|null} Null when the extension is absent.
 */
function extKeyUsage(tbs) {
	const value = extension(tbs, OID.EXT_KEY_USAGE);
	return value ? value.children.map(oid) : null;
}

/**
 * Reads the key usage bits as names.
 *
 * @param {object} tbs Parsed TBSCertificate node.
 * @returns {Array<string>|null} Null when the extension is absent.
 */
function keyUsage(tbs) {
	const value = extension(tbs, OID.KEY_USAGE);
	if (!value) {
		return null;
	}
	// BIT STRING: first byte is the number of unused bits, then the bits
	// from the most significant bit of the first byte on.
	const bits = value.value.subarray(1);
	return KEY_USAGE_BITS.filter((name, i) => i < bits.length * 8 && (bits[i >> 3] >> (7 - (i & 7))) & 1);
}

/**
 * Parses a DER certificate.
 *
 * @param {Buffer} der Certificate.
 * @returns {{der: Buffer, serial: bigint, serialRaw: Buffer, issuerRaw: Buffer, subjectRaw: Buffer,
 *   issuer: Array<{oid: string, value: string}>, subject: Array<{oid: string, value: string}>,
 *   notBefore: Date, notAfter: Date, signatureAlgorithm: string,
 *   keyUsage: Array<string>|null, extKeyUsage: Array<string>|null,
 *   spki: {algorithm: string, params: Array<string>, publicKey: Buffer}}}
 *   Raw fields hold complete DER encodings, ready to be copied into CMS.
 */
export function parseCertificate(der) {
	const cert = parseBer(der);
	if (cert.tag !== TAG.SEQUENCE || cert.children.length !== 3) {
		throw new Error('X.509: not a certificate');
	}
	const tbs = cert.children[0];
	// Skip the optional [0] version field.
	const off = tbs.children[0].tag === 0xa0 ? 1 : 0;
	const serial = tbs.children[off];
	const spkiNode = tbs.children[off + 5];
	const algNode = spkiNode.children[0];
	const paramsNode = algNode.children[1];
	// GOST keys use a SEQUENCE of OIDs, EC keys a single curve OID.
	let params = [];
	if (paramsNode && paramsNode.tag === TAG.OID) {
		params = [oid(paramsNode)];
	} else if (paramsNode && paramsNode.children) {
		params = paramsNode.children.filter((n) => n.tag === TAG.OID).map(oid);
	}
	const bitString = spkiNode.children[1];
	if (bitString.tag !== TAG.BIT_STRING || bitString.value[0] !== 0) {
		throw new Error('X.509: unexpected public key encoding');
	}
	const validity = tbs.children[off + 3];
	return {
		der: Buffer.from(der),
		serial: toBigInt(serial.value),
		serialRaw: Buffer.from(serial.raw),
		issuerRaw: Buffer.from(tbs.children[off + 2].raw),
		subjectRaw: Buffer.from(tbs.children[off + 4].raw),
		issuer: nameAttributes(tbs.children[off + 2]),
		subject: nameAttributes(tbs.children[off + 4]),
		notBefore: parseTime(validity.children[0]),
		notAfter: parseTime(validity.children[1]),
		signatureAlgorithm: oid(cert.children[1].children[0]),
		keyUsage: keyUsage(tbs),
		extKeyUsage: extKeyUsage(tbs),
		spki: {
			algorithm: oid(algNode.children[0]),
			params,
			publicKey: Buffer.from(bitString.value.subarray(1)),
		},
	};
}

/**
 * Converts PEM to DER. DER input is returned unchanged.
 *
 * @param {Buffer} data PEM or DER bytes.
 * @returns {Buffer}
 */
export function pemToDer(data) {
	const text = data.toString('latin1');
	if (!text.includes('-----BEGIN')) {
		return data;
	}
	return Buffer.from(text.replace(/-----[^-]+-----|\s/g, ''), 'base64');
}
