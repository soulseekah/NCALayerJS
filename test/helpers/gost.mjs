// Test helpers: throwaway GOST 2015 512 keys and self-signed certificates
// in the same layout as NCA RK certificates.

import { randomBytes } from 'node:crypto';
import { seq, setOf, int, oid, tlv, octetString, time, context, algorithm } from '../../src/der.mjs';
import { fromBigInt, TAG } from '../../src/ber.mjs';
import { CURVES, publicKey, sign } from '../../src/gost3410.mjs';
import { streebog512 } from '../../src/streebog.mjs';
import { parseCertificate } from '../../src/x509.mjs';
import { OID, encodeSpki, encodeSignature, hashToInteger } from '../../src/kalkan.mjs';

export const curve = CURVES['tc26-512-A'];

const KEY_USAGE_BITS = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];

/**
 * Returns a random private key.
 *
 * @returns {bigint}
 */
export function randomKey() {
	return (BigInt('0x' + randomBytes(64).toString('hex')) % (curve.q - 1n)) + 1n;
}

/**
 * Encodes a private key as Kalkan PrivateKeyInfo.
 *
 * @param {bigint} d Private key.
 * @returns {Buffer}
 */
export function encodePkcs8(d) {
	const alg = seq(oid(OID.GOST2015_512_KEY), seq(oid(OID.GOST2015_512_CURVE_A), oid(OID.STREEBOG_512)));
	return seq(int(0), alg, octetString(octetString(fromBigInt(d, 64, true))));
}

/**
 * Builds a self-signed certificate for a key.
 *
 * @param {bigint} d Private key.
 * @param {object} [options]
 * @param {string} [options.cn] Common name.
 * @param {bigint} [options.serial] Serial number.
 * @param {Array<Array<string>>} [options.extraSubject] More [oid, value] subject attributes.
 * @param {Array<string>} [options.extKeyUsage] EKU OIDs; no extension when omitted.
 * @param {Array<string>} [options.keyUsage] KeyUsage bit names; no extension when omitted.
 * @param {Date} [options.notBefore] Start of validity.
 * @param {Date} [options.notAfter] End of validity.
 * @returns {Buffer} DER certificate.
 */
export function selfSignedCertificate(d, {
	cn = 'NCALayerJS test',
	serial = 0x1234n,
	extraSubject = [],
	extKeyUsage = null,
	keyUsage = null,
	notBefore = new Date('2026-01-01T00:00:00Z'),
	notAfter = new Date('2027-12-31T00:00:00Z'),
} = {}) {
	const rdn = (type, value) => setOf(seq(oid(type), tlv(TAG.UTF8_STRING, Buffer.from(value, 'utf8'))));
	const name = seq(rdn('2.5.4.3', cn), ...extraSubject.map(([type, value]) => rdn(type, value)));
	const exts = [];
	if (keyUsage) {
		// BIT STRING with bit 0 as the most significant bit of the first byte.
		const bits = Buffer.alloc(2);
		for (const name of keyUsage) {
			const i = KEY_USAGE_BITS.indexOf(name);
			bits[i >> 3] |= 0x80 >> (i & 7);
		}
		exts.push(seq(oid('2.5.29.15'), octetString(tlv(TAG.BIT_STRING, Buffer.concat([Buffer.from([0]), bits])))));
	}
	if (extKeyUsage) {
		exts.push(seq(oid('2.5.29.37'), octetString(seq(...extKeyUsage.map((o) => oid(o))))));
	}
	const extensions = exts.length ? context(3, seq(...exts)) : null;
	const tbs = seq(
		context(0, int(2)),
		int(serial),
		algorithm(OID.GOST2015_512_SIGN),
		name,
		seq(time(notBefore), time(notAfter)),
		name,
		encodeSpki(publicKey(curve, d)),
		extensions,
	);
	const sig = encodeSignature(sign(curve, d, hashToInteger(streebog512(tbs))), curve);
	return seq(tbs, algorithm(OID.GOST2015_512_SIGN), tlv(TAG.BIT_STRING, Buffer.concat([Buffer.from([0]), sig])));
}

/**
 * Returns a signer object like loadSigner() does.
 *
 * @param {object} [options] Passed to selfSignedCertificate().
 * @returns {{curve: object, d: bigint, certificate: object}}
 */
export function makeSigner(options) {
	const d = randomKey();
	return { curve, d, certificate: parseCertificate(selfSignedCertificate(d, options)) };
}
