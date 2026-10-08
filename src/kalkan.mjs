// Kazakh (Kalkan / NCA RK) GOST 2015 encodings. All numbers are stored
// little-endian, as verified against real NCA keys and Kalkan signatures:
//
// - private key: OCTET STRING with a 64-byte little-endian scalar
// - public key: OCTET STRING with x then y, each 64 bytes little-endian
// - signature: r then s, each 64 bytes little-endian
// - hash to integer: Streebog output read as little-endian

import { parseBer, oid as readOid, toBigInt, fromBigInt, TAG } from './ber.mjs';
import { seq, oid, tlv, octetString } from './der.mjs';
import { CURVE_BY_OID, isOnCurve, publicKey } from './gost3410.mjs';
import { parseCertificate } from './x509.mjs';
import { readPkcs12 } from './pkcs12.mjs';

export const OID = {
	GOST2015_512_KEY: '1.2.398.3.10.1.1.2.2',
	GOST2015_512_SIGN: '1.2.398.3.10.1.1.2.3.2',
	GOST2015_512_CURVE_A: '1.2.398.3.10.1.1.2.2.1',
	STREEBOG_512: '1.2.398.3.10.1.3.3',
};

/**
 * Looks up a curve by OID.
 *
 * @param {string} curveOid Curve parameter OID.
 * @returns {object}
 */
function curveFor(curveOid) {
	const curve = CURVE_BY_OID[curveOid];
	if (!curve) {
		throw new Error(`Kalkan: unknown curve ${curveOid}`);
	}
	return curve;
}

/**
 * Decodes a GOST 2015 512 private key.
 *
 * @param {Buffer} der PrivateKeyInfo.
 * @returns {{curve: object, d: bigint}}
 */
export function privateKeyFromPkcs8(der) {
	const pki = parseBer(der);
	const alg = pki.children[1];
	const algOid = readOid(alg.children[0]);
	if (algOid !== OID.GOST2015_512_KEY) {
		throw new Error(`Kalkan: unsupported key algorithm ${algOid}`);
	}
	const curve = curveFor(readOid(alg.children[1].children[0]));
	const inner = parseBer(pki.children[2].value);
	if (inner.tag !== TAG.OCTET_STRING) {
		throw new Error('Kalkan: unexpected private key encoding');
	}
	const d = toBigInt(inner.value, true);
	if (d <= 0n || d >= curve.q) {
		throw new Error('Kalkan: private key out of range');
	}
	return { curve, d };
}

/**
 * Decodes the GOST public key of a parsed certificate.
 *
 * @param {object} cert Result of parseCertificate().
 * @returns {{curve: object, Q: Array<bigint>}}
 */
export function publicKeyFromCertificate(cert) {
	if (cert.spki.algorithm !== OID.GOST2015_512_KEY) {
		throw new Error(`Kalkan: unsupported public key algorithm ${cert.spki.algorithm}`);
	}
	const curve = curveFor(cert.spki.params[0]);
	const raw = parseBer(cert.spki.publicKey).value;
	const size = curve.bits / 8;
	if (raw.length !== 2 * size) {
		throw new Error('Kalkan: unexpected public key length');
	}
	const Q = [toBigInt(raw.subarray(0, size), true), toBigInt(raw.subarray(size), true)];
	if (!isOnCurve(Q, curve)) {
		throw new Error('Kalkan: public key is not on the curve');
	}
	return { curve, Q };
}

/**
 * Encodes a SubjectPublicKeyInfo the way NCA certificates do.
 *
 * @param {Array<bigint>} Q Public key.
 * @returns {Buffer}
 */
export function encodeSpki(Q) {
	const point = Buffer.concat([fromBigInt(Q[0], 64, true), fromBigInt(Q[1], 64, true)]);
	const algorithm = seq(oid(OID.GOST2015_512_KEY), seq(oid(OID.GOST2015_512_CURVE_A), oid(OID.STREEBOG_512)));
	return seq(algorithm, tlv(TAG.BIT_STRING, Buffer.concat([Buffer.from([0]), octetString(point)])));
}

/**
 * Converts a Streebog hash to the integer alpha used by GOST signatures.
 *
 * @param {Buffer} hash Hash in memory order.
 * @returns {bigint}
 */
export function hashToInteger(hash) {
	return toBigInt(hash, true);
}

/**
 * Encodes a signature as r then s, little-endian.
 *
 * @param {{r: bigint, s: bigint}} sig Signature.
 * @param {object} curve Curve, to get the field size.
 * @returns {Buffer}
 */
export function encodeSignature({ r, s }, curve) {
	const size = curve.bits / 8;
	return Buffer.concat([fromBigInt(r, size, true), fromBigInt(s, size, true)]);
}

/**
 * Decodes a signature from r then s, little-endian.
 *
 * @param {Buffer} bytes Signature value.
 * @returns {{r: bigint, s: bigint}}
 */
export function decodeSignature(bytes) {
	const half = bytes.length / 2;
	return { r: toBigInt(bytes.subarray(0, half), true), s: toBigInt(bytes.subarray(half), true) };
}

/**
 * Loads a signing key and its certificate from a Kalkan PKCS#12 file.
 * The certificate is matched by public key, not by bag attributes.
 *
 * @param {Buffer} p12 File contents.
 * @param {string} password Container password.
 * @returns {{curve: object, d: bigint, certificate: object}}
 */
export function loadSigner(p12, password) {
	const { keys, certificates } = readPkcs12(p12, password);
	if (keys.length !== 1) {
		throw new Error(`Kalkan: expected one private key, found ${keys.length}`);
	}
	const { curve, d } = privateKeyFromPkcs8(keys[0].privateKeyInfo);
	const [x, y] = publicKey(curve, d);
	for (const { der } of certificates) {
		const cert = parseCertificate(der);
		if (cert.spki.algorithm !== OID.GOST2015_512_KEY) {
			continue;
		}
		const { Q } = publicKeyFromCertificate(cert);
		if (Q[0] === x && Q[1] === y) {
			return { curve, d, certificate: cert };
		}
	}
	throw new Error('Kalkan: no certificate matches the private key');
}
