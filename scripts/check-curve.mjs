#!/usr/bin/env node
// Finds which GOST R 34.10 512-bit curve a Kazakh NCA PKCS#12 key uses.
// Prints only curve names and yes/no results, never key material.
//
// Usage: NCA_PASSWORD=... node scripts/check-curve.mjs <key.p12> <cert.pem|cert.der>

import { readFileSync } from 'node:fs';
import { createHash, createDecipheriv } from 'node:crypto';
import { parseBer, octets, oid, toBigInt, TAG } from '../src/ber.mjs';
import { CURVES, isOnCurve, multiply } from '../src/gost3410.mjs';

const OID_DATA = '1.2.840.113549.1.7.1';
const OID_SHROUDED_KEY_BAG = '1.2.840.113549.1.12.10.1.2';
const OID_PBE_SHA1_3DES = '1.2.840.113549.1.12.1.3';

/**
 * Derives key material as described in RFC 7292 appendix B (SHA-1 only).
 *
 * @param {string} password Password, encoded as BMPString with a null tail.
 * @param {Buffer} salt Salt from the PBE parameters.
 * @param {number} id 1 for the key, 2 for the IV, 3 for the MAC key.
 * @param {number} iterations Iteration count.
 * @param {number} size Number of bytes to return.
 * @returns {Buffer}
 */
function pkcs12Kdf(password, salt, id, iterations, size) {
	const u = 20;
	const v = 64;
	const pass = Buffer.alloc((password.length + 1) * 2);
	for (let i = 0; i < password.length; i++) {
		pass.writeUInt16BE(password.charCodeAt(i), i * 2);
	}
	// Repeats src to fill a multiple of v bytes.
	const fill = (src) => {
		const out = Buffer.alloc(v * Math.ceil(src.length / v));
		for (let i = 0; i < out.length; i++) {
			out[i] = src[i % src.length];
		}
		return out;
	};
	const D = Buffer.alloc(v, id);
	const I = Buffer.concat([fill(salt), fill(pass)]);
	const out = [];
	for (let produced = 0; produced < size; produced += u) {
		let A = createHash('sha1').update(D).update(I).digest();
		for (let r = 1; r < iterations; r++) {
			A = createHash('sha1').update(A).digest();
		}
		out.push(A);
		const B = fill(A);
		// Each v-byte block of I becomes (I_j + B + 1) mod 2^(8v).
		for (let j = 0; j < I.length; j += v) {
			let carry = 1;
			for (let k = v - 1; k >= 0; k--) {
				const sum = I[j + k] + B[k] + carry;
				I[j + k] = sum & 0xff;
				carry = sum >> 8;
			}
		}
	}
	return Buffer.concat(out).subarray(0, size);
}

/**
 * Extracts and decrypts the PrivateKeyInfo from a PKCS#12 file.
 *
 * @param {Buffer} p12 PKCS#12 file contents.
 * @param {string} password Container password.
 * @returns {Buffer} DER encoded PrivateKeyInfo.
 */
function extractPrivateKeyInfo(p12, password) {
	const pfx = parseBer(p12);
	const authSafe = pfx.children[1];
	if (oid(authSafe.children[0]) !== OID_DATA) {
		throw new Error('Unexpected authSafe content type');
	}
	const contentInfos = parseBer(octets(authSafe.children[1].children[0]));
	for (const ci of contentInfos.children) {
		if (oid(ci.children[0]) !== OID_DATA) {
			continue;
		}
		const bags = parseBer(octets(ci.children[1].children[0]));
		for (const bag of bags.children) {
			if (oid(bag.children[0]) !== OID_SHROUDED_KEY_BAG) {
				continue;
			}
			const epki = bag.children[1].children[0];
			const alg = epki.children[0];
			if (oid(alg.children[0]) !== OID_PBE_SHA1_3DES) {
				throw new Error('Unsupported key bag encryption: ' + oid(alg.children[0]));
			}
			const salt = alg.children[1].children[0].value;
			const iterations = Number(toBigInt(alg.children[1].children[1].value));
			const key = pkcs12Kdf(password, salt, 1, iterations, 24);
			const iv = pkcs12Kdf(password, salt, 2, iterations, 8);
			const decipher = createDecipheriv('des-ede3-cbc', key, iv);
			return Buffer.concat([decipher.update(octets(epki.children[1])), decipher.final()]);
		}
	}
	throw new Error('No shrouded key bag found');
}

/**
 * Reads the raw public key bytes from a certificate.
 *
 * @param {Buffer} certFile PEM or DER certificate.
 * @returns {Buffer} Public key bytes without the OCTET STRING wrapper.
 */
function extractPublicKey(certFile) {
	const text = certFile.toString('latin1');
	const der = text.includes('-----BEGIN')
		? Buffer.from(text.replace(/-----[^-]+-----|\s/g, ''), 'base64')
		: certFile;
	const tbs = parseBer(der).children[0];
	// Skip the optional [0] version field.
	const offset = tbs.children[0].tag === 0xa0 ? 1 : 0;
	const spki = tbs.children[offset + 5];
	const bits = spki.children[1].value.subarray(1);
	const inner = parseBer(bits);
	return inner.tag === TAG.OCTET_STRING ? inner.value : bits;
}

/**
 * Lists the plausible ways to read a point from 2n raw bytes.
 *
 * @param {Buffer} raw Public key bytes.
 * @returns {Array<{name: string, point: Array<bigint>}>}
 */
function pointCandidates(raw) {
	const half = raw.length / 2;
	const lo = raw.subarray(0, half);
	const hi = raw.subarray(half);
	const out = [];
	for (const le of [true, false]) {
		const e = le ? 'LE' : 'BE';
		out.push({ name: `x|y ${e}`, point: [toBigInt(lo, le), toBigInt(hi, le)] });
		out.push({ name: `y|x ${e}`, point: [toBigInt(hi, le), toBigInt(lo, le)] });
	}
	return out;
}

/**
 * Entry point.
 */
function main() {
	const [p12Path, certPath] = process.argv.slice(2);
	const password = process.env.NCA_PASSWORD;
	if (!p12Path || !certPath || password === undefined) {
		console.error('Usage: NCA_PASSWORD=... node check-curve.mjs <key.p12> <cert>');
		process.exit(2);
	}

	console.log('== Check A: certificate public key on curve');
	const raw = extractPublicKey(readFileSync(certPath));
	console.log(`public key length ${raw.length} bytes`);
	const hits = [];
	for (const [name, c] of Object.entries(CURVES)) {
		for (const cand of pointCandidates(raw)) {
			if (isOnCurve(cand.point, c)) {
				hits.push({ name, c, cand });
				console.log(`${name}: MATCH with ${cand.name}`);
			}
		}
	}
	if (!hits.length) {
		console.log('no curve matched');
	}

	console.log('== Check B: private key matches public key');
	const pki = parseBer(extractPrivateKeyInfo(readFileSync(p12Path), password));
	const alg = pki.children[1];
	console.log(`key algorithm ${oid(alg.children[0])}`);
	const algParams = alg.children[1];
	if (algParams && algParams.children) {
		console.log(`key params ${algParams.children.filter((n) => n.tag === TAG.OID).map(oid).join(', ')}`);
	}
	let keyBytes = octets(pki.children[2]);
	try {
		const inner = parseBer(keyBytes);
		if ((inner.tag === TAG.INTEGER || inner.tag === TAG.OCTET_STRING) && inner.end === keyBytes.length) {
			console.log(`private key wrapped in tag 0x${inner.tag.toString(16)}`);
			keyBytes = inner.value;
		}
	} catch {
		console.log('private key is raw bytes');
	}
	console.log(`private key length ${keyBytes.length} bytes`);
	for (const { name, c, cand } of hits) {
		for (const le of [true, false]) {
			const d = toBigInt(keyBytes, le) % c.q;
			const Q = multiply(d, c.G, c);
			const ok = Q !== null && Q[0] === cand.point[0] && Q[1] === cand.point[1];
			console.log(`${name} (${cand.name}), key ${le ? 'LE' : 'BE'}: ${ok ? 'MATCH' : 'no'}`);
		}
	}
}

main();
