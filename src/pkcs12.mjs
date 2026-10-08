// PKCS#12 (RFC 7292) reader. Supports the password based encryption that
// Kalkan uses: SHA-1 with 3DES for keys and SHA-1 with 40-bit RC2 for
// certificates. PBES2 is not supported yet.

import { createHash, createHmac, createDecipheriv, timingSafeEqual } from 'node:crypto';
import { parseBer, octets, oid, toBigInt } from './ber.mjs';
import { cbcDecrypt as rc2CbcDecrypt } from './rc2.mjs';

const OID = {
	DATA: '1.2.840.113549.1.7.1',
	ENCRYPTED_DATA: '1.2.840.113549.1.7.6',
	KEY_BAG: '1.2.840.113549.1.12.10.1.1',
	SHROUDED_KEY_BAG: '1.2.840.113549.1.12.10.1.2',
	CERT_BAG: '1.2.840.113549.1.12.10.1.3',
	X509_CERTIFICATE: '1.2.840.113549.1.9.22.1',
	FRIENDLY_NAME: '1.2.840.113549.1.9.20',
	LOCAL_KEY_ID: '1.2.840.113549.1.9.21',
};

// Hash OIDs allowed in the MAC.
const MAC_HASHES = {
	'1.3.14.3.2.26': 'sha1',
	'2.16.840.1.101.3.4.2.1': 'sha256',
};

// PKCS#12 PBE schemes, RFC 7292 appendix C.
const PBE = {
	'1.2.840.113549.1.12.1.3': { cipher: '3des', keyLength: 24 },
	'1.2.840.113549.1.12.1.5': { cipher: 'rc2', keyLength: 16, bits: 128 },
	'1.2.840.113549.1.12.1.6': { cipher: 'rc2', keyLength: 5, bits: 40 },
};

/**
 * Derives key material as described in RFC 7292 appendix B.
 *
 * @param {string} password Password, encoded as BMPString with a null tail.
 * @param {Uint8Array} salt Salt.
 * @param {number} id 1 for the key, 2 for the IV, 3 for the MAC key.
 * @param {number} iterations Iteration count.
 * @param {number} size Number of bytes to return.
 * @param {string} hash Hash name, sha1 or sha256. Both have a 64-byte block.
 * @returns {Buffer}
 */
export function pkcs12Kdf(password, salt, id, iterations, size, hash = 'sha1') {
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
	let produced = 0;
	while (produced < size) {
		let A = createHash(hash).update(D).update(I).digest();
		for (let r = 1; r < iterations; r++) {
			A = createHash(hash).update(A).digest();
		}
		out.push(A);
		produced += A.length;
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
 * Decrypts data protected with a PKCS#12 PBE scheme.
 *
 * @param {object} alg Parsed AlgorithmIdentifier node.
 * @param {Buffer} data Ciphertext.
 * @param {string} password Container password.
 * @returns {Buffer} Plaintext.
 */
function decryptPbe(alg, data, password) {
	const algOid = oid(alg.children[0]);
	const scheme = PBE[algOid];
	if (!scheme) {
		throw new Error(`PKCS#12: unsupported encryption ${algOid}`);
	}
	const salt = alg.children[1].children[0].value;
	const iterations = Number(toBigInt(alg.children[1].children[1].value));
	const key = pkcs12Kdf(password, salt, 1, iterations, scheme.keyLength);
	const iv = pkcs12Kdf(password, salt, 2, iterations, 8);
	if (scheme.cipher === 'rc2') {
		return rc2CbcDecrypt(key, scheme.bits, iv, data);
	}
	try {
		const decipher = createDecipheriv('des-ede3-cbc', key, iv);
		return Buffer.concat([decipher.update(data), decipher.final()]);
	} catch {
		throw new Error('PKCS#12: 3DES decryption failed (wrong password?)');
	}
}

/**
 * Checks the PFX MAC, RFC 7292 section 5.
 *
 * @param {object} macData Parsed MacData node.
 * @param {Buffer} content Authenticated safe bytes.
 * @param {string} password Container password.
 */
function verifyMac(macData, content, password) {
	const digestInfo = macData.children[0];
	const hashOid = oid(digestInfo.children[0].children[0]);
	const hash = MAC_HASHES[hashOid];
	if (!hash) {
		throw new Error(`PKCS#12: unsupported MAC hash ${hashOid}`);
	}
	const expected = digestInfo.children[1].value;
	const salt = macData.children[1].value;
	const iterations = macData.children[2] ? Number(toBigInt(macData.children[2].value)) : 1;
	const key = pkcs12Kdf(password, salt, 3, iterations, expected.length, hash);
	const actual = createHmac(hash, key).update(content).digest();
	if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
		throw new Error('PKCS#12: MAC mismatch (wrong password?)');
	}
}

/**
 * Reads friendlyName and localKeyId from bag attributes.
 *
 * @param {object|undefined} attrs Parsed SET of Attribute, or undefined.
 * @returns {{friendlyName: string|null, localKeyId: Buffer|null}}
 */
function bagAttributes(attrs) {
	const out = { friendlyName: null, localKeyId: null };
	for (const attr of attrs ? attrs.children : []) {
		const type = oid(attr.children[0]);
		const value = attr.children[1].children[0];
		if (type === OID.FRIENDLY_NAME) {
			// BMPString is UTF-16BE; Node only decodes UTF-16LE.
			out.friendlyName = Buffer.from(value.value).swap16().toString('utf16le');
		} else if (type === OID.LOCAL_KEY_ID) {
			out.localKeyId = Buffer.from(value.value);
		}
	}
	return out;
}

/**
 * Reads private keys and certificates from a PKCS#12 file.
 *
 * @param {Buffer} p12 File contents.
 * @param {string} password Container password.
 * @returns {{keys: Array<{privateKeyInfo: Buffer, friendlyName: string|null, localKeyId: Buffer|null}>,
 *   certificates: Array<{der: Buffer, friendlyName: string|null, localKeyId: Buffer|null}>}}
 */
export function readPkcs12(p12, password) {
	const pfx = parseBer(p12);
	const authSafe = pfx.children[1];
	if (oid(authSafe.children[0]) !== OID.DATA) {
		throw new Error('PKCS#12: only password integrity mode is supported');
	}
	const content = octets(authSafe.children[1].children[0]);
	if (pfx.children[2]) {
		verifyMac(pfx.children[2], content, password);
	}

	const keys = [];
	const certificates = [];
	for (const ci of parseBer(content).children) {
		const type = oid(ci.children[0]);
		let safeContents;
		if (type === OID.DATA) {
			safeContents = octets(ci.children[1].children[0]);
		} else if (type === OID.ENCRYPTED_DATA) {
			const eci = ci.children[1].children[0].children[1];
			safeContents = decryptPbe(eci.children[1], octets(eci.children[2]), password);
		} else {
			throw new Error(`PKCS#12: unsupported content type ${type}`);
		}

		for (const bag of parseBer(safeContents).children) {
			const bagId = oid(bag.children[0]);
			const value = bag.children[1].children[0];
			const attrs = bagAttributes(bag.children[2]);
			if (bagId === OID.KEY_BAG) {
				keys.push({ privateKeyInfo: Buffer.from(value.raw), ...attrs });
			} else if (bagId === OID.SHROUDED_KEY_BAG) {
				const privateKeyInfo = decryptPbe(value.children[0], octets(value.children[1]), password);
				keys.push({ privateKeyInfo, ...attrs });
			} else if (bagId === OID.CERT_BAG) {
				if (oid(value.children[0]) !== OID.X509_CERTIFICATE) {
					continue;
				}
				const der = Buffer.from(octets(value.children[1].children[0]));
				certificates.push({ der, ...attrs });
			}
		}
	}
	return { keys, certificates };
}
