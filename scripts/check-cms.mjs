#!/usr/bin/env node
// Verifies a Kalkan GOST 2015 512 CMS signature and finds which signature
// layout Kalkan uses: order of r and s, byte order, and how the hash is
// turned into an integer.
//
// Usage: node scripts/check-cms.mjs <signed.der>

import { readFileSync } from 'node:fs';
import { parseBer, octets, oid, toBigInt, TAG } from '../src/ber.mjs';
import { streebog512 } from '../src/streebog.mjs';
import { CURVE_BY_OID, isOnCurve, verify } from '../src/gost3410.mjs';

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

/**
 * Reads the GOST public key and curve from a certificate node.
 *
 * @param {object} cert Parsed Certificate node.
 * @returns {{curve: object, Q: Array<bigint>, curveOid: string}}
 */
function certificateKey(cert) {
	const tbs = cert.children[0];
	// Skip the optional [0] version field.
	const offset = tbs.children[0].tag === 0xa0 ? 1 : 0;
	const spki = tbs.children[offset + 5];
	const params = spki.children[0].children[1];
	const curveOid = oid(params.children[0]);
	const curve = CURVE_BY_OID[curveOid];
	if (!curve) {
		throw new Error(`Unknown curve ${curveOid}`);
	}
	const bits = spki.children[1].value.subarray(1);
	const raw = parseBer(bits).value;
	const half = raw.length / 2;
	// Public keys are x then y, each little-endian. See check-curve.mjs.
	const Q = [toBigInt(raw.subarray(0, half), true), toBigInt(raw.subarray(half), true)];
	return { curve, Q, curveOid };
}

/**
 * Entry point.
 */
function main() {
	const [path] = process.argv.slice(2);
	if (!path) {
		console.error('Usage: node check-cms.mjs <signed.der>');
		process.exit(2);
	}

	const ci = parseBer(readFileSync(path));
	if (oid(ci.children[0]) !== OID_SIGNED_DATA) {
		throw new Error('Not a SignedData');
	}
	const sd = ci.children[1].children[0];
	const encap = sd.children[2];
	const certs = sd.children.find((n) => n.tag === 0xa0);
	const signerInfo = sd.children[sd.children.length - 1].children[0];
	console.log(`digest algorithm ${oid(sd.children[1].children[0].children[0])}`);
	console.log(`certificates ${certs ? certs.children.length : 0}`);

	console.log('== Content hash');
	const content = octets(encap.children[1].children[0]);
	const signedAttrs = signerInfo.children.find((n) => n.tag === 0xa0);
	const mdAttr = signedAttrs.children.find((a) => oid(a.children[0]) === OID_MESSAGE_DIGEST);
	const messageDigest = mdAttr.children[1].children[0].value;
	console.log(`messageDigest ${streebog512(content).equals(messageDigest) ? 'MATCH' : 'no'}`);

	console.log('== Signature');
	const sigAlgIndex = signerInfo.children.indexOf(signedAttrs) + 1;
	console.log(`signature algorithm ${oid(signerInfo.children[sigAlgIndex].children[0])}`);
	const sig = signerInfo.children[sigAlgIndex + 1];
	if (sig.tag !== TAG.OCTET_STRING) {
		throw new Error('Signature value is not an OCTET STRING');
	}
	console.log(`signature length ${sig.value.length} bytes`);

	// RFC 5652 section 5.4: signed attributes are hashed as an explicit SET.
	const attrsDer = Buffer.from(signedAttrs.raw);
	attrsDer[0] = TAG.SET;
	const hash = streebog512(attrsDer);

	const { curve, Q, curveOid } = certificateKey(certs.children[0]);
	console.log(`signer curve ${curveOid}, public key on curve ${isOnCurve(Q, curve)}`);

	const half = sig.value.length / 2;
	const first = sig.value.subarray(0, half);
	const second = sig.value.subarray(half);
	let found = 0;
	for (const order of ['s|r', 'r|s']) {
		for (const sigLe of [false, true]) {
			for (const hashLe of [false, true]) {
				const a = toBigInt(first, sigLe);
				const b = toBigInt(second, sigLe);
				const [r, s] = order === 's|r' ? [b, a] : [a, b];
				const ok = verify(curve, Q, toBigInt(hash, hashLe), r, s);
				found += ok ? 1 : 0;
				console.log(`${order} sig ${sigLe ? 'LE' : 'BE'}, hash ${hashLe ? 'LE' : 'BE'}: ${ok ? 'VALID' : 'no'}`);
			}
		}
	}
	console.log(found === 1 ? 'exactly one layout verifies' : `${found} layouts verify`);
}

main();
