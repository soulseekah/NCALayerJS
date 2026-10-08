import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { publicKey } from '../src/gost3410.mjs';
import { parseCertificate } from '../src/x509.mjs';
import { privateKeyFromPkcs8, publicKeyFromCertificate, encodeSignature, decodeSignature, hashToInteger } from '../src/kalkan.mjs';
import { curve, randomKey, encodePkcs8, selfSignedCertificate } from './helpers/gost.mjs';

test('private key round trip through PrivateKeyInfo', () => {
	const d = randomKey();
	const key = privateKeyFromPkcs8(encodePkcs8(d));
	assert.equal(key.d, d);
	assert.equal(key.curve, curve);
});

test('privateKeyFromPkcs8 rejects non-GOST keys', () => {
	const ec = readFileSync(new URL('./fixtures/key.pkcs8.der', import.meta.url));
	assert.throws(() => privateKeyFromPkcs8(ec), /unsupported key algorithm 1\.2\.840\.10045\.2\.1/);
});

test('public key from certificate matches the private key', () => {
	const d = randomKey();
	const { Q } = publicKeyFromCertificate(parseCertificate(selfSignedCertificate(d)));
	assert.deepEqual(Q, publicKey(curve, d));
});

test('publicKeyFromCertificate rejects non-GOST certificates', () => {
	const cert = parseCertificate(readFileSync(new URL('./fixtures/cert.der', import.meta.url)));
	assert.throws(() => publicKeyFromCertificate(cert), /unsupported public key algorithm/);
});

test('signature encoding is r then s, little-endian', () => {
	const bytes = encodeSignature({ r: 0x0102n, s: 0x0304n }, curve);
	assert.equal(bytes.length, 128);
	assert.deepEqual(bytes.subarray(0, 2), Buffer.from([0x02, 0x01]));
	assert.deepEqual(bytes.subarray(64, 66), Buffer.from([0x04, 0x03]));
	assert.deepEqual(decodeSignature(bytes), { r: 0x0102n, s: 0x0304n });
});

test('hash is read as a little-endian integer', () => {
	assert.equal(hashToInteger(Buffer.from([0x01, 0x02])), 0x0201n);
});
