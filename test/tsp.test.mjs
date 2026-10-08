import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { buildRequest, verifyToken, requestTimestamp, hashWith, PROFILE, OID } from '../src/tsp.mjs';
import { parseBer, oid, toBigInt, TAG } from '../src/ber.mjs';
import { seq, octetString, algorithm } from '../src/der.mjs';
import { streebog512 } from '../src/streebog.mjs';
import { OID as KALKAN } from '../src/kalkan.mjs';
import { fakeFetch, makeToken } from './helpers/tsa.mjs';

const sha = createHash('sha256').update('data').digest();
const gostHash = streebog512('data');

const manifestPath = new URL('./fixtures/kalkan-manifest.der', import.meta.url);
const manifest = existsSync(manifestPath) ? readFileSync(manifestPath) : null;

test('buildRequest encodes version, imprint, policy, nonce and certReq', () => {
	const { der, nonce } = buildRequest(sha, { nonce: 0x1234n });
	const f = parseBer(der).children;
	assert.equal(toBigInt(f[0].value), 1n);
	assert.equal(oid(f[1].children[0].children[0]), OID.SHA256);
	assert.deepEqual(f[1].children[1].value, sha);
	assert.equal(oid(f[2]), PROFILE.RSA.policy);
	assert.equal(toBigInt(f[3].value), 0x1234n);
	assert.equal(nonce, 0x1234n);
	assert.equal(f[4].tag, TAG.BOOLEAN);
	assert.deepEqual(f[4].value, Buffer.from([0xff]));
});

test('buildRequest supports the GOST profile', () => {
	const f = parseBer(buildRequest(gostHash, PROFILE.GOST).der).children;
	assert.equal(oid(f[1].children[0].children[0]), KALKAN.STREEBOG_512);
	assert.equal(oid(f[2]), PROFILE.GOST.policy);
});

test('buildRequest checks the hash length and makes random nonces', () => {
	const a = buildRequest(sha, { policy: null });
	assert.equal(parseBer(a.der).children.length, 4);
	assert.notEqual(a.nonce, buildRequest(sha).nonce);
	assert.throws(() => buildRequest(Buffer.alloc(20)), /does not match/);
	assert.throws(() => buildRequest(sha, PROFILE.GOST), /does not match/);
	assert.throws(() => hashWith('1.2.3', Buffer.alloc(0)), /unsupported digest/);
});

test('requestTimestamp returns a verified RSA token', async () => {
	const { token, info } = await requestTimestamp(sha, { fetch: fakeFetch() });
	assert.equal(info.valid, true);
	assert.equal(info.policy, PROFILE.RSA.policy);
	assert.equal(info.hashAlgorithm, OID.SHA256);
	assert.ok(info.time instanceof Date);
	assert.equal(verifyToken(token, { hash: sha }).valid, true);
	assert.equal(verifyToken(token, { data: Buffer.from('data') }).valid, true);
});

test('requestTimestamp returns a verified GOST token', async () => {
	const { token, info } = await requestTimestamp(gostHash, { profile: PROFILE.GOST, fetch: fakeFetch() });
	assert.equal(info.valid, true, info.reason);
	assert.equal(info.policy, PROFILE.GOST.policy);
	assert.equal(info.hashAlgorithm, KALKAN.STREEBOG_512);
	assert.equal(verifyToken(token, { data: Buffer.from('data') }).valid, true);
	assert.equal(verifyToken(token, { data: Buffer.from('other') }).reason, 'token covers different data');
});

test('requestTimestamp rejects bad replies', async () => {
	await assert.rejects(requestTimestamp(sha, { fetch: fakeFetch({ httpStatus: 500 }) }), /HTTP 500/);
	await assert.rejects(requestTimestamp(sha, { fetch: fakeFetch({ status: 2 }) }), /rejected with status 2/);
	await assert.rejects(requestTimestamp(sha, { fetch: fakeFetch({ nonce: 1n }) }), /nonce mismatch/);
	await assert.rejects(requestTimestamp(sha, { fetch: fakeFetch({ hash: Buffer.alloc(32) }) }), /covers different data/);
	await assert.rejects(requestTimestamp(sha, { fetch: fakeFetch({ policy: '1.2.3.4' }) }), /unexpected policy 1\.2\.3\.4/);
});

test('verifyToken detects a tampered TSTInfo', () => {
	for (const gost of [false, true]) {
		const token = Buffer.from(makeToken(seq(algorithm(OID.SHA256), octetString(sha)), 5n, { gost }));
		assert.equal(verifyToken(token, { hash: sha }).valid, true);
		// The TSTInfo serial 0x1234 sits inside the signed content.
		const at = token.indexOf(Buffer.from([0x02, 0x02, 0x12, 0x34]));
		token[at + 3] ^= 0x01;
		const result = verifyToken(token, { hash: sha });
		assert.equal(result.valid, false);
		assert.equal(result.reason, 'token message digest mismatch');
	}
});

test('verifies the real token in the Kalkan manifest', { skip: manifest ? false : 'run test/fixtures/fetch-kalkan-manifest.sh first' }, () => {
	const sd = parseBer(manifest).children[1].children[0];
	const si = sd.children[sd.children.length - 1].children[0];
	const token = si.children[6].children[0].children[1].children[0].raw;
	// CAdES: the token covers the SignerInfo signature value.
	const result = verifyToken(token, { data: si.children[5].value });
	assert.equal(result.reason, null);
	assert.equal(result.valid, true);
	assert.equal(result.policy, PROFILE.RSA.policy);
	assert.notEqual(result.nonce, null);
});
