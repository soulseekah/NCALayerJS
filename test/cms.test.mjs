import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { signCms, verifyCms, addTimestamp, timestampCms, OID } from '../src/cms.mjs';
import { OID as TSP_OID, PROFILE } from '../src/tsp.mjs';
import { seq, octetString, algorithm } from '../src/der.mjs';
import { fakeFetch, makeToken } from './helpers/tsa.mjs';
import { parseBer, oid } from '../src/ber.mjs';
import { makeSigner, selfSignedCertificate } from './helpers/gost.mjs';

// NCALayer update manifest, signed by NIT with Kalkan. A real-world
// GOST 2015 512 CMS with a timestamp token in the unsigned attributes.
// Not distributed with the code; tests that need it skip when missing.
const manifestPath = new URL('./fixtures/kalkan-manifest.der', import.meta.url);
const manifest = existsSync(manifestPath) ? readFileSync(manifestPath) : null;
const needsManifest = { skip: manifest ? false : 'run test/fixtures/fetch-kalkan-manifest.sh first' };

const signer = makeSigner();
const content = Buffer.from('{"hello": "Қазақстан"}', 'utf8');

/**
 * Lists signed attribute OIDs of the first SignerInfo, in encoded order.
 *
 * @param {Buffer} der ContentInfo.
 * @returns {Array<string>}
 */
function signedAttributeOids(der) {
	const sd = parseBer(der).children[1].children[0];
	const si = sd.children[sd.children.length - 1].children[0];
	return si.children[3].children.map((a) => oid(a.children[0]));
}

test('verifies a real Kalkan signature', needsManifest, () => {
	const { signers, content: data } = verifyCms(manifest);
	assert.equal(signers.length, 1);
	assert.equal(signers[0].reason, null);
	assert.equal(signers[0].valid, true);
	// NIT re-signs the file on updates, so only check that a time is there.
	assert.ok(signers[0].signingTime instanceof Date && !isNaN(signers[0].signingTime));
	assert.match(data.toString('utf8'), /"ncalayer"/);
	assert.equal(signers[0].timestamp.reason, null);
	assert.equal(signers[0].timestamp.valid, true);
});

test('signs and verifies attached CMS', () => {
	const when = new Date('2026-10-08T10:20:30Z');
	const der = signCms({ content, signer, signingTime: when });
	const { signers, content: data } = verifyCms(der);
	assert.deepEqual(data, content);
	assert.equal(signers[0].valid, true, signers[0].reason);
	assert.deepEqual(signers[0].signingTime, when);
	assert.deepEqual(signers[0].certificate.der, signer.certificate.der);
});

test('signs and verifies detached CMS', () => {
	const der = signCms({ content, signer, detached: true });
	assert.throws(() => verifyCms(der), /content is required/);
	assert.equal(verifyCms(der, { content }).signers[0].valid, true);
	const other = verifyCms(der, { content: Buffer.from('other') }).signers[0];
	assert.equal(other.valid, false);
	assert.equal(other.reason, 'message digest mismatch');
});

test('attached CMS rejects different external content', () => {
	const der = signCms({ content, signer });
	assert.throws(() => verifyCms(der, { content: Buffer.from('other') }), /differs/);
});

test('signed attributes have the same order as Kalkan output', needsManifest, () => {
	const ours = signedAttributeOids(signCms({ content, signer }));
	assert.deepEqual(ours, signedAttributeOids(manifest));
	assert.deepEqual(ours, [OID.CONTENT_TYPE, OID.SIGNING_TIME, OID.SIGNING_CERTIFICATE_V2, OID.MESSAGE_DIGEST]);
});

test('tampered signature is rejected', () => {
	const der = Buffer.from(signCms({ content, signer }));
	// The signature value is the last 128 bytes of the structure.
	der[der.length - 10] ^= 0x01;
	const result = verifyCms(der).signers[0];
	assert.equal(result.valid, false);
	assert.equal(result.reason, 'signature is not valid');
});

test('signature from another key with the same certificate is rejected', () => {
	const impostor = { ...makeSigner(), certificate: signer.certificate };
	const result = verifyCms(signCms({ content, signer: impostor })).signers[0];
	assert.equal(result.valid, false);
	assert.equal(result.reason, 'signature is not valid');
});

test('signingCertificateV2 must match the signer certificate', () => {
	// Re-signing the same certificate gives new bytes (random nonce) with
	// the same issuer, serial and length, so only the attribute catches it.
	const copy = selfSignedCertificate(signer.d);
	assert.notDeepEqual(copy, signer.certificate.der);
	const der = signCms({ content, signer });
	const swapped = Buffer.from(der.toString('hex').replace(signer.certificate.der.toString('hex'), copy.toString('hex')), 'hex');
	const result = verifyCms(swapped).signers[0];
	assert.equal(result.valid, false);
	assert.equal(result.reason, 'signingCertificateV2 does not match the signer certificate');
});

test('signatures without a token report no timestamp', () => {
	assert.equal(verifyCms(signCms({ content, signer })).signers[0].timestamp, null);
});

test('timestampCms adds a token that verifyCms accepts', async () => {
	const der = await timestampCms(signCms({ content, signer }), { fetch: fakeFetch() });
	const [result] = verifyCms(der).signers;
	assert.equal(result.valid, true, result.reason);
	assert.equal(result.timestamp.valid, true, result.timestamp.reason);
	assert.ok(result.timestamp.time instanceof Date);
});

test('a token for other data fails the timestamp but not the signature', () => {
	const imprint = seq(algorithm(TSP_OID.SHA256), octetString(createHash('sha256').update('other').digest()));
	const der = addTimestamp(signCms({ content, signer }), makeToken(imprint, null));
	const [result] = verifyCms(der).signers;
	assert.equal(result.valid, true);
	assert.equal(result.timestamp.valid, false);
	assert.equal(result.timestamp.reason, 'token covers different data');
});

test('addTimestamp refuses a second token', async () => {
	const der = await timestampCms(signCms({ content, signer }), { fetch: fakeFetch() });
	assert.throws(() => addTimestamp(der, Buffer.alloc(0)), /already has unsigned attributes/);
});

test('timestampCms supports the RSA profile too', async () => {
	const der = await timestampCms(signCms({ content, signer }), { profile: PROFILE.RSA, fetch: fakeFetch() });
	const [result] = verifyCms(der).signers;
	assert.equal(result.timestamp.valid, true, result.timestamp.reason);
});
