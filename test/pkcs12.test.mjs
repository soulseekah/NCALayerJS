import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPrivateKey } from 'node:crypto';
import { readPkcs12 } from '../src/pkcs12.mjs';

// Fixtures come from test/fixtures/make-pkcs12.sh.
const fixture = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url));

/**
 * Returns the private scalar of a PKCS#8 EC key, via Node's own parser.
 *
 * @param {Buffer} der PrivateKeyInfo.
 * @returns {string}
 */
function scalar(der) {
	return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }).export({ format: 'jwk' }).d;
}

test('reads a legacy 3DES + RC2-40 container', () => {
	const { keys, certificates } = readPkcs12(fixture('legacy.p12'), 'test123');
	assert.equal(keys.length, 1);
	assert.equal(certificates.length, 1);
	assert.equal(scalar(keys[0].privateKeyInfo), scalar(fixture('key.pkcs8.der')));
	assert.deepEqual(certificates[0].der, fixture('cert.der'));
});

test('reads bag attributes', () => {
	const { keys, certificates } = readPkcs12(fixture('legacy.p12'), 'test123');
	assert.equal(keys[0].friendlyName, 'Test Key');
	assert.equal(certificates[0].friendlyName, 'Test Key');
	assert.ok(keys[0].localKeyId.length > 0);
	assert.deepEqual(keys[0].localKeyId, certificates[0].localKeyId);
});

test('wrong password fails on the MAC', () => {
	assert.throws(() => readPkcs12(fixture('legacy.p12'), 'test124'), /MAC mismatch/);
	assert.throws(() => readPkcs12(fixture('legacy.p12'), ''), /MAC mismatch/);
});

test('SHA-256 MAC passes, then PBES2 is reported as unsupported', () => {
	// PBES2 OID 1.2.840.113549.1.5.13. Getting this far proves the MAC
	// check worked with SHA-256 and the right password.
	assert.throws(() => readPkcs12(fixture('modern.p12'), 'test123'), /unsupported encryption 1\.2\.840\.113549\.1\.5\.13/);
	assert.throws(() => readPkcs12(fixture('modern.p12'), 'nope'), /MAC mismatch/);
});
