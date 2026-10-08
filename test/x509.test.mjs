import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { parseCertificate, pemToDer, OID } from '../src/x509.mjs';
import { randomKey, selfSignedCertificate } from './helpers/gost.mjs';
import { parseBer } from '../src/ber.mjs';

const der = readFileSync(new URL('./fixtures/cert.der', import.meta.url));

test('reads serial, names and public key of an EC certificate', () => {
	const cert = parseCertificate(der);
	const ref = new X509Certificate(der);
	assert.equal(cert.serial, BigInt('0x' + ref.serialNumber));
	assert.equal(cert.spki.algorithm, '1.2.840.10045.2.1');
	assert.deepEqual(cert.spki.params, ['1.2.840.10045.3.1.7']);
	// Uncompressed P-256 point.
	assert.equal(cert.spki.publicKey.length, 65);
	assert.equal(cert.spki.publicKey[0], 0x04);
	assert.equal(parseBer(cert.issuerRaw).end, cert.issuerRaw.length);
	// Self-signed: issuer and subject are the same name.
	assert.deepEqual(cert.issuerRaw, cert.subjectRaw);
	assert.equal(parseBer(cert.serialRaw).value.length > 0, true);
});

test('pemToDer converts PEM and keeps DER', () => {
	const pem = Buffer.from(new X509Certificate(der).toString());
	assert.deepEqual(pemToDer(pem), der);
	assert.equal(pemToDer(der), der);
});

test('rejects data that is not a certificate', () => {
	assert.throws(() => parseCertificate(Buffer.from('3003020101', 'hex')), /not a certificate/);
});

test('reads validity, subject attributes and extended key usage', () => {
	const der = selfSignedCertificate(randomKey(), {
		cn: 'КОВШЕНИН ГЕННАДИЙ',
		extraSubject: [['2.5.4.5', 'IIN870724051399'], ['2.5.4.11', 'BIN000740000728']],
		extKeyUsage: ['1.3.6.1.5.5.7.3.4', '1.2.398.3.3.4.1.1'],
		notBefore: new Date('2026-10-08T09:31:32Z'),
		notAfter: new Date('2027-10-08T09:31:32Z'),
	});
	const cert = parseCertificate(der);
	assert.deepEqual(cert.subject, [
		{ oid: OID.COMMON_NAME, value: 'КОВШЕНИН ГЕННАДИЙ' },
		{ oid: OID.SERIAL_NUMBER, value: 'IIN870724051399' },
		{ oid: OID.ORGANIZATIONAL_UNIT, value: 'BIN000740000728' },
	]);
	assert.deepEqual(cert.issuer, cert.subject);
	assert.deepEqual(cert.notBefore, new Date('2026-10-08T09:31:32Z'));
	assert.deepEqual(cert.notAfter, new Date('2027-10-08T09:31:32Z'));
	assert.deepEqual(cert.extKeyUsage, ['1.3.6.1.5.5.7.3.4', '1.2.398.3.3.4.1.1']);
});

test('extKeyUsage is null without the extension', () => {
	assert.equal(parseCertificate(selfSignedCertificate(randomKey())).extKeyUsage, null);
	assert.equal(parseCertificate(der).extKeyUsage, null);
});

test('decodes the subject of an OpenSSL certificate', () => {
	assert.deepEqual(parseCertificate(der).subject, [{ oid: OID.COMMON_NAME, value: 'NCALayerJS test' }]);
});

test('reads key usage bits and the signature algorithm', () => {
	const cert = parseCertificate(selfSignedCertificate(randomKey(), { keyUsage: ['digitalSignature', 'nonRepudiation', 'keyAgreement', 'decipherOnly'] }));
	assert.deepEqual(cert.keyUsage, ['digitalSignature', 'nonRepudiation', 'keyAgreement', 'decipherOnly']);
	assert.equal(cert.signatureAlgorithm, '1.2.398.3.10.1.1.2.3.2');
	assert.equal(parseCertificate(selfSignedCertificate(randomKey())).keyUsage, null);
	// The OpenSSL fixture is signed with ecdsa-with-SHA256.
	assert.equal(parseCertificate(der).signatureAlgorithm, '1.2.840.10045.4.3.2');
});
