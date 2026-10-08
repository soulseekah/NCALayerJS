import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createBasicsModule, parseSignArgs, keyMismatch, preview, nestingError, impliesClientAuth, MODULE } from '../src/basics.mjs';
import { verifyXml } from '../src/xmldsig.mjs';
import { verifyCms } from '../src/cms.mjs';
import { parseCertificate } from '../src/x509.mjs';
import { pemToDer } from '../src/x509.mjs';
import { makeSigner, randomKey, selfSignedCertificate } from './helpers/gost.mjs';

const signer = makeSigner({ extraSubject: [['2.5.4.5', 'IIN870724051399']], extKeyUsage: ['1.3.6.1.5.5.7.3.4'] });
const now = () => new Date('2026-10-08T12:00:00Z');
const context = { origin: 'https://nca.pki.gov.kz' };

// The request shape the NCA RK login page sends (data shortened).
const loginArgs = {
	allowedStorages: ['AKKaztokenStore', 'PKCS12', 'JKS'],
	format: 'xml',
	data: '<?xml version="1.0" encoding="utf-8"?><root><data>1e2a9b00-76c5-4e0a-97d7-e418b5000000</data></root>',
	signingParams: { decode: false, encapsulate: false, digested: false, tsaProfile: null },
	signerParams: { extKeyUsageOids: [], chain: [] },
	locale: 'ru',
};

/**
 * Creates a module with a recording confirm callback.
 *
 * @param {boolean} answer What the user answers.
 * @param {object} [options] More createBasicsModule options.
 * @returns {{handler: Function, asked: Array<object>, logs: Array<string>}}
 */
function setup(answer = true, options = {}) {
	const asked = [];
	const logs = [];
	const handler = createBasicsModule({
		signer,
		confirm: async (summary) => {
			asked.push(summary);
			return answer;
		},
		log: (line) => logs.push(line),
		now,
		...options,
	});
	return { handler, asked, logs };
}

/**
 * Builds a basics sign request.
 *
 * @param {object} args Args overrides on top of loginArgs.
 * @returns {object}
 */
function signRequest(args = {}) {
	return { module: MODULE, method: 'sign', args: { ...loginArgs, ...args } };
}

test('signs the login challenge as XML after confirmation', async () => {
	const { handler, asked } = setup();
	const res = await handler(signRequest(), context);
	assert.equal(res.status, true);
	assert.equal(res.body.result.length, 1);
	const check = verifyXml(res.body.result[0]);
	assert.equal(check.valid, true, check.reason);
	assert.equal(asked.length, 1);
	assert.equal(asked[0].origin, 'https://nca.pki.gov.kz');
	assert.equal(asked[0].format, 'xml');
	assert.match(asked[0].previews[0], /1e2a9b00/);
	assert.equal(asked[0].timestamp, false);
});

test('a declined request returns the NCALayer cancel response', async () => {
	const { handler, logs } = setup(false);
	assert.deepEqual(await handler(signRequest(), context), { status: true, body: {} });
	assert.ok(logs.includes('declined by the user'));
});

test('signs several CMS items, attached and detached', async () => {
	const { handler } = setup();
	const res = await handler(signRequest({ format: 'cms', data: ['one', 'two'], signingParams: {} }), context);
	assert.equal(res.body.result.length, 2);
	for (const [i, pem] of res.body.result.entries()) {
		assert.match(pem, /^-----BEGIN CMS-----\n[A-Za-z0-9+/=\n]+\n-----END CMS-----$/);
		const { content, signers } = verifyCms(pemToDer(Buffer.from(pem)));
		assert.equal(signers[0].valid, true);
		assert.equal(content.toString(), ['one', 'two'][i]);
	}
	const detached = await handler(signRequest({ format: 'cms', data: 'one', signingParams: { encapsulate: false } }), context);
	assert.throws(() => verifyCms(pemToDer(Buffer.from(detached.body.result[0]))), /content is required/);
});

test('decodes base64 CMS data and adds a timestamp only for a tsaProfile object', async () => {
	const stamped = [];
	const { handler, asked } = setup(true, { timestamp: async (der) => { stamped.push(der); return der; } });
	const data = Buffer.from('payload').toString('base64');
	const res = await handler(signRequest({ format: 'cms', data, signingParams: { decode: true, tsaProfile: {} } }), context);
	assert.equal(verifyCms(pemToDer(Buffer.from(res.body.result[0]))).content.toString(), 'payload');
	assert.equal(stamped.length, 1);
	assert.equal(asked[0].timestamp, true);
	assert.equal(asked[0].previews[0], 'payload');
	await handler(signRequest({ format: 'cms', data, signingParams: { decode: true, tsaProfile: null } }), context);
	assert.equal(stamped.length, 1);
});

test('invalid parameters fail like NCALayer, without asking', async () => {
	const { handler, asked } = setup();
	const cases = [
		[{ format: 'pdf' }, /unknown format/],
		[{ data: [] }, /non-empty array/],
		[{ signingParams: null }, /signingParams/],
		[{ signerParams: {} }, /extKeyUsageOids/],
		[{ format: 'raw' }, /raw is not supported/],
		[{ format: 'cms', signingParams: { digested: true } }, /digested/],
		[{ format: 'cms', data: '!!!', signingParams: { decode: true } }, /base64/],
	];
	for (const [args, details] of cases) {
		const res = await handler(signRequest(args), context);
		assert.equal(res.status, false);
		assert.equal(res.code, 'INVALID_SIGNING_PARAMS');
		assert.equal(res.message, 'Invalid signing parameters provided.');
		assert.match(res.details, details);
	}
	assert.equal(asked.length, 0);
});

test('malformed XML fails before asking', async () => {
	const { handler, asked } = setup();
	const res = await handler(signRequest({ data: '<root><unclosed></root>' }), context);
	assert.equal(res.status, false);
	assert.equal(res.code, 'UNABLE_TO_PARSE_XML');
	assert.equal(asked.length, 0);
});

test('co-signing an existing CMS is refused for now', async () => {
	const { handler } = setup();
	const first = await handler(signRequest({ format: 'cms', data: 'x', signingParams: {} }), context);
	const der = pemToDer(Buffer.from(first.body.result[0])).toString('base64');
	const res = await handler(signRequest({ format: 'cms', data: der, signingParams: { decode: true } }), context);
	assert.equal(res.code, 'SIGNING_FAILURE');
	assert.match(res.details, /co-signing/);
});

test('unknown classes, methods and api versions are general errors', async () => {
	const { handler } = setup();
	assert.equal((await handler({ ...signRequest(), method: 'nope' }, context)).code, 'GENERAL_ERROR');
	assert.equal((await handler({ ...signRequest(), class: 'PKIEssentials' }, context)).code, 'GENERAL_ERROR');
	const res = await handler({ ...signRequest(), apiVersion: 1 }, context);
	assert.equal(res.code, 'GENERAL_ERROR');
	assert.equal(res.message, 'General error.');
	assert.equal(res.details, 'Supported apiVersion is 2');
});

test('keys that do not match the request are not offered', async () => {
	const { handler, asked, logs } = setup();
	const res = await handler(signRequest({ allowedStorages: ['AKKaztokenStore'] }), context);
	assert.deepEqual(res, { status: true, body: {} });
	assert.equal(asked.length, 0);
	assert.ok(logs.some((l) => /PKCS12/.test(l)));
});

test('keyMismatch checks storages, key usage, IIN, BIN, serial, chain and validity', () => {
	const cert = signer.certificate;
	const args = (signerParams, extra = {}) => parseSignArgs({ ...loginArgs, signerParams: { extKeyUsageOids: [], ...signerParams }, ...extra });
	const at = now();
	assert.equal(keyMismatch(cert, args({}), at), null);
	assert.equal(keyMismatch(cert, args({}, { allowedStorages: null }), at), null);
	assert.equal(keyMismatch(cert, args({ extKeyUsageOids: ['1.3.6.1.5.5.7.3.4'] }), at), null);
	assert.match(keyMismatch(cert, args({ extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'] }), at), /key usages/);
	assert.equal(keyMismatch(cert, args({ iin: '870724051399' }), at), null);
	assert.match(keyMismatch(cert, args({ iin: '111111111111' }), at), /IIN/);
	assert.match(keyMismatch(cert, args({ bin: '000740000728' }), at), /BIN/);
	assert.equal(keyMismatch(cert, args({ serialNumber: cert.serial.toString(16) }), at), null);
	assert.match(keyMismatch(cert, args({ serialNumber: 'ff' }), at), /certificate ff/);
	// Self-signed: the certificate is its own issuer, so it trusts itself.
	const self = cert.der.toString('base64');
	assert.equal(keyMismatch(cert, args({ chain: [self] }), at), null);
	const other = selfSignedCertificate(randomKey(), { cn: 'Other CA' }).toString('base64');
	assert.match(keyMismatch(cert, args({ chain: [other, 'garbage'] }), at), /issuer/);
	assert.match(keyMismatch(cert, args({}), new Date('2030-01-01T00:00:00Z')), /not valid/);
	assert.equal(keyMismatch(cert, args({}, { signingParams: { allowExpired: true } }), new Date('2030-01-01T00:00:00Z')), null);
});

test('preview shortens long data and hides binary', () => {
	assert.equal(preview('<a/>', 'xml', false), '<a/>');
	assert.match(preview('x'.repeat(1000), 'xml', false), /\.\.\. \(1000 chars\)$/);
	assert.equal(preview(Buffer.from('Сәлем').toString('base64'), 'cms', true), 'Сәлем');
	assert.equal(preview(Buffer.from([0, 1, 2, 255]).toString('base64'), 'cms', true), '(4 bytes of binary data)');
});

test('the real login chain format is accepted', () => {
	// Chain entries arrive as PEM with headers, like the NCA page sends them.
	const pem = `-----BEGIN CERTIFICATE-----\n${signer.certificate.der.toString('base64')}\n-----END CERTIFICATE-----`;
	const args = parseSignArgs({ ...loginArgs, signerParams: { extKeyUsageOids: [], chain: [pem] } });
	assert.equal(keyMismatch(parseCertificate(signer.certificate.der), args, now()), null);
});

test('nestingError finds broken nesting and ignores markup that is not a tag', () => {
	assert.equal(nestingError('<?xml version="1.0"?><!DOCTYPE r><r a="x>y"><!-- <b> --><![CDATA[<c>]]><d/><e></e></r>'), null);
	assert.match(nestingError('<a><b></a></b>'), /does not match/);
	assert.match(nestingError('<root><unclosed></root>'), /does not match/);
	assert.match(nestingError('<root>'), /unclosed tag <root>/);
	assert.match(nestingError('</x>'), /<nothing>/);
});

test('all kinds of malformed XML are refused', async () => {
	const { handler, asked } = setup();
	for (const data of ['<root><unclosed></root>', '<a><b></a></b>', 'not xml', '<root a=1/>', '<root>&bogus;</root>']) {
		const res = await handler(signRequest({ data }), context);
		assert.equal(res.code, 'UNABLE_TO_PARSE_XML', data);
		assert.equal(res.message, 'Unable to parse XML.');
	}
	assert.equal(asked.length, 0);
});

test('GOST certificates with keyAgreement count as clientAuth, like NCALayer', () => {
	// The shape of the egov.kz login request.
	const egov = parseSignArgs({ ...loginArgs, signingParams: {}, signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.2'] } });
	const both = makeSigner({ keyUsage: ['digitalSignature', 'nonRepudiation', 'keyAgreement'], extKeyUsage: ['1.3.6.1.5.5.7.3.4', '1.2.398.3.3.4.1.1'] });
	const signOnly = makeSigner({ keyUsage: ['digitalSignature', 'nonRepudiation'], extKeyUsage: ['1.3.6.1.5.5.7.3.4'] });
	assert.equal(impliesClientAuth(both.certificate), true);
	assert.equal(impliesClientAuth(signOnly.certificate), false);
	assert.equal(keyMismatch(both.certificate, egov, now()), null);
	assert.match(keyMismatch(signOnly.certificate, egov, now()), /1\.3\.6\.1\.5\.5\.7\.3\.2/);
	// Only clientAuth is implied; other usages are still required as listed.
	const other = parseSignArgs({ ...loginArgs, signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.1'] } });
	assert.match(keyMismatch(both.certificate, other, now()), /1\.3\.6\.1\.5\.5\.7\.3\.1/);
});
