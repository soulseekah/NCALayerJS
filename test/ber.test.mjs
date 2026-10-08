import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseBer, octets, oid, toBigInt, fromBigInt, parseTime, TAG } from '../src/ber.mjs';

const hex = (s) => Buffer.from(s.replace(/\s/g, ''), 'hex');

test('parses a definite length sequence', () => {
	// SEQUENCE { INTEGER 5, NULL }
	const node = parseBer(hex('3005 020105 0500'));
	assert.equal(node.tag, TAG.SEQUENCE);
	assert.equal(node.children.length, 2);
	assert.deepEqual(node.children[0].value, hex('05'));
	assert.equal(node.children[1].tag, TAG.NULL);
	assert.equal(node.end, 7);
});

test('parses long form lengths', () => {
	const body = Buffer.alloc(200, 0xab);
	const node = parseBer(Buffer.concat([hex('0481c8'), body]));
	assert.equal(node.value.length, 200);
	assert.equal(node.end, 203);
});

test('parses indefinite length with end-of-contents', () => {
	// SEQUENCE (indefinite) { INTEGER 1 } EOC, followed by a trailing byte.
	const node = parseBer(hex('3080 020101 0000 ff'));
	assert.equal(node.children.length, 1);
	assert.equal(node.end, 7);
	assert.deepEqual(node.raw, hex('3080 020101 0000'));
});

test('raw holds the full encoding of nested nodes', () => {
	const node = parseBer(hex('3008 a006 0404 deadbeef'));
	assert.deepEqual(node.children[0].raw, hex('a006 0404 deadbeef'));
	assert.deepEqual(node.children[0].children[0].raw, hex('0404 deadbeef'));
});

test('octets joins constructed OCTET STRING parts', () => {
	const node = parseBer(hex('2480 0402 0102 0401 03 0000'));
	assert.deepEqual(octets(node), hex('010203'));
});

test('decodes OIDs', () => {
	assert.equal(oid(parseBer(hex('06092a864886f70d010701'))), '1.2.840.113549.1.7.1');
	// Kazakh GOST 2015 512 signature algorithm.
	assert.equal(oid(parseBer(hex('060a2a830e030a0101020302'))), '1.2.398.3.10.1.1.2.3.2');
	// First arc 2 with a large second arc: 2.999.3
	assert.equal(oid(parseBer(hex('0603883703'))), '2.999.3');
});

test('oid rejects non-OID nodes', () => {
	assert.throws(() => oid(parseBer(hex('020101'))), /expected OID/);
});

test('rejects malformed input', () => {
	assert.throws(() => parseBer(hex('1f01 00')), /high tag/);
	assert.throws(() => parseBer(hex('0480')), /indefinite length on a primitive/);
	assert.throws(() => parseBer(hex('0405 0102')), /exceeds buffer/);
	assert.throws(() => parseBer(hex('3003 020201')), /exceeds buffer/);
	assert.throws(() => parseBer(hex('')), /unexpected end/);
});

test('toBigInt and fromBigInt round trip in both byte orders', () => {
	assert.equal(toBigInt(hex('0102')), 0x0102n);
	assert.equal(toBigInt(hex('0102'), true), 0x0201n);
	assert.equal(toBigInt(hex('')), 0n);
	assert.deepEqual(fromBigInt(0x0102n, 4), hex('00000102'));
	assert.deepEqual(fromBigInt(0x0102n, 4, true), hex('02010000'));
	assert.throws(() => fromBigInt(0x10000n, 2), /does not fit/);
	assert.throws(() => fromBigInt(-1n, 2), /negative/);
});

test('accepts Uint8Array input', () => {
	const node = parseBer(new Uint8Array([0x02, 0x01, 0x07]));
	assert.deepEqual(node.value, hex('07'));
});

test('parseTime reads UTCTime with the 1950 pivot', () => {
	assert.deepEqual(parseTime(parseBer(Buffer.concat([hex('170d'), Buffer.from('260615123851Z')]))), new Date('2026-06-15T12:38:51Z'));
	assert.deepEqual(parseTime(parseBer(Buffer.concat([hex('170d'), Buffer.from('500101000000Z')]))), new Date('1950-01-01T00:00:00Z'));
});

test('parseTime reads GeneralizedTime with and without fractions', () => {
	assert.deepEqual(parseTime(parseBer(Buffer.concat([hex('180f'), Buffer.from('20260921093817Z')]))), new Date('2026-09-21T09:38:17Z'));
	assert.deepEqual(parseTime(parseBer(Buffer.concat([hex('1812'), Buffer.from('20260921093817.25Z')]))), new Date('2026-09-21T09:38:17.250Z'));
});

test('parseTime rejects local times and other tags', () => {
	assert.throws(() => parseTime(parseBer(Buffer.concat([hex('180e'), Buffer.from('20260921093817')]))), /unsupported time/);
	assert.throws(() => parseTime(parseBer(hex('020101'))), /unsupported time/);
});
