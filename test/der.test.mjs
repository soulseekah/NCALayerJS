import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tlv, seq, setOf, int, oid, octetString, nul, time, generalizedTime, boolean, context, algorithm } from '../src/der.mjs';
import { parseBer, oid as readOid, toBigInt, parseTime, TAG } from '../src/ber.mjs';

const hex = (s) => Buffer.from(s.replace(/\s/g, ''), 'hex');

test('integers use minimal two\'s complement encoding', () => {
	assert.deepEqual(int(0), hex('020100'));
	assert.deepEqual(int(127), hex('02017f'));
	assert.deepEqual(int(128), hex('02020080'));
	assert.deepEqual(int(256), hex('02020100'));
	assert.throws(() => int(-1), /negative/);
});

test('large integers round trip', () => {
	const n = 0x6aece0aa19654604264dade91277b64a3b075c5dn;
	const node = parseBer(int(n));
	assert.equal(toBigInt(node.value), n);
});

test('OIDs round trip', () => {
	for (const s of ['1.2.840.113549.1.7.2', '1.2.398.3.10.1.1.2.3.2', '2.999.3', '0.0', '2.5.4.3']) {
		assert.equal(readOid(parseBer(oid(s))), s);
	}
	assert.deepEqual(oid('1.2.840.113549.1.7.1'), hex('06092a864886f70d010701'));
	assert.throws(() => oid('1'), /invalid OID/);
	assert.throws(() => oid('1.40'), /invalid OID/);
	assert.throws(() => oid('3.1'), /invalid OID/);
	assert.throws(() => oid('1.2.x'), /invalid OID/);
});

test('long form lengths', () => {
	for (const len of [127, 128, 255, 256, 70000]) {
		const node = parseBer(octetString(Buffer.alloc(len)));
		assert.equal(node.value.length, len);
	}
	assert.deepEqual(octetString(Buffer.alloc(128)).subarray(0, 3), hex('048180'));
	assert.deepEqual(octetString(Buffer.alloc(256)).subarray(0, 4), hex('04820100'));
});

test('setOf sorts elements by encoding', () => {
	const a = int(2);
	const b = seq(int(1));
	const c = int(1);
	assert.deepEqual(setOf(b, a, c), Buffer.concat([hex('310b'), c, a, b]));
});

test('seq skips null items', () => {
	assert.deepEqual(seq(int(1), null, undefined, nul()), hex('3005 020101 0500'));
});

test('time picks UTCTime before 2050 and GeneralizedTime after', () => {
	assert.deepEqual(time(new Date('2026-06-15T12:38:51.900Z')), tlv(0x17, Buffer.from('260615123851Z')));
	assert.deepEqual(time(new Date('1999-01-02T03:04:05Z')), tlv(0x17, Buffer.from('990102030405Z')));
	assert.deepEqual(time(new Date('2050-01-01T00:00:00Z')), tlv(0x18, Buffer.from('20500101000000Z')));
});

test('context and algorithm helpers', () => {
	assert.deepEqual(context(0, int(1)), hex('a003 020101'));
	assert.deepEqual(context(1), hex('a100'));
	const alg = parseBer(algorithm('1.2.398.3.10.1.3.3'));
	assert.equal(readOid(alg.children[0]), '1.2.398.3.10.1.3.3');
	assert.equal(alg.children[1].tag, TAG.NULL);
});

test('generalizedTime always uses four-digit years', () => {
	assert.deepEqual(generalizedTime(new Date('2026-09-21T09:38:17.900Z')), tlv(0x18, Buffer.from('20260921093817Z')));
	assert.deepEqual(parseTime(parseBer(generalizedTime(new Date('2026-09-21T09:38:17Z')))), new Date('2026-09-21T09:38:17Z'));
});

test('boolean encodes DER true and false', () => {
	assert.deepEqual(boolean(true), hex('0101ff'));
	assert.deepEqual(boolean(false), hex('010100'));
});
