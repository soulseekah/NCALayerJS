import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { CURVES, CURVE_BY_OID, makeCurve, multiply, isOnCurve, publicKey, sign, verify } from '../src/gost3410.mjs';

// RFC 7091 section 7 example. Hex values are split where the RFC splits
// them, to make comparing with the RFC text easy.
const RFC = {
	curve: makeCurve({
		p: '8000000000000000000000000000' + '000000000000000000000000000000000431',
		a: '7',
		b: '5FBFF498AA938CE739B8E022FBAFEF40563' + 'F6E6A3472FC2A514C0CE9DAE23B7E',
		q: '80000000000000000000000000000001' + '50FE8A1892976154C59CFC193ACCF5B3',
		x: '2',
		y: '8E2A8A0E65147D4BD6316030E16D19' + 'C85C97F0A9CA267122B96ABBCEA7E8FC8',
	}),
	d: BigInt('0x7A929ADE789BB9BE10ED359DD39A72C' + '11B60961F49397EEE1D19CE9891EC3B28'),
	xq: BigInt('0x7F2B49E270DB6D90D8595BEC458B5' + '0C58585BA1D4E9B788F6689DBD8E56FD80B'),
	yq: BigInt('0x26F1B489D6701DD185C8413A977B3' + 'CBBAF64D1C593D26627DFFB101A87FF77DA'),
	e: BigInt('0x2DFBC1B372D89A1188C09C52E0EE' + 'C61FCE52032AB1022E8E67ECE6672B043EE5'),
	k: BigInt('0x77105C9B20BCD3122823C8CF6FCC' + '7B956DE33814E95B7FE64FED924594DCEAB3'),
	r: BigInt('0x41AA28D2F1AB148280CD9ED56FED' + 'A41974053554A42767B83AD043FD39DC0493'),
	s: BigInt('0x1456C64BA4642A1653C235A98A602' + '49BCD6D3F746B631DF928014F6C5BF9C40'),
};

for (const [name, c] of Object.entries(CURVES)) {
	test(`curve ${name}: G is on the curve and has order q`, () => {
		assert.equal(c.bits, 512);
		assert.ok(isOnCurve(c.G, c));
		assert.equal(multiply(c.q, c.G, c), null);
	});
}

test('Kazakh curve OID maps to tc26 paramSet A', () => {
	assert.equal(CURVE_BY_OID['1.2.398.3.10.1.1.2.2.1'], CURVES['tc26-512-A']);
});

test('RFC 7091: public key from private key', () => {
	assert.deepEqual(publicKey(RFC.curve, RFC.d), [RFC.xq, RFC.yq]);
});

test('RFC 7091: signature with the given nonce', () => {
	assert.deepEqual(sign(RFC.curve, RFC.d, RFC.e, RFC.k), { r: RFC.r, s: RFC.s });
});

test('RFC 7091: verification', () => {
	const Q = [RFC.xq, RFC.yq];
	assert.equal(verify(RFC.curve, Q, RFC.e, RFC.r, RFC.s), true);
	assert.equal(verify(RFC.curve, Q, RFC.e + 1n, RFC.r, RFC.s), false);
	assert.equal(verify(RFC.curve, Q, RFC.e, RFC.r, RFC.s + 1n), false);
	assert.equal(verify(RFC.curve, Q, RFC.e, RFC.s, RFC.r), false);
});

test('verify rejects r and s out of range', () => {
	const Q = [RFC.xq, RFC.yq];
	const q = RFC.curve.q;
	assert.equal(verify(RFC.curve, Q, RFC.e, 0n, RFC.s), false);
	assert.equal(verify(RFC.curve, Q, RFC.e, RFC.r, q), false);
	assert.equal(verify(RFC.curve, Q, RFC.e, RFC.r + q, RFC.s), false);
});

test('verify rejects a public key that is not on the curve', () => {
	assert.equal(verify(RFC.curve, [RFC.xq, RFC.yq + 1n], RFC.e, RFC.r, RFC.s), false);
});

test('publicKey rejects out of range private keys', () => {
	assert.throws(() => publicKey(RFC.curve, 0n), /out of range/);
	assert.throws(() => publicKey(RFC.curve, RFC.curve.q), /out of range/);
});

test('512-bit sign and verify round trip on paramSet A', () => {
	const c = CURVES['tc26-512-A'];
	const d = (BigInt('0x' + randomBytes(64).toString('hex')) % (c.q - 1n)) + 1n;
	const Q = publicKey(c, d);
	const alpha = BigInt('0x' + randomBytes(64).toString('hex'));
	const { r, s } = sign(c, d, alpha);
	assert.equal(verify(c, Q, alpha, r, s), true);
	assert.equal(verify(c, Q, alpha ^ 1n, r, s), false);
});

test('random nonces give different signatures', () => {
	const a = sign(RFC.curve, RFC.d, RFC.e);
	const b = sign(RFC.curve, RFC.d, RFC.e);
	assert.notEqual(a.r, b.r);
});

test('hash equal to zero mod q is treated as e = 1', () => {
	const { r, s } = sign(RFC.curve, RFC.d, RFC.curve.q, RFC.k);
	assert.deepEqual(sign(RFC.curve, RFC.d, 1n, RFC.k), { r, s });
});
