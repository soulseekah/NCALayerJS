import { test } from 'node:test';
import assert from 'node:assert/strict';
import { expandKey, encryptBlock, decryptBlock, cbcEncrypt, cbcDecrypt } from '../src/rc2.mjs';

const hex = (s) => Buffer.from(s.replace(/\s/g, ''), 'hex');

// RFC 2268 section 5: [key, effective bits, plaintext, ciphertext].
const VECTORS = [
	['00000000 00000000', 63, '00000000 00000000', 'ebb773f9 93278eff'],
	['ffffffff ffffffff', 64, 'ffffffff ffffffff', '278b27e4 2e2f0d49'],
	['30000000 00000000', 64, '10000000 00000001', '30649edf 9be7d2c2'],
	['88', 64, '00000000 00000000', '61a8a244 adacccf0'],
	['88bca90e 90875a', 64, '00000000 00000000', '6ccf4308 974c267f'],
	['88bca90e 90875a7f 0f79c384 627bafb2', 64, '00000000 00000000', '1a807d27 2bbe5db1'],
	['88bca90e 90875a7f 0f79c384 627bafb2', 128, '00000000 00000000', '2269552a b0f85ca6'],
	['88bca90e 90875a7f 0f79c384 627bafb2 16f80a6f 85920584 c42fceb0 be255daf 1e', 129, '00000000 00000000', '5b78d3a4 3dfff1f1'],
];

for (const [key, bits, plain, cipher] of VECTORS) {
	test(`RFC 2268 vector: ${hex(key).length}-byte key, ${bits} bits`, () => {
		const K = expandKey(hex(key), bits);
		assert.deepEqual(encryptBlock(K, hex(plain)), hex(cipher));
		assert.deepEqual(decryptBlock(K, hex(cipher)), hex(plain));
	});
}

test('CBC round trip for lengths around the block size', () => {
	const key = hex('0102030405');
	const iv = hex('0011223344556677');
	for (const len of [0, 1, 7, 8, 9, 16, 100]) {
		const data = Buffer.alloc(len, 0x5a);
		const enc = cbcEncrypt(key, 40, iv, data);
		assert.equal(enc.length, (Math.floor(len / 8) + 1) * 8);
		assert.deepEqual(cbcDecrypt(key, 40, iv, enc), data, `length ${len}`);
	}
});

test('CBC decrypt rejects bad padding and bad lengths', () => {
	const key = hex('0102030405');
	const iv = Buffer.alloc(8);
	const enc = cbcEncrypt(key, 40, iv, Buffer.from('hello'));
	assert.throws(() => cbcDecrypt(hex('0102030406'), 40, iv, enc), /bad padding/);
	assert.throws(() => cbcDecrypt(key, 40, iv, enc.subarray(0, 7)), /multiple of 8/);
	assert.throws(() => cbcDecrypt(key, 40, iv, Buffer.alloc(0)), /multiple of 8/);
});

test('expandKey rejects bad parameters', () => {
	assert.throws(() => expandKey(Buffer.alloc(0), 64), /1 to 128 bytes/);
	assert.throws(() => expandKey(Buffer.alloc(129), 64), /1 to 128 bytes/);
	assert.throws(() => expandKey(Buffer.alloc(8), 0), /1 to 1024 bits/);
});
