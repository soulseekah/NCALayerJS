import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Streebog, streebog512, streebog256 } from '../src/streebog.mjs';

// RFC 6986 section 10 examples, written in RFC (big-endian) notation like
// gost-engine test_gosthash2012.c does. Reversed to memory order below.
const M1 = '323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130';
const M1_512 = '486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b';
const M1_256 = '00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d';
const M2 = 'fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1';
const M2_512 = '28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e';
const M2_256 = '508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d';

/**
 * Converts RFC notation hex to bytes in memory order.
 *
 * @param {string} hex Big-endian hex string.
 * @returns {Buffer}
 */
function rfc(hex) {
	return Buffer.from(hex, 'hex').reverse();
}

test('RFC 6986 example 1, 512-bit', () => {
	assert.deepEqual(streebog512(rfc(M1)), rfc(M1_512));
});

test('RFC 6986 example 1, 256-bit', () => {
	assert.deepEqual(streebog256(rfc(M1)), rfc(M1_256));
});

test('RFC 6986 example 2, 512-bit, two blocks', () => {
	assert.deepEqual(streebog512(rfc(M2)), rfc(M2_512));
});

test('RFC 6986 example 2, 256-bit, two blocks', () => {
	assert.deepEqual(streebog256(rfc(M2)), rfc(M2_256));
});

test('example 1 message is the ASCII digits string', () => {
	assert.equal(rfc(M1).toString('latin1'), '012345678901234567890123456789012345678901234567890123456789012');
});

test('chunked updates give the same hash as one call', () => {
	const data = Buffer.alloc(300);
	for (let i = 0; i < data.length; i++) {
		data[i] = (i * 31) & 0xff;
	}
	const expected = streebog512(data);
	for (const size of [1, 7, 63, 64, 65, 128]) {
		const h = new Streebog(512);
		for (let pos = 0; pos < data.length; pos += size) {
			h.update(data.subarray(pos, pos + size));
		}
		assert.deepEqual(h.digest(), expected, `chunk size ${size}`);
	}
});

test('exact block multiples differ from their prefixes', () => {
	// Guards the final padding step when the last block is full.
	const a = streebog512(Buffer.alloc(64, 0x61));
	const b = streebog512(Buffer.alloc(63, 0x61));
	const c = streebog512(Buffer.alloc(128, 0x61));
	assert.notDeepEqual(a, b);
	assert.notDeepEqual(a, c);
});

test('strings are hashed as UTF-8', () => {
	assert.deepEqual(streebog512('ҰЛТТЫҚ'), streebog512(Buffer.from('ҰЛТТЫҚ', 'utf8')));
});

test('rejects unsupported output length', () => {
	assert.throws(() => new Streebog(384), /512 or 256/);
});

test('rejects use after digest', () => {
	const h = new Streebog();
	h.digest();
	assert.throws(() => h.update('x'), /already/);
	assert.throws(() => h.digest(), /already/);
});
