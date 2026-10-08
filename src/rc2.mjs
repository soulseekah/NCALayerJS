// RC2 block cipher (RFC 2268) in CBC mode. Needed because old PKCS#12
// files encrypt certificates with 40-bit RC2, and Node only offers RC2
// with the OpenSSL legacy provider.

// PITABLE from RFC 2268 section 2, one row of 16 bytes per line.
const PITABLE = Buffer.from([
	'd978f9c419ddb5ed28e9fd794aa0d89d',
	'c67e37832b76538e624c6488448bfba2',
	'179a59f587b34f1361456d8d09817d32',
	'bd8f40eb86b77b0bf09521225c6b4e82',
	'54d66593ce60b21c7356c014a78cf1dc',
	'1275ca1f3bbee4d1423dd430a33cb626',
	'6fbf0eda4669075727f21d9bbc944303',
	'f811c7f690ef3ee706c3d52fc8661ed7',
	'08e8eade8052eef784aa72ac354d6a2a',
	'961ad2715a1549744b9fd05e0418a4ec',
	'c2e0416e0f51cbcc2491af50a1f47039',
	'997c3a8523b8b47afc02365b25559731',
	'2d5dfa98e38a92ae05df2910676cbac9',
	'd300e6cfe19ea82c6316013f58e289a9',
	'0d38341bab33ffb0bb480c5fb9b1cd2e',
	'c5f3db47e5a59c770aa62068fe7fc1ad',
].join(''), 'hex');

// Rotation amounts s[0..3].
const S = [1, 2, 3, 5];

/**
 * Expands a key to 64 16-bit words, RFC 2268 section 2.
 *
 * @param {Uint8Array} key Key of 1 to 128 bytes.
 * @param {number} effectiveBits Effective key length T1, 1 to 1024.
 * @returns {Uint16Array} Expanded key K[0..63].
 */
export function expandKey(key, effectiveBits) {
	const t = key.length;
	if (t < 1 || t > 128) {
		throw new Error('RC2 key must be 1 to 128 bytes');
	}
	if (effectiveBits < 1 || effectiveBits > 1024) {
		throw new Error('RC2 effective key length must be 1 to 1024 bits');
	}
	const L = new Uint8Array(128);
	L.set(key);
	for (let i = t; i < 128; i++) {
		L[i] = PITABLE[(L[i - 1] + L[i - t]) & 0xff];
	}
	const t8 = (effectiveBits + 7) >> 3;
	const tm = 0xff >> (8 * t8 - effectiveBits);
	L[128 - t8] = PITABLE[L[128 - t8] & tm];
	for (let i = 127 - t8; i >= 0; i--) {
		L[i] = PITABLE[L[i + 1] ^ L[i + t8]];
	}
	const K = new Uint16Array(64);
	for (let i = 0; i < 64; i++) {
		K[i] = L[2 * i] | (L[2 * i + 1] << 8);
	}
	return K;
}

/**
 * Encrypts one 8-byte block, RFC 2268 section 3.
 *
 * @param {Uint16Array} K Expanded key.
 * @param {Uint8Array} block 8-byte input.
 * @returns {Buffer} 8-byte output.
 */
export function encryptBlock(K, block) {
	const R = [0, 1, 2, 3].map((i) => block[2 * i] | (block[2 * i + 1] << 8));
	let j = 0;
	const mix = (i) => {
		const r1 = R[(i + 3) & 3];
		let x = (R[i] + K[j] + (r1 & R[(i + 2) & 3]) + (~r1 & R[(i + 1) & 3])) & 0xffff;
		j++;
		x = ((x << S[i]) | (x >>> (16 - S[i]))) & 0xffff;
		R[i] = x;
	};
	const mash = (i) => {
		R[i] = (R[i] + K[R[(i + 3) & 3] & 63]) & 0xffff;
	};
	const mixing = (n) => {
		for (let round = 0; round < n; round++) {
			[0, 1, 2, 3].forEach(mix);
		}
	};
	mixing(5);
	[0, 1, 2, 3].forEach(mash);
	mixing(6);
	[0, 1, 2, 3].forEach(mash);
	mixing(5);
	return wordsToBytes(R);
}

/**
 * Decrypts one 8-byte block, RFC 2268 section 4.
 *
 * @param {Uint16Array} K Expanded key.
 * @param {Uint8Array} block 8-byte input.
 * @returns {Buffer} 8-byte output.
 */
export function decryptBlock(K, block) {
	const R = [0, 1, 2, 3].map((i) => block[2 * i] | (block[2 * i + 1] << 8));
	let j = 63;
	const rmix = (i) => {
		let x = R[i];
		x = ((x >>> S[i]) | (x << (16 - S[i]))) & 0xffff;
		const r1 = R[(i + 3) & 3];
		R[i] = (x - K[j] - (r1 & R[(i + 2) & 3]) - (~r1 & R[(i + 1) & 3])) & 0xffff;
		j--;
	};
	const rmash = (i) => {
		R[i] = (R[i] - K[R[(i + 3) & 3] & 63]) & 0xffff;
	};
	const rmixing = (n) => {
		for (let round = 0; round < n; round++) {
			[3, 2, 1, 0].forEach(rmix);
		}
	};
	rmixing(5);
	[3, 2, 1, 0].forEach(rmash);
	rmixing(6);
	[3, 2, 1, 0].forEach(rmash);
	rmixing(5);
	return wordsToBytes(R);
}

/**
 * Packs four 16-bit words into 8 little-endian bytes.
 *
 * @param {Array<number>} R Words.
 * @returns {Buffer}
 */
function wordsToBytes(R) {
	const out = Buffer.alloc(8);
	for (let i = 0; i < 4; i++) {
		out.writeUInt16LE(R[i], 2 * i);
	}
	return out;
}

/**
 * Encrypts with RC2-CBC and PKCS#7 padding.
 *
 * @param {Uint8Array} key Key bytes.
 * @param {number} effectiveBits Effective key length in bits.
 * @param {Uint8Array} iv 8-byte IV.
 * @param {Uint8Array} data Plaintext.
 * @returns {Buffer} Ciphertext.
 */
export function cbcEncrypt(key, effectiveBits, iv, data) {
	const K = expandKey(key, effectiveBits);
	const pad = 8 - (data.length % 8);
	const input = Buffer.concat([Buffer.from(data), Buffer.alloc(pad, pad)]);
	const out = Buffer.alloc(input.length);
	let prev = Buffer.from(iv);
	for (let pos = 0; pos < input.length; pos += 8) {
		const block = Buffer.alloc(8);
		for (let i = 0; i < 8; i++) {
			block[i] = input[pos + i] ^ prev[i];
		}
		prev = encryptBlock(K, block);
		prev.copy(out, pos);
	}
	return out;
}

/**
 * Decrypts RC2-CBC and removes PKCS#7 padding.
 *
 * @param {Uint8Array} key Key bytes.
 * @param {number} effectiveBits Effective key length in bits.
 * @param {Uint8Array} iv 8-byte IV.
 * @param {Uint8Array} data Ciphertext, a multiple of 8 bytes.
 * @returns {Buffer} Plaintext.
 */
export function cbcDecrypt(key, effectiveBits, iv, data) {
	if (data.length === 0 || data.length % 8 !== 0) {
		throw new Error('RC2 ciphertext length must be a positive multiple of 8');
	}
	const K = expandKey(key, effectiveBits);
	const out = Buffer.alloc(data.length);
	let prev = iv;
	for (let pos = 0; pos < data.length; pos += 8) {
		const block = data.subarray(pos, pos + 8);
		const plain = decryptBlock(K, block);
		for (let i = 0; i < 8; i++) {
			out[pos + i] = plain[i] ^ prev[i];
		}
		prev = block;
	}
	const pad = out[out.length - 1];
	if (pad < 1 || pad > 8 || !out.subarray(out.length - pad).every((b) => b === pad)) {
		throw new Error('RC2: bad padding (wrong password?)');
	}
	return out.subarray(0, out.length - pad);
}
