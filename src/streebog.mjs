// GOST R 34.11-2012 (Streebog) hash function, as described in RFC 6986.
//
// All 512-bit values are stored as 64-byte arrays in memory order, which
// is little-endian: byte i holds a_i from the RFC notation.

// Substitution Pi', RFC 6986 section 6.2.
const PI = Uint8Array.from([
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
	233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
	249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
	5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
	235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
	181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
	21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
	50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
	223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
	224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
	167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
	173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
	7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
	225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
	32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
	89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
]);

// Rows 0..63 of matrix A, RFC 6986 section 6.4.
const A = [
	'8e20faa72ba0b470', '47107ddd9b505a38', 'ad08b0e0c3282d1c', 'd8045870ef14980e',
	'6c022c38f90a4c07', '3601161cf205268d', '1b8e0b0e798c13c8', '83478b07b2468764',
	'a011d380818e8f40', '5086e740ce47c920', '2843fd2067adea10', '14aff010bdd87508',
	'0ad97808d06cb404', '05e23c0468365a02', '8c711e02341b2d01', '46b60f011a83988e',
	'90dab52a387ae76f', '486dd4151c3dfdb9', '24b86a840e90f0d2', '125c354207487869',
	'092e94218d243cba', '8a174a9ec8121e5d', '4585254f64090fa0', 'accc9ca9328a8950',
	'9d4df05d5f661451', 'c0a878a0a1330aa6', '60543c50de970553', '302a1e286fc58ca7',
	'18150f14b9ec46dd', '0c84890ad27623e0', '0642ca05693b9f70', '0321658cba93c138',
	'86275df09ce8aaa8', '439da0784e745554', 'afc0503c273aa42a', 'd960281e9d1d5215',
	'e230140fc0802984', '71180a8960409a42', 'b60c05ca30204d21', '5b068c651810a89e',
	'456c34887a3805b9', 'ac361a443d1c8cd2', '561b0d22900e4669', '2b838811480723ba',
	'9bcf4486248d9f5d', 'c3e9224312c8c1a0', 'effa11af0964ee50', 'f97d86d98a327728',
	'e4fa2054a80b329c', '727d102a548b194e', '39b008152acb8227', '9258048415eb419d',
	'492c024284fbaec0', 'aa16012142f35760', '550b8e9e21f7a530', 'a48b474f9ef5dc18',
	'70a6a56e2440598e', '3853dc371220a247', '1ca76e95091051ad', '0edd37c48a08a6d8',
	'07e095624504536c', '8d70c431ac02a736', 'c83862965601dd1b', '641c314b2b8ee083',
];

// Iteration constants C[1]..C[12], RFC 6986 section 6.5, big-endian hex.
const C_HEX = [
	'b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc' +
		'4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507',
	'6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b50131' +
		'9ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7',
	'f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7b' +
		'd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2',
	'ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353f' +
		'a9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e',
	'4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbd' +
		'bfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57',
	'ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6' +
		'cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e',
	'f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c9' +
		'0992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493',
	'9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49a' +
		'f4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e',
	'378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984' +
		'800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb',
	'abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b336103' +
		'9fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced',
	'7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798' +
		'a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b',
	'378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b' +
		'5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720',
];

// Iteration constants in memory order.
const C = C_HEX.map((hex) => Uint8Array.from(Buffer.from(hex, 'hex').reverse()));

// Combined S, P and L lookup tables. For byte position k (0..7) of a
// 64-bit word and input byte x, entry k * 256 + x holds l() of a word that
// has only byte k set to Pi(x). Split into high and low 32-bit halves.
const T_HI = new Uint32Array(8 * 256);
const T_LO = new Uint32Array(8 * 256);

for (let k = 0; k < 8; k++) {
	for (let x = 0; x < 256; x++) {
		const v = PI[x];
		let hi = 0;
		let lo = 0;
		for (let t = 0; t < 8; t++) {
			if (v & (1 << t)) {
				// Bit b_i of the input selects row 63 - i.
				const row = A[63 - (8 * k + t)];
				hi ^= parseInt(row.slice(0, 8), 16);
				lo ^= parseInt(row.slice(8), 16);
			}
		}
		T_HI[k * 256 + x] = hi >>> 0;
		T_LO[k * 256 + x] = lo >>> 0;
	}
}

/**
 * Applies the LPS transformation to a 512-bit value.
 *
 * @param {Uint8Array} a 64-byte input.
 * @returns {Uint8Array} 64-byte output.
 */
function lps(a) {
	const out = new Uint8Array(64);
	for (let j = 0; j < 8; j++) {
		let hi = 0;
		let lo = 0;
		for (let k = 0; k < 8; k++) {
			// P moves byte 8k + j to position 8j + k (Tau is a transpose).
			const idx = k * 256 + a[8 * k + j];
			hi ^= T_HI[idx];
			lo ^= T_LO[idx];
		}
		const o = 8 * j;
		out[o] = lo;
		out[o + 1] = lo >>> 8;
		out[o + 2] = lo >>> 16;
		out[o + 3] = lo >>> 24;
		out[o + 4] = hi;
		out[o + 5] = hi >>> 8;
		out[o + 6] = hi >>> 16;
		out[o + 7] = hi >>> 24;
	}
	return out;
}

/**
 * XORs two 512-bit values.
 *
 * @param {Uint8Array} a 64-byte value.
 * @param {Uint8Array} b 64-byte value.
 * @returns {Uint8Array} New 64-byte value.
 */
function xor(a, b) {
	const out = new Uint8Array(64);
	for (let i = 0; i < 64; i++) {
		out[i] = a[i] ^ b[i];
	}
	return out;
}

/**
 * Adds b to a modulo 2^512, in place.
 *
 * @param {Uint8Array} a 64-byte accumulator.
 * @param {Uint8Array} b 64-byte addend.
 */
function add512(a, b) {
	let carry = 0;
	for (let i = 0; i < 64; i++) {
		const sum = a[i] + b[i] + carry;
		a[i] = sum & 0xff;
		carry = sum >>> 8;
	}
}

/**
 * Adds a small bit count to a 512-bit counter, in place.
 *
 * @param {Uint8Array} n 64-byte counter.
 * @param {number} bits Value to add, at most 512.
 */
function addBits(n, bits) {
	const b = new Uint8Array(64);
	b[0] = bits & 0xff;
	b[1] = bits >>> 8;
	add512(n, b);
}

/**
 * Compression function g_N(h, m), RFC 6986 section 8.
 *
 * @param {Uint8Array} n Counter N.
 * @param {Uint8Array} h Chaining value.
 * @param {Uint8Array} m Message block.
 * @returns {Uint8Array} New chaining value.
 */
function g(n, h, m) {
	let k = lps(xor(h, n));
	let state = m;
	for (let i = 0; i < 12; i++) {
		state = lps(xor(state, k));
		k = lps(xor(k, C[i]));
	}
	return xor(xor(xor(state, k), h), m);
}

/**
 * Streebog hash with an API similar to node:crypto Hash.
 */
export class Streebog {
	/**
	 * @param {number} bits Output length, 512 or 256.
	 */
	constructor(bits = 512) {
		if (bits !== 512 && bits !== 256) {
			throw new Error('Streebog output length must be 512 or 256');
		}
		this.bits = bits;
		this.h = new Uint8Array(64).fill(bits === 512 ? 0x00 : 0x01);
		this.n = new Uint8Array(64);
		this.sigma = new Uint8Array(64);
		this.block = new Uint8Array(64);
		this.blockLength = 0;
		this.finished = false;
	}

	/**
	 * Adds data to the hash.
	 *
	 * @param {Uint8Array|string} data Bytes, or a string hashed as UTF-8.
	 * @returns {Streebog} This instance, for chaining.
	 */
	update(data) {
		if (this.finished) {
			throw new Error('Digest already called');
		}
		const bytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
		let pos = 0;
		while (pos < bytes.length) {
			const take = Math.min(64 - this.blockLength, bytes.length - pos);
			this.block.set(bytes.subarray(pos, pos + take), this.blockLength);
			this.blockLength += take;
			pos += take;
			if (this.blockLength === 64) {
				this.h = g(this.n, this.h, this.block);
				addBits(this.n, 512);
				add512(this.sigma, this.block);
				this.blockLength = 0;
			}
		}
		return this;
	}

	/**
	 * Finishes the hash. The instance can not be used after this call.
	 *
	 * @returns {Buffer} 64 or 32 bytes in memory order.
	 */
	digest() {
		if (this.finished) {
			throw new Error('Digest already called');
		}
		this.finished = true;
		const m = new Uint8Array(64);
		m.set(this.block.subarray(0, this.blockLength));
		m[this.blockLength] = 0x01;
		const zero = new Uint8Array(64);
		let h = g(this.n, this.h, m);
		addBits(this.n, this.blockLength * 8);
		add512(this.sigma, m);
		h = g(zero, h, this.n);
		h = g(zero, h, this.sigma);
		return Buffer.from(this.bits === 512 ? h : h.subarray(32));
	}
}

/**
 * Hashes data with Streebog-512.
 *
 * @param {Uint8Array|string} data Input.
 * @returns {Buffer} 64-byte hash in memory order.
 */
export function streebog512(data) {
	return new Streebog(512).update(data).digest();
}

/**
 * Hashes data with Streebog-256.
 *
 * @param {Uint8Array|string} data Input.
 * @returns {Buffer} 32-byte hash in memory order.
 */
export function streebog256(data) {
	return new Streebog(256).update(data).digest();
}
