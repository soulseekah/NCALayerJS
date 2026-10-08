// GOST R 34.10-2012 elliptic curve signatures (RFC 7091), affine BigInt
// arithmetic on short Weierstrass curves.
//
// Note: this code is not constant time. It is meant for a local signer
// where the attacker can not time many signing operations.

import { randomBytes } from 'node:crypto';

/**
 * Builds a curve object with BigInt fields from hex strings.
 *
 * @param {{p: string, a: string, b: string, q: string, x: string, y: string}} hex
 * @returns {{p: bigint, a: bigint, b: bigint, q: bigint, G: Array<bigint>, bits: number}}
 */
export function makeCurve(hex) {
	const n = (s) => BigInt('0x' + s);
	const p = n(hex.p);
	return { p, a: n(hex.a), b: n(hex.b), q: n(hex.q), G: [n(hex.x), n(hex.y)], bits: p.toString(2).length > 256 ? 512 : 256 };
}

// Constants copied from gost-engine gost_params.c (commit 4632029).
export const CURVES = {
	'tc26-512-test': makeCurve({
		a: '7',
		b: '1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC43' +
			'61834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC',
		p: '4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15D' +
			'F1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373',
		q: '4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15D' +
			'A82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF',
		x: '24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762' +
			'FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A',
		y: '2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C' +
			'83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E',
	}),
	'tc26-512-A': makeCurve({
		a: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
			'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4',
		b: 'E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265' +
			'EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760',
		p: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
			'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7',
		q: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
			'27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275',
		x: '3',
		y: '7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF16' +
			'26BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4',
	}),
	'tc26-512-B': makeCurve({
		a: '8000000000000000000000000000000000000000000000000000000000000000' +
			'000000000000000000000000000000000000000000000000000000000000006C',
		b: '687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F' +
			'3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116',
		p: '8000000000000000000000000000000000000000000000000000000000000000' +
			'000000000000000000000000000000000000000000000000000000000000006F',
		q: '8000000000000000000000000000000000000000000000000000000000000001' +
			'49A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD',
		x: '2',
		y: '1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335' +
			'DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD',
	}),
	'tc26-512-C': makeCurve({
		a: 'DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E1430645' +
			'46E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3',
		b: 'B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE0' +
			'38CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1',
		p: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
			'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7',
		q: '3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
			'C98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED',
		x: 'E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043A' +
			'A27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148',
		y: 'F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9B' +
			'E18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F',
	}),
};

// Kazakh curve parameter OIDs. Only mappings verified against real keys.
export const CURVE_BY_OID = {
	// Checked: a real NCA key's public point lies on tc26 paramSet A.
	'1.2.398.3.10.1.1.2.2.1': CURVES['tc26-512-A'],
};

/**
 * Returns a mod m in the range [0, m).
 *
 * @param {bigint} a Value.
 * @param {bigint} m Modulus.
 * @returns {bigint}
 */
function mod(a, m) {
	const r = a % m;
	return r < 0n ? r + m : r;
}

/**
 * Modular inverse by the extended Euclidean algorithm.
 *
 * @param {bigint} a Value, coprime with m.
 * @param {bigint} m Modulus.
 * @returns {bigint}
 */
function inv(a, m) {
	let [r0, r1] = [mod(a, m), m];
	let [s0, s1] = [1n, 0n];
	while (r1 !== 0n) {
		const q = r0 / r1;
		[r0, r1] = [r1, r0 - q * r1];
		[s0, s1] = [s1, s0 - q * s1];
	}
	if (r0 !== 1n) {
		throw new Error('Value is not invertible');
	}
	return mod(s0, m);
}

/**
 * Adds two affine points. Null is the point at infinity.
 *
 * @param {Array<bigint>|null} P First point.
 * @param {Array<bigint>|null} Q Second point.
 * @param {object} c Curve.
 * @returns {Array<bigint>|null}
 */
export function add(P, Q, c) {
	if (!P) {
		return Q;
	}
	if (!Q) {
		return P;
	}
	const [x1, y1] = P;
	const [x2, y2] = Q;
	let l;
	if (x1 === x2) {
		if (mod(y1 + y2, c.p) === 0n) {
			return null;
		}
		l = mod((3n * x1 * x1 + c.a) * inv(2n * y1, c.p), c.p);
	} else {
		l = mod((y2 - y1) * inv(x2 - x1, c.p), c.p);
	}
	const x3 = mod(l * l - x1 - x2, c.p);
	return [x3, mod(l * (x1 - x3) - y1, c.p)];
}

/**
 * Multiplies a point by a scalar with double-and-add.
 *
 * @param {bigint} k Non-negative scalar.
 * @param {Array<bigint>|null} P Point.
 * @param {object} c Curve.
 * @returns {Array<bigint>|null}
 */
export function multiply(k, P, c) {
	let R = null;
	let A = P;
	while (k > 0n) {
		if (k & 1n) {
			R = add(R, A, c);
		}
		A = add(A, A, c);
		k >>= 1n;
	}
	return R;
}

/**
 * Checks y^2 = x^3 + ax + b mod p.
 *
 * @param {Array<bigint>} P Point.
 * @param {object} c Curve.
 * @returns {boolean}
 */
export function isOnCurve(P, c) {
	const [x, y] = P;
	if (x < 0n || x >= c.p || y < 0n || y >= c.p) {
		return false;
	}
	return mod(y * y - (x * x * x + c.a * x + c.b), c.p) === 0n;
}

/**
 * Computes the public key Q = dP.
 *
 * @param {object} c Curve.
 * @param {bigint} d Private key, 0 < d < q.
 * @returns {Array<bigint>}
 */
export function publicKey(c, d) {
	if (d <= 0n || d >= c.q) {
		throw new Error('Private key out of range');
	}
	return multiply(d, c.G, c);
}

/**
 * Reduces the hash integer alpha to e as in section 6.1 step 2.
 *
 * @param {bigint} alpha Hash as an integer.
 * @param {bigint} q Subgroup order.
 * @returns {bigint}
 */
function reduceHash(alpha, q) {
	const e = mod(alpha, q);
	return e === 0n ? 1n : e;
}

/**
 * Returns a uniform random scalar in [1, q).
 *
 * @param {bigint} q Subgroup order.
 * @returns {bigint}
 */
function randomScalar(q) {
	const size = Math.ceil(q.toString(2).length / 8);
	for (;;) {
		const k = BigInt('0x' + randomBytes(size).toString('hex')) >> BigInt(size * 8 - q.toString(2).length);
		if (k > 0n && k < q) {
			return k;
		}
	}
}

/**
 * Signs a hash integer, GOST R 34.10-2012 section 6.1.
 *
 * @param {object} c Curve.
 * @param {bigint} d Private key.
 * @param {bigint} alpha Hash as an integer.
 * @param {bigint} [k] Nonce, only for tests. Random when omitted.
 * @returns {{r: bigint, s: bigint}}
 */
export function sign(c, d, alpha, k) {
	const e = reduceHash(alpha, c.q);
	for (;;) {
		const nonce = k ?? randomScalar(c.q);
		const C = multiply(nonce, c.G, c);
		const r = mod(C[0], c.q);
		const s = mod(r * d + nonce * e, c.q);
		if (r !== 0n && s !== 0n) {
			return { r, s };
		}
		if (k !== undefined) {
			throw new Error('Given nonce produces a zero r or s');
		}
	}
}

/**
 * Verifies a signature, GOST R 34.10-2012 section 6.2.
 *
 * @param {object} c Curve.
 * @param {Array<bigint>} Q Public key.
 * @param {bigint} alpha Hash as an integer.
 * @param {bigint} r Signature part r.
 * @param {bigint} s Signature part s.
 * @returns {boolean}
 */
export function verify(c, Q, alpha, r, s) {
	if (r <= 0n || r >= c.q || s <= 0n || s >= c.q) {
		return false;
	}
	if (!isOnCurve(Q, c)) {
		return false;
	}
	const v = inv(reduceHash(alpha, c.q), c.q);
	const z1 = mod(s * v, c.q);
	const z2 = mod(-r * v, c.q);
	const C = add(multiply(z1, c.G, c), multiply(z2, Q, c), c);
	return C !== null && mod(C[0], c.q) === r;
}
