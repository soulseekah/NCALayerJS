// RFC 3161 timestamp client for the NCA RK timestamp authority.
//
// The TSA has two profiles: RSA (SHA-256 imprint, token signed with
// sha256WithRSA), used by NIT for its own files, and GOST 2015 (Streebog
// imprint, token signed with GOST 2015 512), which NCALayer basics.sign
// requests. Both are verified here.

import { createHash, randomBytes, X509Certificate, verify as cryptoVerify } from 'node:crypto';
import { parseBer, octets, oid as readOid, toBigInt, parseTime, TAG } from './ber.mjs';
import { seq, int, oid, octetString, boolean, algorithm } from './der.mjs';
import { parseCertificate } from './x509.mjs';
import { streebog512 } from './streebog.mjs';
import { verify as gostVerify } from './gost3410.mjs';
import { OID as KALKAN, hashToInteger, decodeSignature, publicKeyFromCertificate } from './kalkan.mjs';

export const DEFAULT_URL = 'http://tsp.pki.gov.kz/';

export const OID = {
	SIGNED_DATA: '1.2.840.113549.1.7.2',
	TST_INFO: '1.2.840.113549.1.9.16.1.4',
	CONTENT_TYPE: '1.2.840.113549.1.9.3',
	MESSAGE_DIGEST: '1.2.840.113549.1.9.4',
	SHA256: '2.16.840.1.101.3.4.2.1',
};

// TSA profiles. Policies found by asking the NCA TSA: the RSA one is its
// default, the GOST one is the only GOST policy it accepts.
export const PROFILE = {
	RSA: { policy: '1.2.398.3.3.2.6.2', hashAlgorithm: OID.SHA256 },
	GOST: { policy: '1.2.398.3.3.2.6.4', hashAlgorithm: KALKAN.STREEBOG_512 },
};

// Digest OIDs allowed for imprints and token SignerInfos.
const DIGESTS = {
	[OID.SHA256]: (data) => createHash('sha256').update(data).digest(),
	'2.16.840.1.101.3.4.2.2': (data) => createHash('sha384').update(data).digest(),
	'2.16.840.1.101.3.4.2.3': (data) => createHash('sha512').update(data).digest(),
	[KALKAN.STREEBOG_512]: (data) => streebog512(data),
};

// RSA signature OIDs allowed in token SignerInfos, with node hash names.
const RSA_SIGNATURES = new Set([
	'1.2.840.113549.1.1.1',
	'1.2.840.113549.1.1.11',
	'1.2.840.113549.1.1.12',
	'1.2.840.113549.1.1.13',
]);
const NODE_HASH = {
	[OID.SHA256]: 'sha256',
	'2.16.840.1.101.3.4.2.2': 'sha384',
	'2.16.840.1.101.3.4.2.3': 'sha512',
};

/**
 * Hashes data with a supported digest OID.
 *
 * @param {string} digestOid Digest OID.
 * @param {Uint8Array} data Data.
 * @returns {Buffer}
 */
export function hashWith(digestOid, data) {
	const fn = DIGESTS[digestOid];
	if (!fn) {
		throw new Error(`TSP: unsupported digest ${digestOid}`);
	}
	return fn(data);
}

/**
 * Builds a TimeStampReq, RFC 3161 section 2.4.1.
 *
 * @param {Buffer} hash Hash of the data to timestamp.
 * @param {object} [options]
 * @param {string} [options.hashAlgorithm] Digest OID of the hash.
 * @param {string|null} [options.policy] Requested policy OID, null for none.
 * @param {bigint} [options.nonce] Nonce, random 64 bits when omitted.
 * @returns {{der: Buffer, nonce: bigint}}
 */
export function buildRequest(hash, { hashAlgorithm = PROFILE.RSA.hashAlgorithm, policy = PROFILE.RSA.policy, nonce } = {}) {
	if (!DIGESTS[hashAlgorithm] || hash.length !== hashWith(hashAlgorithm, Buffer.alloc(0)).length) {
		throw new Error('TSP: hash does not match the hash algorithm');
	}
	const n = nonce ?? toBigInt(randomBytes(8));
	const der = seq(
		int(1),
		seq(algorithm(hashAlgorithm), octetString(hash)),
		policy ? oid(policy) : null,
		int(n),
		boolean(true),
	);
	return { der, nonce: n };
}

/**
 * Checks the token SignerInfo signature with RSA or GOST.
 *
 * @param {object} cert Parsed TSA certificate.
 * @param {string} sigAlg Signature algorithm OID.
 * @param {string} digestAlg Digest algorithm OID.
 * @param {Buffer} attrs Signed attributes encoded as a SET.
 * @param {Buffer} signature Signature value.
 * @returns {boolean}
 */
function checkTokenSignature(cert, sigAlg, digestAlg, attrs, signature) {
	if (sigAlg === KALKAN.GOST2015_512_SIGN) {
		if (digestAlg !== KALKAN.STREEBOG_512) {
			return false;
		}
		const { curve, Q } = publicKeyFromCertificate(cert);
		const { r, s } = decodeSignature(signature);
		return gostVerify(curve, Q, hashToInteger(streebog512(attrs)), r, s);
	}
	if (!RSA_SIGNATURES.has(sigAlg) || !NODE_HASH[digestAlg]) {
		return false;
	}
	return cryptoVerify(NODE_HASH[digestAlg], attrs, new X509Certificate(cert.der).publicKey, signature);
}

/**
 * Verifies a timestamp token. This checks the token signature and its
 * signed attributes, not the TSA certificate chain or revocation.
 *
 * @param {Buffer} token ContentInfo with the token SignedData.
 * @param {object} [expected] What the token must cover; omit to skip.
 * @param {Buffer} [expected.hash] Imprint hash, compared as is.
 * @param {Buffer} [expected.data] Data, hashed with the token's imprint algorithm.
 * @returns {{valid: boolean, reason: string|null, time: Date|null, policy: string|null,
 *   hashAlgorithm: string|null, serial: bigint|null, nonce: bigint|null, certificate: object|null}}
 */
export function verifyToken(token, { hash, data } = {}) {
	const result = { valid: false, reason: null, time: null, policy: null, hashAlgorithm: null, serial: null, nonce: null, certificate: null };
	const ci = parseBer(token);
	if (readOid(ci.children[0]) !== OID.SIGNED_DATA) {
		result.reason = 'token is not a SignedData';
		return result;
	}
	const sd = ci.children[1].children[0];
	const encap = sd.children[2];
	if (readOid(encap.children[0]) !== OID.TST_INFO || !encap.children[1]) {
		result.reason = 'token does not contain a TSTInfo';
		return result;
	}

	// TSTInfo: version, policy, messageImprint, serialNumber, genTime,
	// then optional accuracy, ordering, nonce, tsa and extensions.
	const tstBytes = octets(encap.children[1].children[0]);
	const tst = parseBer(tstBytes).children;
	result.policy = readOid(tst[1]);
	result.serial = toBigInt(tst[3].value);
	result.time = parseTime(tst[4]);
	const nonceNode = tst.slice(5).find((n) => n.tag === TAG.INTEGER);
	result.nonce = nonceNode ? toBigInt(nonceNode.value) : null;
	const imprint = tst[2];
	result.hashAlgorithm = readOid(imprint.children[0].children[0]);
	if (!DIGESTS[result.hashAlgorithm]) {
		result.reason = `unsupported imprint algorithm ${result.hashAlgorithm}`;
		return result;
	}
	const want = hash ?? (data ? hashWith(result.hashAlgorithm, data) : null);
	if (want && !imprint.children[1].value.equals(want)) {
		result.reason = 'token covers different data';
		return result;
	}

	const si = sd.children[sd.children.length - 1].children[0];
	const sid = si.children[1];
	const certNode = sd.children.find((n) => n.tag === 0xa0);
	const certs = certNode ? certNode.children.map((n) => parseCertificate(n.raw)) : [];
	const cert = sid.tag === TAG.SEQUENCE
		? certs.find((c) => c.issuerRaw.equals(sid.children[0].raw) && c.serialRaw.equals(sid.children[1].raw))
		: null;
	if (!cert) {
		result.reason = 'TSA certificate not found in the token';
		return result;
	}
	result.certificate = cert;

	const digestAlg = readOid(si.children[2].children[0]);
	const signedAttrs = si.children[3];
	if (!DIGESTS[digestAlg] || signedAttrs.tag !== 0xa0) {
		result.reason = 'unsupported token digest or missing signed attributes';
		return result;
	}
	const attrs = new Map(signedAttrs.children.map((a) => [readOid(a.children[0]), a.children[1].children[0]]));
	const md = attrs.get(OID.MESSAGE_DIGEST);
	if (!md || !md.value.equals(hashWith(digestAlg, tstBytes))) {
		result.reason = 'token message digest mismatch';
		return result;
	}
	const ct = attrs.get(OID.CONTENT_TYPE);
	if (!ct || readOid(ct) !== OID.TST_INFO) {
		result.reason = 'token content type attribute mismatch';
		return result;
	}

	const der = Buffer.from(signedAttrs.raw);
	der[0] = TAG.SET;
	const sigAlg = readOid(si.children[4].children[0]);
	if (!checkTokenSignature(cert, sigAlg, digestAlg, der, si.children[5].value)) {
		result.reason = `token signature is not valid (${sigAlg})`;
		return result;
	}
	result.valid = true;
	return result;
}

/**
 * Requests a timestamp token and checks the reply.
 *
 * @param {Buffer} hash Hash of the data to timestamp.
 * @param {object} [options]
 * @param {{policy: string, hashAlgorithm: string}} [options.profile] PROFILE.RSA or PROFILE.GOST.
 * @param {string} [options.url] TSA URL.
 * @param {Function} [options.fetch] fetch implementation, for tests.
 * @returns {Promise<{token: Buffer, info: object}>} Token ContentInfo and verifyToken() result.
 */
export async function requestTimestamp(hash, { profile = PROFILE.RSA, url = DEFAULT_URL, fetch = globalThis.fetch } = {}) {
	const { der, nonce } = buildRequest(hash, profile);
	const res = await fetch(url, {
		method: 'POST',
		headers: { 'Content-Type': 'application/timestamp-query' },
		body: der,
	});
	if (!res.ok) {
		throw new Error(`TSP: HTTP ${res.status}`);
	}
	const resp = parseBer(Buffer.from(await res.arrayBuffer()));
	// PKIStatus: 0 granted, 1 granted with modifications.
	const status = Number(toBigInt(resp.children[0].children[0].value));
	if (status > 1 || !resp.children[1]) {
		throw new Error(`TSP: request rejected with status ${status}`);
	}
	const token = Buffer.from(resp.children[1].raw);
	const info = verifyToken(token, { hash });
	if (!info.valid) {
		throw new Error(`TSP: ${info.reason}`);
	}
	if (info.nonce !== nonce) {
		throw new Error('TSP: nonce mismatch');
	}
	if (info.policy !== profile.policy) {
		throw new Error(`TSP: unexpected policy ${info.policy}`);
	}
	return { token, info };
}
