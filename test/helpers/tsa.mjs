// In-process fake RFC 3161 timestamp authority for tests. It signs tokens
// with a throwaway RSA key, or with a throwaway GOST key in GOST mode.

import { createHash, generateKeyPairSync, sign as rsaSign } from 'node:crypto';
import { seq, setOf, int, oid, tlv, octetString, time, generalizedTime, context, algorithm } from '../../src/der.mjs';
import { parseBer, oid as readOid, toBigInt, TAG } from '../../src/ber.mjs';
import { parseCertificate } from '../../src/x509.mjs';
import { streebog512 } from '../../src/streebog.mjs';
import { sign as gostSign } from '../../src/gost3410.mjs';
import { OID as KALKAN, encodeSignature, hashToInteger } from '../../src/kalkan.mjs';
import { PROFILE, OID } from '../../src/tsp.mjs';
import { makeSigner } from './gost.mjs';

const SHA256_RSA = '1.2.840.113549.1.1.11';
const RSA = '1.2.840.113549.1.1.1';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

const name = seq(setOf(seq(oid('2.5.4.3'), tlv(TAG.UTF8_STRING, Buffer.from('Fake TSA', 'utf8')))));
const tbs = seq(
	context(0, int(2)),
	int(0x7a5n),
	algorithm(SHA256_RSA),
	name,
	seq(time(new Date('2026-01-01T00:00:00Z')), time(new Date('2027-01-01T00:00:00Z'))),
	name,
	publicKey.export({ type: 'spki', format: 'der' }),
);
const rsaCertDer = seq(tbs, algorithm(SHA256_RSA), tlv(TAG.BIT_STRING, Buffer.concat([Buffer.from([0]), rsaSign('sha256', tbs, privateKey)])));
const rsaCert = parseCertificate(rsaCertDer);
const gostTsa = makeSigner({ cn: 'Fake GOST TSA' });

/**
 * Builds a timestamp token for a message imprint.
 *
 * @param {Buffer} imprintRaw Encoded MessageImprint.
 * @param {bigint|null} nonce Nonce to echo, or null.
 * @param {object} [options]
 * @param {string} [options.policy] Policy OID.
 * @param {boolean} [options.gost] Sign the token with GOST instead of RSA.
 * @param {Date} [options.when] Timestamp time.
 * @returns {Buffer} ContentInfo.
 */
export function makeToken(imprintRaw, nonce, { policy = PROFILE.RSA.policy, gost = false, when = new Date() } = {}) {
	const tst = seq(int(1), oid(policy), imprintRaw, int(0x1234n), generalizedTime(when), nonce === null ? null : int(nonce));
	const digestOid = gost ? KALKAN.STREEBOG_512 : OID.SHA256;
	const digest = gost ? streebog512(tst) : createHash('sha256').update(tst).digest();
	const attrs = setOf(
		seq(oid(OID.CONTENT_TYPE), setOf(oid(OID.TST_INFO))),
		seq(oid(OID.MESSAGE_DIGEST), setOf(octetString(digest))),
	);
	const signature = gost
		? encodeSignature(gostSign(gostTsa.curve, gostTsa.d, hashToInteger(streebog512(attrs))), gostTsa.curve)
		: rsaSign('sha256', attrs, privateKey);
	const cert = gost ? gostTsa.certificate : rsaCert;
	const signedAttrs = Buffer.from(attrs);
	signedAttrs[0] = 0xa0;
	const si = seq(int(1), seq(cert.issuerRaw, cert.serialRaw), algorithm(digestOid), signedAttrs,
		algorithm(gost ? KALKAN.GOST2015_512_SIGN : RSA), octetString(signature));
	const sd = seq(int(3), setOf(algorithm(digestOid)), seq(oid(OID.TST_INFO), context(0, octetString(tst))), context(0, cert.der), setOf(si));
	return seq(oid(OID.SIGNED_DATA), context(0, sd));
}

/**
 * Answers a TimeStampReq. Tokens are GOST-signed when the request asks
 * for the GOST policy, like the real NCA TSA.
 *
 * @param {Buffer} request DER TimeStampReq.
 * @param {object} [options]
 * @param {number} [options.status] PKIStatus to return; 2 means rejection.
 * @param {bigint} [options.nonce] Nonce to return instead of the requested one.
 * @param {Buffer} [options.hash] Hash to put in the token instead of the requested one.
 * @param {string} [options.policy] Policy OID to return instead of the requested one.
 * @returns {Buffer} DER TimeStampResp.
 */
export function respond(request, { status = 0, nonce, hash, policy } = {}) {
	if (status > 1) {
		return seq(seq(int(status)));
	}
	const req = parseBer(request).children;
	const imprintAlg = req[1].children[0];
	const imprint = hash ? seq(imprintAlg.raw, octetString(hash)) : req[1].raw;
	const reqPolicy = req.find((n) => n.tag === TAG.OID);
	const echoPolicy = policy ?? (reqPolicy ? readOid(reqPolicy) : PROFILE.RSA.policy);
	const reqNonce = req.find((n, i) => i > 1 && n.tag === TAG.INTEGER);
	const echo = nonce ?? (reqNonce ? toBigInt(reqNonce.value) : null);
	return seq(seq(int(status)), makeToken(imprint, echo, { policy: echoPolicy, gost: echoPolicy === PROFILE.GOST.policy }));
}

/**
 * Returns a fetch() stand-in that answers with this TSA.
 *
 * @param {object} [options] Passed to respond(). httpStatus sets an HTTP error.
 * @returns {Function}
 */
export function fakeFetch(options = {}) {
	return async (url, init) => {
		if (options.httpStatus) {
			return { ok: false, status: options.httpStatus };
		}
		const body = respond(Buffer.from(init.body), options);
		return { ok: true, status: 200, arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.length) };
	};
}
