// CMS SignedData (RFC 5652) with Kazakh GOST 2015 512 signatures, laid out
// the same way Kalkan does it.

import { createHash } from 'node:crypto';
import { parseBer, octets, oid as readOid, parseTime, TAG } from './ber.mjs';
import { tlv, seq, setOf, int, oid, octetString, time, context, algorithm } from './der.mjs';
import { streebog512 } from './streebog.mjs';
import { sign, verify } from './gost3410.mjs';
import { parseCertificate } from './x509.mjs';
import { OID as KALKAN, hashToInteger, encodeSignature, decodeSignature, publicKeyFromCertificate } from './kalkan.mjs';
import { requestTimestamp, verifyToken, hashWith, PROFILE } from './tsp.mjs';

export const OID = {
	DATA: '1.2.840.113549.1.7.1',
	SIGNED_DATA: '1.2.840.113549.1.7.2',
	CONTENT_TYPE: '1.2.840.113549.1.9.3',
	MESSAGE_DIGEST: '1.2.840.113549.1.9.4',
	SIGNING_TIME: '1.2.840.113549.1.9.5',
	SIGNING_CERTIFICATE_V2: '1.2.840.113549.1.9.16.2.47',
	TIMESTAMP_TOKEN: '1.2.840.113549.1.9.16.2.14',
};

/**
 * Encodes one Attribute with a single value.
 *
 * @param {string} type Attribute OID.
 * @param {Buffer} value Encoded value.
 * @returns {Buffer}
 */
function attribute(type, value) {
	return seq(oid(type), setOf(value));
}

/**
 * Creates a CMS SignedData.
 *
 * @param {object} options
 * @param {Buffer} options.content Data to sign.
 * @param {{curve: object, d: bigint, certificate: object}} options.signer Result of loadSigner().
 * @param {boolean} [options.detached] Leave the content out of the result.
 * @param {Date} [options.signingTime] Defaults to now.
 * @returns {Buffer} DER encoded ContentInfo.
 */
export function signCms({ content, signer, detached = false, signingTime = new Date() }) {
	const cert = signer.certificate;
	// ESSCertIDv2 with the default SHA-256 hash and no issuerSerial.
	const essCertId = seq(octetString(createHash('sha256').update(cert.der).digest()));
	const attrs = setOf(
		attribute(OID.CONTENT_TYPE, oid(OID.DATA)),
		attribute(OID.SIGNING_TIME, time(signingTime)),
		attribute(OID.SIGNING_CERTIFICATE_V2, seq(seq(essCertId))),
		attribute(OID.MESSAGE_DIGEST, octetString(streebog512(content))),
	);
	// RFC 5652 section 5.4: sign the attributes as a SET, store them as [0].
	const alpha = hashToInteger(streebog512(attrs));
	const signature = encodeSignature(sign(signer.curve, signer.d, alpha), signer.curve);
	const signedAttrs = Buffer.from(attrs);
	signedAttrs[0] = 0xa0;

	const signerInfo = seq(
		int(1),
		seq(cert.issuerRaw, cert.serialRaw),
		algorithm(KALKAN.STREEBOG_512),
		signedAttrs,
		algorithm(KALKAN.GOST2015_512_SIGN),
		octetString(signature),
	);
	const encap = detached
		? seq(oid(OID.DATA))
		: seq(oid(OID.DATA), context(0, octetString(content)));
	const signedData = seq(
		int(1),
		setOf(algorithm(KALKAN.STREEBOG_512)),
		encap,
		context(0, cert.der),
		setOf(signerInfo),
	);
	return seq(oid(OID.SIGNED_DATA), context(0, signedData));
}

/**
 * Verifies one SignerInfo.
 *
 * @param {object} si Parsed SignerInfo.
 * @param {Array<object>} certificates Parsed certificates from the SignedData.
 * @param {Buffer} content Signed content.
 * @param {string} contentType eContentType OID.
 * @returns {{valid: boolean, reason: string|null, certificate: object|null, signingTime: Date|null, timestamp: object|null}}
 *   timestamp is only checked for valid signatures; see verifyTimestampAttribute().
 */
function verifySignerInfo(si, certificates, content, contentType) {
	const result = { valid: false, reason: null, certificate: null, signingTime: null, timestamp: null };
	const sid = si.children[1];
	if (sid.tag !== TAG.SEQUENCE) {
		result.reason = 'subjectKeyIdentifier signer IDs are not supported';
		return result;
	}
	const cert = certificates.find((c) => c.issuerRaw.equals(sid.children[0].raw) && c.serialRaw.equals(sid.children[1].raw));
	if (!cert) {
		result.reason = 'signer certificate not found';
		return result;
	}
	result.certificate = cert;

	const digestAlg = readOid(si.children[2].children[0]);
	const signedAttrs = si.children[3];
	if (digestAlg !== KALKAN.STREEBOG_512 || signedAttrs.tag !== 0xa0) {
		result.reason = `unsupported digest ${digestAlg} or missing signed attributes`;
		return result;
	}
	const sigAlg = readOid(si.children[4].children[0]);
	if (sigAlg !== KALKAN.GOST2015_512_SIGN) {
		result.reason = `unsupported signature algorithm ${sigAlg}`;
		return result;
	}

	const attrs = new Map(signedAttrs.children.map((a) => [readOid(a.children[0]), a.children[1].children[0]]));
	const md = attrs.get(OID.MESSAGE_DIGEST);
	if (!md || !md.value.equals(streebog512(content))) {
		result.reason = 'message digest mismatch';
		return result;
	}
	const ct = attrs.get(OID.CONTENT_TYPE);
	if (!ct || readOid(ct) !== contentType) {
		result.reason = 'content type attribute mismatch';
		return result;
	}
	const scv2 = attrs.get(OID.SIGNING_CERTIFICATE_V2);
	if (scv2) {
		const essCertId = scv2.children[0].children[0];
		// Only the default SHA-256 hash, which Kalkan uses, is supported.
		if (essCertId.children[0].tag !== TAG.OCTET_STRING) {
			result.reason = 'unsupported signingCertificateV2 hash algorithm';
			return result;
		}
		if (!essCertId.children[0].value.equals(createHash('sha256').update(cert.der).digest())) {
			result.reason = 'signingCertificateV2 does not match the signer certificate';
			return result;
		}
	}
	const st = attrs.get(OID.SIGNING_TIME);
	result.signingTime = st ? parseTime(st) : null;

	const der = Buffer.from(signedAttrs.raw);
	der[0] = TAG.SET;
	const { curve, Q } = publicKeyFromCertificate(cert);
	const { r, s } = decodeSignature(si.children[5].value);
	if (!verify(curve, Q, hashToInteger(streebog512(der)), r, s)) {
		result.reason = 'signature is not valid';
		return result;
	}
	result.valid = true;
	result.timestamp = verifyTimestampAttribute(si);
	return result;
}

/**
 * Verifies the timestamp token in the unsigned attributes, if any. As in
 * CAdES, the token must cover the hash of the signature value, made with
 * the token's own imprint algorithm (SHA-256 or Streebog-512).
 *
 * @param {object} si Parsed SignerInfo.
 * @returns {{valid: boolean, reason: string|null, time: Date|null}|null} Null when there is no token.
 */
function verifyTimestampAttribute(si) {
	const unsigned = si.children.find((n) => n.tag === 0xa1);
	const attr = unsigned && unsigned.children.find((a) => readOid(a.children[0]) === OID.TIMESTAMP_TOKEN);
	if (!attr) {
		return null;
	}
	const { valid, reason, time: when } = verifyToken(attr.children[1].children[0].raw, { data: si.children[5].value });
	return { valid, reason, time: when };
}

/**
 * Adds a timestamp token to the first SignerInfo of a SignedData.
 *
 * @param {Buffer} der ContentInfo from signCms().
 * @param {Buffer} token Timestamp token ContentInfo.
 * @returns {Buffer} New ContentInfo.
 */
export function addTimestamp(der, token) {
	const ci = parseBer(der);
	const sd = ci.children[1].children[0];
	const signerInfos = sd.children[sd.children.length - 1];
	const [si, ...others] = signerInfos.children;
	if (si.children.some((n) => n.tag === 0xa1)) {
		throw new Error('CMS: signer already has unsigned attributes');
	}
	// Lengths change, so every enclosing element is encoded again.
	const newSi = tlv(TAG.SEQUENCE, Buffer.concat([...si.children.map((n) => n.raw), context(1, attribute(OID.TIMESTAMP_TOKEN, token))]));
	const newSignerInfos = setOf(newSi, ...others.map((n) => n.raw));
	const newSd = tlv(TAG.SEQUENCE, Buffer.concat([...sd.children.slice(0, -1).map((n) => n.raw), newSignerInfos]));
	return seq(ci.children[0].raw, context(0, newSd));
}

/**
 * Requests a timestamp for the first signature and adds it, the way
 * NCALayer basics.sign does when a tsaProfile is given.
 *
 * @param {Buffer} der ContentInfo from signCms().
 * @param {object} [options] Passed to requestTimestamp() (url, fetch).
 * @param {object} [options.profile] TSA profile, PROFILE.GOST like NCALayer by default.
 * @returns {Promise<Buffer>} New ContentInfo.
 */
export async function timestampCms(der, { profile = PROFILE.GOST, ...options } = {}) {
	const sd = parseBer(der).children[1].children[0];
	const si = sd.children[sd.children.length - 1].children[0];
	const imprint = hashWith(profile.hashAlgorithm, si.children[5].value);
	const { token } = await requestTimestamp(imprint, { profile, ...options });
	return addTimestamp(der, token);
}

/**
 * Verifies the signatures in a CMS SignedData. This checks the math and
 * the signed attributes only, not the certificate chain or revocation.
 *
 * @param {Buffer} der ContentInfo.
 * @param {object} [options]
 * @param {Buffer} [options.content] Content for detached signatures.
 * @returns {{content: Buffer, signers: Array<{valid: boolean, reason: string|null, certificate: object|null,
 *   signingTime: Date|null, timestamp: {valid: boolean, reason: string|null, time: Date|null}|null}>}}
 */
export function verifyCms(der, { content } = {}) {
	const ci = parseBer(der);
	if (readOid(ci.children[0]) !== OID.SIGNED_DATA) {
		throw new Error('CMS: not a SignedData');
	}
	const sd = ci.children[1].children[0];
	const encap = sd.children[2];
	const contentType = readOid(encap.children[0]);
	const embedded = encap.children[1] ? octets(encap.children[1].children[0]) : null;
	if (embedded && content && !embedded.equals(content)) {
		throw new Error('CMS: given content differs from the embedded content');
	}
	const data = embedded ?? content;
	if (!data) {
		throw new Error('CMS: detached signature, content is required');
	}
	const certNode = sd.children.find((n) => n.tag === 0xa0);
	const certificates = certNode ? certNode.children.map((n) => parseCertificate(n.raw)) : [];
	const signerInfos = sd.children[sd.children.length - 1];
	if (signerInfos.tag !== TAG.SET) {
		throw new Error('CMS: signerInfos not found');
	}
	const signers = signerInfos.children.map((si) => verifySignerInfo(si, certificates, data, contentType));
	return { content: Buffer.from(data), signers };
}
