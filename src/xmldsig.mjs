// Enveloped XML signatures with Kazakh GOST 2015 512, laid out the way
// Kalkan does for whole documents:
//
// - SignedInfo canonicalization: inclusive c14n 1.0 without comments
// - one Reference URI="" with enveloped-signature and c14n WithComments
// - ds:Signature appended as the last child of the root element
// - KeyInfo with the signer certificate only
//
// Signature value and digest use the same encodings as Kalkan CMS
// (r|s little-endian, hash in memory order), confirmed by the NCA RK
// signature verification service.

import { SignedXml } from 'xml-crypto';
import { DOMParser } from '@xmldom/xmldom';
import { streebog512 } from './streebog.mjs';
import { sign, verify } from './gost3410.mjs';
import { parseCertificate, pemToDer } from './x509.mjs';
import { hashToInteger, encodeSignature, decodeSignature, publicKeyFromCertificate } from './kalkan.mjs';

export const URI = {
	SIGNATURE: 'urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512',
	DIGEST: 'urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512',
	C14N: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
	C14N_WITH_COMMENTS: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
	ENVELOPED: 'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
	DSIG_NS: 'http://www.w3.org/2000/09/xmldsig#',
};

/**
 * Streebog-512 digest for xml-crypto.
 */
class StreebogDigest {
	/**
	 * @param {string} xml Canonical XML.
	 * @returns {string} Base64 hash.
	 */
	getHash(xml) {
		return streebog512(Buffer.from(xml, 'utf8')).toString('base64');
	}

	/**
	 * @returns {string}
	 */
	getAlgorithmName() {
		return URI.DIGEST;
	}
}

/**
 * GOST 2015 512 signature for xml-crypto. The "key" for signing is a
 * signer from loadSigner(), for verifying a PEM certificate.
 */
class GostSignature {
	/**
	 * @param {string|Buffer} signedInfo Canonical SignedInfo.
	 * @param {{curve: object, d: bigint}} signer Signer.
	 * @param {Function} [callback] Optional error-first callback.
	 * @returns {string|undefined} Base64 signature value.
	 */
	getSignature(signedInfo, signer, callback) {
		const alpha = hashToInteger(streebog512(Buffer.from(signedInfo)));
		const value = encodeSignature(sign(signer.curve, signer.d, alpha), signer.curve).toString('base64');
		if (callback) {
			callback(null, value);
			return undefined;
		}
		return value;
	}

	/**
	 * @param {string} material Canonical SignedInfo.
	 * @param {string} certPem Signer certificate, PEM.
	 * @param {string} signatureValue Base64 signature value.
	 * @returns {boolean}
	 */
	verifySignature(material, certPem, signatureValue) {
		const { curve, Q } = publicKeyFromCertificate(parseCertificate(pemToDer(Buffer.from(certPem))));
		const { r, s } = decodeSignature(Buffer.from(signatureValue, 'base64'));
		return verify(curve, Q, hashToInteger(streebog512(Buffer.from(material, 'utf8'))), r, s);
	}

	/**
	 * @returns {string}
	 */
	getAlgorithmName() {
		return URI.SIGNATURE;
	}
}

/**
 * Creates a SignedXml instance with the Kalkan algorithms registered.
 *
 * @param {object} options SignedXml options.
 * @returns {SignedXml}
 */
function createSignedXml(options) {
	const sig = new SignedXml(options);
	sig.HashAlgorithms[URI.DIGEST] = StreebogDigest;
	sig.SignatureAlgorithms[URI.SIGNATURE] = GostSignature;
	return sig;
}

/**
 * Wraps DER certificate bytes as PEM.
 *
 * @param {Buffer} der Certificate.
 * @returns {string}
 */
function toPem(der) {
	const lines = der.toString('base64').match(/.{1,64}/g).join('\n');
	return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

/**
 * Signs a whole XML document with an enveloped signature.
 *
 * @param {string} xml Document.
 * @param {{curve: object, d: bigint, certificate: object}} signer Result of loadSigner().
 * @returns {string} Signed document.
 */
export function signXml(xml, signer) {
	const certBase64 = signer.certificate.der.toString('base64');
	const sig = createSignedXml({
		privateKey: signer,
		signatureAlgorithm: URI.SIGNATURE,
		canonicalizationAlgorithm: URI.C14N,
		getKeyInfoContent: ({ prefix }) => {
			const p = prefix ? `${prefix}:` : '';
			return `<${p}X509Data><${p}X509Certificate>${certBase64}</${p}X509Certificate></${p}X509Data>`;
		},
	});
	sig.addReference({
		xpath: '/*',
		isEmptyUri: true,
		transforms: [URI.ENVELOPED, URI.C14N_WITH_COMMENTS],
		digestAlgorithm: URI.DIGEST,
	});
	sig.computeSignature(xml, { prefix: 'ds', location: { reference: '/*', action: 'append' } });
	return sig.getSignedXml();
}

/**
 * Verifies a whole-document enveloped signature made by signXml() or
 * Kalkan. This checks the math only, not the certificate chain.
 *
 * Exactly one signature with exactly one Reference URI="" is accepted,
 * so a valid signature can not be moved around the document (signature
 * wrapping).
 *
 * @param {string} xml Signed document.
 * @returns {{valid: boolean, reason: string|null, certificate: object|null}}
 */
export function verifyXml(xml) {
	const result = { valid: false, reason: null, certificate: null };
	const doc = new DOMParser().parseFromString(xml, 'text/xml');
	const signatures = doc.getElementsByTagNameNS(URI.DSIG_NS, 'Signature');
	if (signatures.length !== 1) {
		result.reason = `expected one signature, found ${signatures.length}`;
		return result;
	}
	const node = signatures[0];
	if (node.parentNode !== doc.documentElement) {
		result.reason = 'signature is not a child of the root element';
		return result;
	}
	const certs = node.getElementsByTagNameNS(URI.DSIG_NS, 'X509Certificate');
	if (certs.length !== 1) {
		result.reason = 'expected one X509Certificate in KeyInfo';
		return result;
	}
	const der = Buffer.from(certs[0].textContent.replace(/\s+/g, ''), 'base64');
	result.certificate = parseCertificate(der);

	// Checked on the DOM: xml-crypto loads URI="" and a missing URI alike.
	const refs = node.getElementsByTagNameNS(URI.DSIG_NS, 'Reference');
	if (refs.length !== 1 || !refs[0].hasAttribute('URI') || refs[0].getAttribute('URI') !== '') {
		result.reason = 'expected one Reference with URI=""';
		return result;
	}
	const sig = createSignedXml({ getCertFromKeyInfo: () => toPem(der) });
	sig.loadSignature(node);
	try {
		// Returns false when a reference digest does not match.
		if (!sig.checkSignature(xml)) {
			result.reason = 'document does not match the signed digest';
			return result;
		}
	} catch (err) {
		// The message for a bad signature value embeds the whole value.
		result.reason = /^invalid signature: the signature value/.test(err.message)
			? 'signature is not valid'
			: err.message;
		return result;
	}
	result.valid = true;
	return result;
}
