// Module kz.gov.pki.knca.basics: the "apiVersion 2" API that current
// sites use. Only the sign method of the default PKIExtras class is
// implemented.

import { DOMParser } from '@xmldom/xmldom';
import { parseBer, oid as readOid } from './ber.mjs';
import { parseCertificate, pemToDer, OID as X509 } from './x509.mjs';
import { signCms, timestampCms } from './cms.mjs';
import { signXml } from './xmldsig.mjs';
import { OID as KALKAN } from './kalkan.mjs';

export const MODULE = 'kz.gov.pki.knca.basics';

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

const MESSAGES = {
	GENERAL_ERROR: 'General error.',
	INVALID_SIGNING_PARAMS: 'Invalid signing parameters provided.',
	SIGNING_FAILURE: 'Signing has failed.',
};

/**
 * Error that becomes a basics failure response.
 */
class Failure extends Error {
	/**
	 * @param {string} code Failure code.
	 * @param {string} details Details for the response and the log.
	 * @param {string} [message] Message; the standard one for the code by default.
	 */
	constructor(code, details, message) {
		super(details);
		this.code = code;
		this.responseMessage = message ?? MESSAGES[code] ?? details;
	}
}

/**
 * Builds a basics failure response.
 *
 * @param {Failure} failure Failure.
 * @returns {object}
 */
function failureResponse(failure) {
	return { status: false, code: failure.code, message: failure.responseMessage, details: failure.message };
}

// Response for a cancelled action: NCALayer returns an EmptyResponse body.
const CANCELLED = { status: true, body: {} };

/**
 * Checks that a value is a plain object.
 *
 * @param {*} value Value.
 * @returns {boolean}
 */
function isObject(value) {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Validates sign() arguments.
 *
 * @param {*} args Request args.
 * @returns {{format: string, items: Array<string>, signingParams: object, signerParams: object, allowedStorages: Array<string>|null}}
 */
export function parseSignArgs(args) {
	if (!isObject(args)) {
		throw new Failure('INVALID_SIGNING_PARAMS', 'args must be an object');
	}
	const { format, data, signingParams, signerParams, allowedStorages } = args;
	if (!['xml', 'cms', 'raw'].includes(format)) {
		throw new Failure('INVALID_SIGNING_PARAMS', `unknown format ${JSON.stringify(format)}`);
	}
	const items = typeof data === 'string' ? [data] : data;
	if (!Array.isArray(items) || items.length === 0 || !items.every((d) => typeof d === 'string')) {
		throw new Failure('INVALID_SIGNING_PARAMS', 'data must be a string or a non-empty array of strings');
	}
	if (!isObject(signingParams)) {
		throw new Failure('INVALID_SIGNING_PARAMS', 'signingParams must be an object');
	}
	if (!isObject(signerParams) || !Array.isArray(signerParams.extKeyUsageOids)) {
		throw new Failure('INVALID_SIGNING_PARAMS', 'signerParams.extKeyUsageOids must be an array');
	}
	if (allowedStorages !== undefined && allowedStorages !== null && !Array.isArray(allowedStorages)) {
		throw new Failure('INVALID_SIGNING_PARAMS', 'allowedStorages must be an array');
	}
	return { format, items, signingParams, signerParams, allowedStorages: allowedStorages ?? null };
}

/**
 * Returns the value of the first subject attribute with the given OID.
 *
 * @param {object} cert Parsed certificate.
 * @param {string} type Attribute OID.
 * @returns {string|null}
 */
function subjectValue(cert, type) {
	const attr = cert.subject.find((a) => a.oid === type);
	return attr ? attr.value : null;
}

/**
 * Parses a chain entry: PEM, or bare base64 DER.
 *
 * @param {string} text Certificate text.
 * @returns {object|null} Parsed certificate, or null when unreadable.
 */
function parseChainCertificate(text) {
	try {
		const data = Buffer.from(text, 'latin1');
		return parseCertificate(text.includes('-----BEGIN') ? pemToDer(data) : Buffer.from(text.replace(/\s+/g, ''), 'base64'));
	} catch {
		return null;
	}
}

const CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
const SHA256_WITH_RSA = '1.2.840.113549.1.1.11';

/**
 * Tells whether a certificate counts as an authentication certificate
 * without the clientAuth EKU. Current NCA certificates serve both login
 * and signing and are recognized by key usage:
 *
 * - GOST 2015 512 signed certificate with keyAgreement, or
 * - sha256WithRSA signed certificate with keyEncipherment or keyAgreement.
 *
 * @param {object} cert Parsed certificate.
 * @returns {boolean}
 */
export function impliesClientAuth(cert) {
	const usage = cert.keyUsage ?? [];
	if (cert.signatureAlgorithm === KALKAN.GOST2015_512_SIGN && usage.includes('keyAgreement')) {
		return true;
	}
	return cert.signatureAlgorithm === SHA256_WITH_RSA
		&& (usage.includes('keyEncipherment') || usage.includes('keyAgreement'));
}

/**
 * Explains why the unlocked key can not be offered for this request, the
 * way NCALayer would not list it.
 *
 * @param {object} cert Signer certificate.
 * @param {object} args Result of parseSignArgs().
 * @param {Date} now Current time.
 * @returns {string|null} Reason, or null when the key matches.
 */
export function keyMismatch(cert, { format, signingParams, signerParams, allowedStorages }, now) {
	if (allowedStorages && !allowedStorages.includes('PKCS12')) {
		return 'the site does not allow PKCS12 file keys';
	}
	const eku = new Set(cert.extKeyUsage ?? []);
	if (signerParams.extKeyUsageOids.includes(CLIENT_AUTH) && impliesClientAuth(cert)) {
		eku.add(CLIENT_AUTH);
	}
	const missing = signerParams.extKeyUsageOids.filter((o) => !eku.has(o));
	if (missing.length) {
		return `the certificate lacks required key usages ${missing.join(', ')}`;
	}
	const iin = subjectValue(cert, X509.SERIAL_NUMBER);
	if (signerParams.iin && iin !== `IIN${signerParams.iin}`) {
		return `the site asks for IIN ${signerParams.iin}`;
	}
	const bin = subjectValue(cert, X509.ORGANIZATIONAL_UNIT);
	if (signerParams.bin && bin !== `BIN${signerParams.bin}`) {
		return `the site asks for BIN ${signerParams.bin}`;
	}
	if (signerParams.serialNumber && BigInt(`0x${signerParams.serialNumber}`) !== cert.serial) {
		return `the site asks for certificate ${signerParams.serialNumber}`;
	}
	if (Array.isArray(signerParams.chain) && signerParams.chain.length) {
		const issuers = signerParams.chain.map(parseChainCertificate).filter(Boolean);
		if (!issuers.some((ca) => ca.subjectRaw.equals(cert.issuerRaw))) {
			return 'the certificate issuer is not in the chain the site trusts';
		}
	}
	const allowExpired = format === 'xml' || format === 'cms' ? signingParams.allowExpired === true : false;
	if (!allowExpired && (now < cert.notBefore || now > cert.notAfter)) {
		return 'the certificate is not valid at this time';
	}
	return null;
}

/**
 * Wraps DER as PEM with 64-column lines.
 *
 * @param {Buffer} der Data.
 * @param {string} label PEM label.
 * @returns {string}
 */
function toPem(der, label) {
	return `-----BEGIN ${label}-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----`;
}

/**
 * Finds badly nested or unclosed element tags, which xmldom 0.8 repairs
 * silently. Comments, CDATA, PIs and DOCTYPE are skipped.
 *
 * @param {string} xml Document.
 * @returns {string|null} Problem description, or null.
 */
export function nestingError(xml) {
	const stack = [];
	const tokens = /<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<\/\s*([^\s>]+)\s*>|<([^\s/>!?]+)(?:"[^"]*"|'[^']*'|[^'">])*?(\/?)>/g;
	for (const m of xml.matchAll(tokens)) {
		if (m[1]) {
			const open = stack.pop();
			if (open !== m[1]) {
				return `closing tag </${m[1]}> does not match <${open ?? 'nothing'}>`;
			}
		} else if (m[2] && !m[3]) {
			stack.push(m[2]);
		}
	}
	return stack.length ? `unclosed tag <${stack[stack.length - 1]}>` : null;
}

/**
 * Checks that a string is well-formed XML. xmldom 0.8 reports some
 * well-formedness errors only as warnings, so warnings count as errors.
 *
 * @param {string} xml Document.
 */
function assertWellFormed(xml) {
	const errors = [];
	const report = (msg) => errors.push(String(msg).split('\n')[0]);
	const parser = new DOMParser({ errorHandler: { warning: report, error: report, fatalError: report } });
	const doc = parser.parseFromString(xml, 'text/xml');
	const problem = errors[0] ?? (!doc || !doc.documentElement ? 'no root element' : nestingError(xml));
	if (problem) {
		throw new Failure('UNABLE_TO_PARSE_XML', problem, 'Unable to parse XML.');
	}
}

/**
 * Converts one CMS data item to bytes.
 *
 * @param {string} item Data item.
 * @param {boolean} decode Whether the item is base64.
 * @returns {Buffer}
 */
function cmsBytes(item, decode) {
	if (!decode) {
		return Buffer.from(item, 'utf8');
	}
	if (!/^[A-Za-z0-9+/\s]*={0,2}\s*$/.test(item)) {
		throw new Failure('INVALID_SIGNING_PARAMS', 'data is not valid base64');
	}
	return Buffer.from(item, 'base64');
}

/**
 * Checks whether bytes are a CMS SignedData, which NCALayer would co-sign.
 *
 * @param {Buffer} bytes Data.
 * @returns {boolean}
 */
function isSignedData(bytes) {
	try {
		return readOid(parseBer(bytes).children[0]) === OID_SIGNED_DATA;
	} catch {
		return false;
	}
}

/**
 * Makes a short human readable preview of one data item.
 *
 * @param {string} item Data item.
 * @param {string} format Signing format.
 * @param {boolean} decode Whether the item is base64.
 * @returns {string}
 */
export function preview(item, format, decode) {
	const max = 400;
	let text = item;
	if (format === 'cms' && decode) {
		const bytes = Buffer.from(item, 'base64');
		const utf8 = bytes.toString('utf8');
		// Show text only when it survives a UTF-8 round trip without control bytes.
		if (!Buffer.from(utf8, 'utf8').equals(bytes) || /[\x00-\x08\x0e-\x1f]/.test(utf8)) {
			return `(${bytes.length} bytes of binary data)`;
		}
		text = utf8;
	}
	return text.length > max ? `${text.slice(0, max)}... (${text.length} chars)` : text;
}

/**
 * Creates the basics module handler.
 *
 * @param {object} options
 * @param {{curve: object, d: bigint, certificate: object}} options.signer Unlocked key from loadSigner().
 * @param {Function} options.confirm async (summary) => boolean; asks the user.
 * @param {Function} [options.log] Log function.
 * @param {Function} [options.timestamp] async (cmsDer) => cmsDer with a timestamp.
 * @param {Function} [options.now] Current time, for tests.
 * @returns {Function} Module handler for startServer().
 */
export function createBasicsModule({ signer, confirm, log = () => {}, timestamp = timestampCms, now = () => new Date() }) {
	return async (request, { origin }) => {
		try {
			const apiVersion = request.apiVersion ?? 2;
			if (apiVersion !== 2) {
				throw new Failure('GENERAL_ERROR', 'Supported apiVersion is 2');
			}
			const cls = request.class ?? 'PKIExtras';
			if (cls !== 'PKIExtras' || request.method !== 'sign') {
				throw new Failure('GENERAL_ERROR', `unsupported method ${cls}.${request.method}`);
			}
			const args = parseSignArgs(request.args);
			if (args.format === 'raw') {
				throw new Failure('INVALID_SIGNING_PARAMS', 'format raw is not supported yet');
			}
			const decode = args.format === 'cms' && args.signingParams.decode === true;
			if (args.format === 'cms' && args.signingParams.digested === true) {
				throw new Failure('INVALID_SIGNING_PARAMS', 'digested signing is not supported yet');
			}

			const mismatch = keyMismatch(signer.certificate, args, now());
			if (mismatch) {
				log(`no suitable key: ${mismatch}`);
				return CANCELLED;
			}

			// Check the data before asking, so the user never approves junk.
			const prepared = args.items.map((item) => {
				if (args.format === 'xml') {
					assertWellFormed(item);
					return item;
				}
				const bytes = cmsBytes(item, decode);
				if (isSignedData(bytes)) {
					throw new Failure('SIGNING_FAILURE', 'co-signing an existing CMS is not supported yet');
				}
				return bytes;
			});

			const timestamped = args.format === 'cms' && isObject(args.signingParams.tsaProfile);
			const approved = await confirm({
				origin,
				format: args.format,
				previews: args.items.map((item) => preview(item, args.format, decode)),
				certificate: signer.certificate,
				encapsulate: args.format === 'cms' ? args.signingParams.encapsulate !== false : null,
				timestamp: timestamped,
			});
			if (!approved) {
				log('declined by the user');
				return CANCELLED;
			}

			const result = [];
			for (const item of prepared) {
				if (args.format === 'xml') {
					result.push(signXml(item, signer));
					continue;
				}
				let der = signCms({ content: item, signer, detached: args.signingParams.encapsulate === false });
				if (timestamped) {
					der = await timestamp(der);
				}
				result.push(toPem(der, 'CMS'));
			}
			log(`signed ${result.length} ${args.format} item(s) for ${origin ?? 'no origin'}`);
			return { status: true, body: { result } };
		} catch (err) {
			const failure = err instanceof Failure ? err : new Failure('SIGNING_FAILURE', err.message);
			log(`${failure.code}: ${failure.message}`);
			return failureResponse(failure);
		}
	};
}
