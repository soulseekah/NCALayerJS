import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DOMParser } from '@xmldom/xmldom';
import { signXml, verifyXml, URI } from '../src/xmldsig.mjs';
import { streebog512 } from '../src/streebog.mjs';
import { makeSigner } from './helpers/gost.mjs';

const signer = makeSigner();

// The shape of the NCA RK login challenge.
const challenge = '<?xml version="1.0" encoding="utf-8"?><root><data>1e2a9b00-76c5-4e0a-97d7-e418b5000000</data></root>';

/**
 * Returns the ds:Signature element of a signed document.
 *
 * @param {string} xml Signed document.
 * @returns {Element}
 */
function signatureOf(xml) {
	return new DOMParser().parseFromString(xml, 'text/xml').getElementsByTagNameNS(URI.DSIG_NS, 'Signature')[0];
}

/**
 * Returns the text of the first element with the given local name.
 *
 * @param {Element} node Parent.
 * @param {string} name Local name in the xmldsig namespace.
 * @returns {string}
 */
function text(node, name) {
	return node.getElementsByTagNameNS(URI.DSIG_NS, name)[0].textContent;
}

test('signs and verifies the login challenge', () => {
	const signed = signXml(challenge, signer);
	const result = verifyXml(signed);
	assert.equal(result.reason, null);
	assert.equal(result.valid, true);
	assert.deepEqual(result.certificate.der, signer.certificate.der);
});

test('uses the Kalkan whole-document layout', () => {
	const sig = signatureOf(signXml(challenge, signer));
	assert.equal(sig.prefix, 'ds');
	assert.equal(sig.parentNode.localName, 'root');
	assert.equal(sig.parentNode.lastChild, sig);
	const alg = (name) => sig.getElementsByTagNameNS(URI.DSIG_NS, name)[0].getAttribute('Algorithm');
	assert.equal(alg('CanonicalizationMethod'), URI.C14N);
	assert.equal(alg('SignatureMethod'), URI.SIGNATURE);
	assert.equal(alg('DigestMethod'), URI.DIGEST);
	const ref = sig.getElementsByTagNameNS(URI.DSIG_NS, 'Reference')[0];
	assert.equal(ref.getAttribute('URI'), '');
	const transforms = Array.from(sig.getElementsByTagNameNS(URI.DSIG_NS, 'Transform')).map((t) => t.getAttribute('Algorithm'));
	assert.deepEqual(transforms, [URI.ENVELOPED, URI.C14N_WITH_COMMENTS]);
	assert.equal(text(sig, 'X509Certificate'), signer.certificate.der.toString('base64'));
	assert.equal(Buffer.from(text(sig, 'SignatureValue'), 'base64').length, 128);
});

test('digest is Streebog-512 of the canonical document', () => {
	// Without namespaces or attributes, the canonical form is the document
	// without its XML declaration. Checked without xml-crypto.
	const sig = signatureOf(signXml(challenge, signer));
	const canonical = '<root><data>1e2a9b00-76c5-4e0a-97d7-e418b5000000</data></root>';
	assert.equal(text(sig, 'DigestValue'), streebog512(canonical).toString('base64'));
});

test('tampered content or signature is rejected', () => {
	const signed = signXml(challenge, signer);
	assert.equal(verifyXml(signed.replace('1e2a9b00', '1e2a9b01')).reason, 'document does not match the signed digest');
	const value = text(signatureOf(signed), 'SignatureValue');
	const flipped = (value[0] === 'A' ? 'B' : 'A') + value.slice(1);
	const result = verifyXml(signed.replace(value, flipped));
	assert.equal(result.valid, false);
	assert.equal(result.reason, 'signature is not valid');
});

test('namespaces inherited from the root are handled', () => {
	const xml = '<doc xmlns="urn:example:default" xmlns:x="urn:example:x" x:id="1"><x:item b="2" a="1">Қазақстан &amp; ко</x:item></doc>';
	const signed = signXml(xml, signer);
	assert.equal(verifyXml(signed).valid, true);
	assert.equal(verifyXml(signed.replace('a="1"', 'a="2"')).valid, false);
});

test('processing instructions are signed, comments are not', () => {
	const xml = '<?xml version="1.0"?><?app keep?><root><!-- note --><?inner keep?><v>1</v></root>';
	const signed = signXml(xml, signer);
	assert.equal(verifyXml(signed).valid, true);
	// PIs are part of the URI="" node-set, also outside the root element
	// (fixed in xml-crypto 6.3.3).
	assert.equal(verifyXml(signed.replace('<?app keep?>', '<?app edit?>')).valid, false);
	assert.equal(verifyXml(signed.replace('<?inner keep?>', '<?inner edit?>')).valid, false);
	// XMLDSig 4.4.3.3: dereferencing URI="" removes comments, even with
	// the c14n WithComments transform.
	assert.equal(verifyXml(signed.replace('<!-- note -->', '<!-- edit -->')).valid, true);
});

test('rejects wrapped or unusual signatures', () => {
	const signed = signXml(challenge, signer);
	assert.match(verifyXml(challenge).reason, /found 0/);
	const sig = signed.slice(signed.indexOf('<ds:Signature'), signed.indexOf('</root>'));
	assert.match(verifyXml(signed.replace('</root>', `${sig}</root>`)).reason, /found 2/);
	const moved = signed.replace(sig, '').replace('</data>', `</data><wrap>${sig}</wrap>`);
	assert.equal(verifyXml(moved).reason, 'signature is not a child of the root element');
	assert.equal(verifyXml(signed.replace('URI=""', 'URI="#x"')).reason, 'expected one Reference with URI=""');
});
