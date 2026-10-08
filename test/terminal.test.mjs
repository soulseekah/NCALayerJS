import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { askHidden, askYesNo, formatSummary, truncateStrings } from '../src/terminal.mjs';

/**
 * Creates a fake TTY input stream that records raw mode changes.
 *
 * @returns {PassThrough}
 */
function fakeTty() {
	const input = new PassThrough();
	input.isTTY = true;
	input.rawModes = [];
	input.setRawMode = (mode) => input.rawModes.push(mode);
	return input;
}

/**
 * Collects everything written to a stream.
 *
 * @returns {PassThrough}
 */
function sink() {
	const output = new PassThrough();
	output.text = '';
	output.on('data', (d) => (output.text += d));
	return output;
}

test('askHidden reads a line without echoing it', async () => {
	const input = fakeTty();
	const output = sink();
	const answer = askHidden('Password: ', { input, output });
	input.write('Aa12');
	input.write('34\r');
	assert.equal(await answer, 'Aa1234');
	assert.equal(output.text, 'Password: \n');
	assert.deepEqual(input.rawModes, [true, false]);
});

test('askHidden handles backspace and multi-byte characters', async () => {
	const input = fakeTty();
	const answer = askHidden('', { input, output: sink() });
	input.write('пароль\u007f\u007fX\n');
	assert.equal(await answer, 'пароX');
});

test('askHidden cancels on Ctrl+C', async () => {
	const input = fakeTty();
	const answer = askHidden('', { input, output: sink() });
	input.write('abc\u0003');
	await assert.rejects(answer, /Cancelled/);
	assert.deepEqual(input.rawModes, [true, false]);
});

test('askHidden requires a terminal', async () => {
	const input = new PassThrough();
	await assert.rejects(askHidden('', { input, output: sink() }), /terminal is required/);
});

test('truncateStrings shortens long strings at any depth', () => {
	const long = 'x'.repeat(100);
	assert.deepEqual(truncateStrings({ a: long, b: [long, 1, null], c: { d: 'short' } }, 10), {
		a: 'xxxxxxxxxx... (100 chars)',
		b: ['xxxxxxxxxx... (100 chars)', 1, null],
		c: { d: 'short' },
	});
});

test('askYesNo accepts only y or yes', async () => {
	for (const [typed, expected] of [['y\n', true], ['YES\n', true], [' y \n', true], ['n\n', false], ['\n', false], ['yep\n', false]]) {
		const input = new PassThrough();
		const output = sink();
		const answer = askYesNo('Sign? [y/N] ', { input, output });
		input.write(typed);
		assert.equal(await answer, expected, JSON.stringify(typed));
		assert.equal(output.text, 'Sign? [y/N] ');
	}
});

test('askYesNo treats a closed input as no', async () => {
	const input = new PassThrough();
	const answer = askYesNo('', { input, output: sink() });
	input.end();
	assert.equal(await answer, false);
});

test('formatSummary shows site, format, signer and every item', () => {
	const text = formatSummary({
		origin: 'https://nca.pki.gov.kz',
		format: 'cms',
		previews: ['first', 'second'],
		certificate: { subject: [{ oid: '2.5.4.3', value: 'КОВШЕНИН ГЕННАДИЙ' }], notAfter: new Date('2027-10-08T09:31:32Z') },
		encapsulate: false,
		timestamp: true,
	});
	assert.match(text, /Site: +https:\/\/nca\.pki\.gov\.kz/);
	assert.match(text, /Format: +cms, detached, with timestamp/);
	assert.match(text, /Signer: +КОВШЕНИН ГЕННАДИЙ, valid until 2027-10-08/);
	assert.match(text, /--- item 2 ---\nsecond/);
	assert.match(formatSummary({ origin: null, format: 'xml', previews: ['x'], certificate: { subject: [], notAfter: new Date(0) }, encapsulate: null, timestamp: false }), /Format: +xml\n/);
});
