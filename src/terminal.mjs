// Terminal input helpers.

import { createInterface } from 'node:readline';

/**
 * Reads a line without echoing it, for passwords. Enter finishes,
 * Backspace deletes, Ctrl+C and Ctrl+D cancel.
 *
 * @param {string} question Prompt text.
 * @param {object} [streams]
 * @param {object} [streams.input] TTY input stream.
 * @param {object} [streams.output] Output stream for the prompt.
 * @returns {Promise<string>}
 */
export function askHidden(question, { input = process.stdin, output = process.stderr } = {}) {
	if (!input.isTTY) {
		return Promise.reject(new Error('A terminal is required to enter the password'));
	}
	return new Promise((resolve, reject) => {
		let value = '';
		const finish = (err) => {
			input.off('data', onData);
			input.setRawMode(false);
			input.pause();
			output.write('\n');
			if (err) {
				reject(err);
			} else {
				resolve(value);
			}
		};
		const onData = (chunk) => {
			for (const ch of chunk.toString('utf8')) {
				if (ch === '\r' || ch === '\n') {
					finish();
					return;
				}
				if (ch === '\u0003' || ch === '\u0004') {
					finish(new Error('Cancelled'));
					return;
				}
				if (ch === '\u007f' || ch === '\b') {
					value = [...value].slice(0, -1).join('');
				} else {
					value += ch;
				}
			}
		};
		output.write(question);
		input.setRawMode(true);
		input.resume();
		input.on('data', onData);
	});
}

/**
 * Returns a copy of a JSON value with long strings shortened, for logging
 * request structure without dumping whole documents.
 *
 * @param {*} value Parsed JSON value.
 * @param {number} [max] Longest string kept as is.
 * @returns {*}
 */
export function truncateStrings(value, max = 80) {
	if (typeof value === 'string') {
		return value.length > max ? `${value.slice(0, max)}... (${value.length} chars)` : value;
	}
	if (Array.isArray(value)) {
		return value.map((v) => truncateStrings(v, max));
	}
	if (value && typeof value === 'object') {
		return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, truncateStrings(v, max)]));
	}
	return value;
}

/**
 * Asks a yes/no question. Only "y" or "yes" (any case) means yes.
 *
 * @param {string} question Prompt text.
 * @param {object} [streams]
 * @param {object} [streams.input] Input stream.
 * @param {object} [streams.output] Output stream for the prompt.
 * @returns {Promise<boolean>}
 */
export async function askYesNo(question, { input = process.stdin, output = process.stderr } = {}) {
	const rl = createInterface({ input, output, terminal: false });
	try {
		output.write(question);
		const answer = await new Promise((resolve) => {
			rl.once('line', resolve);
			rl.once('close', () => resolve(''));
		});
		return /^\s*y(es)?\s*$/i.test(answer);
	} finally {
		rl.close();
	}
}

/**
 * Renders a signing request summary for the terminal.
 *
 * @param {object} summary Summary from the basics module.
 * @param {string} summary.origin Requesting site.
 * @param {string} summary.format Signing format.
 * @param {Array<string>} summary.previews Data previews.
 * @param {object} summary.certificate Signer certificate.
 * @param {boolean|null} summary.encapsulate CMS attached or detached; null for XML.
 * @param {boolean} summary.timestamp Whether a timestamp will be added.
 * @returns {string}
 */
export function formatSummary({ origin, format, previews, certificate, encapsulate, timestamp }) {
	const cn = certificate.subject.find((a) => a.oid === '2.5.4.3');
	const lines = [
		'',
		'=== Signing request ===',
		`Site:        ${origin ?? '(no origin header)'}`,
		`Format:      ${format}${encapsulate === null ? '' : encapsulate ? ', attached' : ', detached'}${timestamp ? ', with timestamp' : ''}`,
		`Signer:      ${cn ? cn.value : '(no CN)'}, valid until ${certificate.notAfter.toISOString().slice(0, 10)}`,
		`Items:       ${previews.length}`,
	];
	previews.forEach((p, i) => {
		lines.push(`--- item ${i + 1} ---`, p);
	});
	lines.push('=======================');
	return lines.join('\n');
}
