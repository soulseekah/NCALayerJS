#!/usr/bin/env node
// NCALayerJS: local NCALayer compatible signing server.
//
// Usage: ncalayerjs --key <key.p12> [-y] [--tls <dir>] [--port <n>] [--log-requests]
//
// The key is unlocked once at startup. Every signing request is shown in
// the terminal and needs a y/N answer, unless -y is given. TLS files come
// from scripts/make-local-ca.sh, by default in ~/.config/ncalayerjs/tls.

import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { loadSigner } from '../src/kalkan.mjs';
import { startServer, DEFAULT_PORT } from '../src/server.mjs';
import { createBasicsModule, MODULE as BASICS } from '../src/basics.mjs';
import { askHidden, askYesNo, formatSummary, truncateStrings } from '../src/terminal.mjs';

const USAGE = 'Usage: ncalayerjs --key <key.p12> [-y] [--tls <dir>] [--port <n>] [--log-requests]';

/**
 * Entry point.
 */
async function main() {
	const { values } = parseArgs({
		options: {
			key: { type: 'string' },
			yes: { type: 'boolean', short: 'y', default: false },
			tls: { type: 'string', default: join(homedir(), '.config', 'ncalayerjs', 'tls') },
			port: { type: 'string', default: String(DEFAULT_PORT) },
			'log-requests': { type: 'boolean', default: false },
		},
	});
	if (!values.key) {
		console.error(USAGE);
		process.exit(2);
	}

	const p12 = readFileSync(values.key);
	const password = await askHidden(`Password for ${values.key}: `);
	const signer = loadSigner(p12, password);
	const cn = signer.certificate.subject.find((a) => a.oid === '2.5.4.3');
	console.error(`Unlocked: ${cn ? cn.value : '(no CN)'}, valid until ${signer.certificate.notAfter.toISOString().slice(0, 10)}`);
	if (values.yes) {
		console.error('WARNING: -y is on. Every site that reaches this server gets signatures without asking.');
	}

	const log = (line) => process.stderr.write(`${new Date().toISOString()} ${line}\n`);
	const confirm = async (summary) => {
		process.stderr.write(`${formatSummary(summary)}\n`);
		if (values.yes) {
			process.stderr.write('Auto-approved (-y).\n');
			return true;
		}
		return askYesNo('Sign? [y/N] ');
	};

	const server = await startServer({
		cert: readFileSync(join(values.tls, 'server.pem')),
		key: readFileSync(join(values.tls, 'server.key')),
		modules: { [BASICS]: createBasicsModule({ signer, confirm, log }) },
		port: Number(values.port),
		log,
		onRequest: values['log-requests']
			? (request) => log(`  request: ${JSON.stringify(truncateStrings(request))}`)
			: null,
	});

	const stop = async () => {
		console.error('Stopping.');
		await server.close();
		process.exit(0);
	};
	process.on('SIGINT', stop);
	process.on('SIGTERM', stop);
}

await main();
