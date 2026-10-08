#!/usr/bin/env node
// Signs a file as CMS with a Kalkan PKCS#12 key.
//
// Usage: NCA_PASSWORD=... node scripts/sign-cms.mjs <key.p12> <input> <output.cms> [--detached] [--tsp]
//
// --tsp adds a timestamp from the NCA RK TSA (sends only a hash of the signature).

import { readFileSync, writeFileSync } from 'node:fs';
import { loadSigner } from '../src/kalkan.mjs';
import { signCms, timestampCms } from '../src/cms.mjs';

/**
 * Entry point.
 */
async function main() {
	const args = process.argv.slice(2);
	const flags = new Set(args.filter((a) => a.startsWith('--')));
	const [p12Path, inputPath, outputPath] = args.filter((a) => !a.startsWith('--'));
	const password = process.env.NCA_PASSWORD;
	if (!p12Path || !inputPath || !outputPath || password === undefined) {
		console.error('Usage: NCA_PASSWORD=... node sign-cms.mjs <key.p12> <input> <output.cms> [--detached] [--tsp]');
		process.exit(2);
	}
	const signer = loadSigner(readFileSync(p12Path), password);
	let der = signCms({ content: readFileSync(inputPath), signer, detached: flags.has('--detached') });
	if (flags.has('--tsp')) {
		der = await timestampCms(der);
	}
	writeFileSync(outputPath, der);
	console.log(`wrote ${der.length} bytes to ${outputPath} (${[...flags].join(' ') || 'attached'})`);
}

await main();
