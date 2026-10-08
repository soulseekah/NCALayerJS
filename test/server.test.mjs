import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import WebSocket from 'ws';
import { startServer, NCALAYER_VERSION } from '../src/server.mjs';

// Fixtures come from test/fixtures/make-tls.sh.
const cert = readFileSync(new URL('./fixtures/tls.pem', import.meta.url));
const key = readFileSync(new URL('./fixtures/tls.key', import.meta.url));

const calls = [];
const logs = [];
let server;

const modules = {
	'test.echo': async (request, context) => {
		calls.push({ method: request.method, origin: context.origin });
		return { echo: request.args };
	},
	'test.slow': async (request) => {
		calls.push({ method: request.method, start: true });
		await new Promise((resolve) => setTimeout(resolve, 50));
		calls.push({ method: request.method, end: true });
		return { done: request.method };
	},
	'test.fail': async () => {
		throw new Error('boom');
	},
};

before(async () => {
	server = await startServer({ cert, key, modules, port: 0, log: (line) => logs.push(line) });
});

after(async () => {
	await server.close();
});

/**
 * Opens a client connection and collects incoming messages.
 *
 * @param {string} [origin] Origin header to send.
 * @returns {Promise<{ws: WebSocket, next: Function}>} next() resolves with the next message text.
 */
async function connect(origin = 'https://example.kz') {
	const ws = new WebSocket(`wss://127.0.0.1:${server.port}`, { ca: cert, origin });
	const inbox = [];
	const waiting = [];
	ws.on('message', (data) => {
		const text = data.toString('utf8');
		if (waiting.length) {
			waiting.shift()(text);
		} else {
			inbox.push(text);
		}
	});
	await new Promise((resolve, reject) => {
		ws.once('open', resolve);
		ws.once('error', reject);
	});
	const next = () => (inbox.length ? Promise.resolve(inbox.shift()) : new Promise((resolve) => waiting.push(resolve)));
	return { ws, next };
}

test('announces the NCALayer version on connect', async () => {
	const { ws, next } = await connect();
	assert.deepEqual(JSON.parse(await next()), { result: { version: NCALAYER_VERSION } });
	ws.close();
});

test('echoes heartbeats', async () => {
	const { ws, next } = await connect();
	await next();
	ws.send('--heartbeat--');
	assert.equal(await next(), '--heartbeat--');
	ws.close();
});

test('routes requests to modules and passes the origin', async () => {
	const { ws, next } = await connect('https://idp.egov.kz');
	await next();
	ws.send(JSON.stringify({ module: 'test.echo', method: 'ping', args: [1, 'two'] }));
	assert.deepEqual(JSON.parse(await next()), { echo: [1, 'two'] });
	assert.deepEqual(calls.at(-1), { method: 'ping', origin: 'https://idp.egov.kz' });
	assert.ok(logs.some((l) => l === 'https://idp.egov.kz: test.echo ping'));
	ws.close();
});

test('unknown and default modules give MODULE_NOT_FOUND', async () => {
	const { ws, next } = await connect();
	await next();
	ws.send(JSON.stringify({ module: 'kz.gov.pki.knca.nope', method: 'x' }));
	assert.deepEqual(JSON.parse(await next()), { success: false, errorCode: 'MODULE_NOT_FOUND' });
	// No module field means the legacy Applet module, which we do not have.
	ws.send(JSON.stringify({ method: 'browseKeyStore', args: [] }));
	assert.deepEqual(JSON.parse(await next()), { success: false, errorCode: 'MODULE_NOT_FOUND' });
	// Inherited object keys must not be treated as modules.
	ws.send(JSON.stringify({ module: 'toString' }));
	assert.deepEqual(JSON.parse(await next()), { success: false, errorCode: 'MODULE_NOT_FOUND' });
	ws.close();
});

test('bad requests and handler errors get error replies', async () => {
	const { ws, next } = await connect();
	await next();
	ws.send('{not json');
	assert.deepEqual(JSON.parse(await next()), { success: false, errorCode: 'BAD_REQUEST' });
	ws.send('[1, 2]');
	assert.deepEqual(JSON.parse(await next()), { success: false, errorCode: 'BAD_REQUEST' });
	ws.send(JSON.stringify({ module: 'test.fail', method: 'x' }));
	assert.deepEqual(JSON.parse(await next()), { success: false, errorCode: 'GENERAL_ERROR' });
	assert.ok(logs.some((l) => l === 'test.fail failed: boom'));
	ws.close();
});

test('requests from different connections are handled one at a time', async () => {
	const a = await connect();
	const b = await connect();
	await a.next();
	await b.next();
	calls.length = 0;
	a.ws.send(JSON.stringify({ module: 'test.slow', method: 'first' }));
	b.ws.send(JSON.stringify({ module: 'test.slow', method: 'second' }));
	assert.deepEqual(JSON.parse(await a.next()), { done: 'first' });
	assert.deepEqual(JSON.parse(await b.next()), { done: 'second' });
	assert.deepEqual(calls, [
		{ method: 'first', start: true },
		{ method: 'first', end: true },
		{ method: 'second', start: true },
		{ method: 'second', end: true },
	]);
	a.ws.close();
	b.ws.close();
});

test('plain HTTPS requests get 426', async () => {
	const status = await new Promise((resolve, reject) => {
		httpsRequest({ host: '127.0.0.1', port: server.port, ca: cert, path: '/' }, (res) => {
			res.resume();
			resolve(res.statusCode);
		}).on('error', reject).end();
	});
	assert.equal(status, 426);
});

test('onRequest sees every parsed request', async () => {
	const seen = [];
	const other = await startServer({ cert, key, port: 0, log: () => {}, onRequest: (r, c) => seen.push([r.method, c.origin]) });
	const ws = new WebSocket(`wss://127.0.0.1:${other.port}`, { ca: cert, origin: 'https://a.kz' });
	const replies = [];
	await new Promise((resolve) => {
		ws.on('message', (d) => {
			replies.push(d.toString());
			if (replies.length === 2) {
				resolve();
			}
		});
		ws.once('open', () => ws.send(JSON.stringify({ module: 'x', method: 'sign' })));
	});
	assert.deepEqual(seen, [['sign', 'https://a.kz']]);
	ws.close();
	await other.close();
});
