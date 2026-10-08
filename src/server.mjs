// NCALayer compatible WebSocket server: wss://127.0.0.1:13579.
//
// Modules are plain async handlers keyed by module name. Requests from
// all connections are handled one at a time, because each one may need a
// terminal prompt.

import { createServer as createHttpsServer } from 'node:https';
import { WebSocketServer } from 'ws';

export const DEFAULT_PORT = 13579;

// Version NCALayer announces on connect.
export const NCALAYER_VERSION = '1.4';

// Module used when a request has no "module" field.
export const DEFAULT_MODULE = 'kz.gov.pki.knca.applet.Applet';

const HEARTBEAT = '--heartbeat--';

// Signing requests carry whole documents as base64.
const MAX_PAYLOAD = 64 * 1024 * 1024;

/**
 * Starts the server.
 *
 * @param {object} options
 * @param {string|Buffer} options.cert TLS certificate, PEM.
 * @param {string|Buffer} options.key TLS private key, PEM.
 * @param {Object<string, Function>} [options.modules] Handlers: async (request, context) => response object.
 *   context holds origin, the Origin header or null.
 * @param {number} [options.port] Port, 0 picks a free one (for tests).
 * @param {Function} [options.log] Log function, receives one line.
 * @param {Function} [options.onRequest] Called with (request, context) for every parsed request.
 * @returns {Promise<{port: number, close: Function}>}
 */
export async function startServer({ cert, key, modules = {}, port = DEFAULT_PORT, log = defaultLog, onRequest = null }) {
	const https = createHttpsServer({ cert, key, minVersion: 'TLSv1.2' }, (req, res) => {
		res.writeHead(426, { 'Content-Type': 'text/plain' });
		res.end('WebSocket only\n');
	});
	const wss = new WebSocketServer({ server: https, maxPayload: MAX_PAYLOAD });
	let queue = Promise.resolve();

	wss.on('connection', (ws, req) => {
		const origin = req.headers.origin ?? null;
		log(`connect from ${origin ?? 'no origin'}`);
		ws.send(JSON.stringify({ result: { version: NCALAYER_VERSION } }));

		ws.on('message', (data, isBinary) => {
			const text = data.toString('utf8');
			if (!isBinary && text === HEARTBEAT) {
				ws.send(HEARTBEAT);
				return;
			}
			// Chain on the global queue so prompts never overlap.
			queue = queue.then(() => handle(text, origin, modules, log, onRequest)).then(
				(response) => send(ws, response),
				(err) => log(`internal error: ${err.message}`),
			);
		});
		ws.on('close', () => log(`disconnect from ${origin ?? 'no origin'}`));
		ws.on('error', (err) => log(`socket error: ${err.message}`));
	});

	await new Promise((resolve, reject) => {
		https.once('error', reject);
		https.listen(port, '127.0.0.1', resolve);
	});
	log(`listening on wss://127.0.0.1:${https.address().port}`);

	return {
		port: https.address().port,
		close: () => new Promise((resolve) => {
			for (const client of wss.clients) {
				client.terminate();
			}
			wss.close(() => https.close(() => resolve()));
		}),
	};
}

/**
 * Handles one request message.
 *
 * @param {string} text Message text.
 * @param {string|null} origin Origin header of the connection.
 * @param {Object<string, Function>} modules Module handlers.
 * @param {Function} log Log function.
 * @param {Function|null} onRequest Hook called with each parsed request.
 * @returns {Promise<object>} Response object.
 */
async function handle(text, origin, modules, log, onRequest) {
	let request;
	try {
		request = JSON.parse(text);
	} catch {
		log(`${origin ?? 'no origin'}: invalid JSON`);
		return { success: false, errorCode: 'BAD_REQUEST' };
	}
	if (request === null || typeof request !== 'object' || Array.isArray(request)) {
		log(`${origin ?? 'no origin'}: request is not an object`);
		return { success: false, errorCode: 'BAD_REQUEST' };
	}
	const module = typeof request.module === 'string' ? request.module : DEFAULT_MODULE;
	log(`${origin ?? 'no origin'}: ${module} ${typeof request.method === 'string' ? request.method : '(no method)'}`);
	if (onRequest) {
		onRequest(request, { origin });
	}
	const handler = Object.hasOwn(modules, module) ? modules[module] : null;
	if (!handler) {
		return { success: false, errorCode: 'MODULE_NOT_FOUND' };
	}
	try {
		return await handler(request, { origin });
	} catch (err) {
		log(`${module} failed: ${err.message}`);
		return { success: false, errorCode: 'GENERAL_ERROR' };
	}
}

/**
 * Sends a response if the socket is still open.
 *
 * @param {WebSocket} ws Socket.
 * @param {object} response Response object.
 */
function send(ws, response) {
	if (ws.readyState === ws.OPEN) {
		ws.send(JSON.stringify(response));
	}
}

/**
 * Writes a timestamped log line to stderr.
 *
 * @param {string} line Message.
 */
function defaultLog(line) {
	process.stderr.write(`${new Date().toISOString()} ${line}\n`);
}
