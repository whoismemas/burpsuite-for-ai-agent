// Burp Suite MCP server for OpenCode
// Provides an HTTP bridge for Burp to push traffic to, and MCP tools
// for the OpenCode agent to query captured requests, tasks, and issues.
//
// Usage: node src/index.js [--port 9999]
//
// Burp plugin (pentesterflow_burp.py) sends traffic to the HTTP bridge.
// OpenCode queries the store via MCP tools over stdio.

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { z } from 'zod';

// ──────────────────────────────────────────────
// Capture Store (in-memory, bounded)
// ──────────────────────────────────────────────

const MAX_ENDPOINTS = 2000;
const MAX_PARAMS_PER_ENDPOINT = 256;
const BODY_STRING_CAP = 64 * 1024;

class CaptureStore {
  constructor(maxEntries = 5000) {
    this.requests = new Map();
    this.endpoints = new Map();
    this.snapshots = [];
    this.burpTasks = [];
    this.burpIssues = new Map();
    this.outboundActions = [];
    this.maxEntries = Math.max(100, maxEntries);
    this.nextSeq = 1;
    this.lastActivityAt = 0;
  }

  ingest(raw) {
    if (!raw || typeof raw !== 'object') return { ok: false, reason: 'not an object' };
    const obj = raw;
    const kind = typeof obj.kind === 'string' ? obj.kind : undefined;

    if (kind === 'ws-open' || kind === 'ws-send' || kind === 'ws-recv') {
      this._recordEndpoint('WS', obj.url || '', undefined, undefined);
      this.lastActivityAt = Date.now();
      return { ok: true };
    }

    const url = typeof obj.url === 'string' ? obj.url : '';
    if (!url) return { ok: false, reason: 'missing url' };

    const method = (typeof obj.method === 'string' ? obj.method : 'GET').toUpperCase();
    const idSeed = obj.id ?? `${kind ?? 'wr'}-${this.nextSeq++}`;
    const id = `${kind ?? 'wr'}:${String(idSeed)}`;

    const entry = {
      id,
      source: kind === 'fetch' || kind === 'xhr' || kind === 'ws' ? kind : kind ? 'unknown' : 'webRequest',
      tabId: typeof obj.tabId === 'number' ? obj.tabId : undefined,
      method,
      url,
      type: typeof obj.type === 'string' ? obj.type : undefined,
      initiator: typeof obj.initiator === 'string' ? obj.initiator : undefined,
      status: typeof obj.status === 'number' ? obj.status : undefined,
      fromCache: typeof obj.fromCache === 'boolean' ? obj.fromCache : undefined,
      requestHeaders: this._coerceHeaders(obj.requestHeaders ?? obj.reqHeaders),
      responseHeaders: this._coerceHeaders(obj.responseHeaders ?? obj.respHeaders),
      requestBody: this._capBody(obj.requestBody ?? obj.reqBody ?? undefined),
      responseBody: typeof obj.respBody === 'string' ? this._capString(obj.respBody) : undefined,
      timeStart: typeof obj.timeStart === 'number' ? obj.timeStart : undefined,
      timeEnd: typeof obj.timeEnd === 'number' ? obj.timeEnd : undefined,
      elapsedMs: typeof obj.elapsedMs === 'number' ? obj.elapsedMs : undefined,
      receivedAt: Date.now(),
    };

    this.requests.delete(id);
    this.requests.set(id, entry);
    this._recordEndpoint(method, url, entry.requestBody, this._queryParams(url));
    this._pruneIfNeeded();
    this.lastActivityAt = Date.now();
    return { ok: true };
  }

  ingestSnapshot(raw) {
    if (!raw || typeof raw !== 'object') return { ok: false, reason: 'not an object' };
    const obj = raw;
    if (typeof obj.url !== 'string') return { ok: false, reason: 'missing url' };
    const snap = {
      receivedAt: Date.now(),
      url: obj.url,
      title: typeof obj.title === 'string' ? obj.title : undefined,
      userAgent: typeof obj.userAgent === 'string' ? obj.userAgent : undefined,
      documentCookie: typeof obj.documentCookie === 'string' ? this._capString(obj.documentCookie) : undefined,
      cookies: Array.isArray(obj.cookies) ? obj.cookies : undefined,
      localStorage: this._coerceStringMap(obj.localStorage),
      sessionStorage: this._coerceStringMap(obj.sessionStorage),
    };
    this.snapshots.push(snap);
    if (this.snapshots.length > 100) this.snapshots.splice(0, this.snapshots.length - 100);
    this.lastActivityAt = Date.now();
    return { ok: true };
  }

  status() {
    return {
      requestCount: this.requests.size,
      endpointCount: this.endpoints.size,
      snapshotCount: this.snapshots.length,
      burpTaskCount: this.burpTasks.length,
      burpIssueCount: this.burpIssues.size,
      outboundActionCount: this.outboundActions.length,
      lastActivityAt: this.lastActivityAt,
    };
  }

  addOutboundAction(type, params) {
    const entry = {
      id: `outbound-${this.nextSeq++}`,
      type,
      params,
      createdAt: Date.now(),
    };
    this.outboundActions.push(entry);
    if (this.outboundActions.length > 200) {
      this.outboundActions.splice(0, this.outboundActions.length - 200);
    }
    this.lastActivityAt = Date.now();
    return entry;
  }

  drainOutboundActions() {
    const actions = this.outboundActions;
    this.outboundActions = [];
    return actions;
  }

  listOutboundActions() {
    return [...this.outboundActions];
  }

  listRequests(filter = {}) {
    const limit = filter.limit ?? 200;
    const urlSubstr = filter.urlSubstr?.toLowerCase();
    const method = filter.method?.toUpperCase();
    const out = [];
    const values = [...this.requests.values()];
    for (let i = values.length - 1; i >= 0; i -= 1) {
      const r = values[i];
      if (!r) continue;
      if (urlSubstr && !r.url.toLowerCase().includes(urlSubstr)) continue;
      if (method && r.method !== method) continue;
      out.push(r);
      if (out.length >= limit) break;
    }
    return out;
  }

  getRequest(id) {
    return this.requests.get(id);
  }

  listEndpoints(filter = {}) {
    const urlSubstr = filter.urlSubstr?.toLowerCase();
    const method = filter.method?.toUpperCase();
    return [...this.endpoints.values()]
      .filter((e) => {
        if (urlSubstr && !e.url.toLowerCase().includes(urlSubstr)) return false;
        if (method && e.method !== method) return false;
        return true;
      })
      .map((e) => ({
        method: e.method,
        url: e.url,
        queryParams: [...e.queryParams],
        bodyParams: [...e.bodyParams],
        hitCount: e.hitCount,
        firstSeen: e.firstSeen,
        lastSeen: e.lastSeen,
      }))
      .sort((a, b) => b.hitCount - a.hitCount);
  }

  latestSnapshot(urlSubstr) {
    if (!urlSubstr) return this.snapshots[this.snapshots.length - 1];
    const needle = urlSubstr.toLowerCase();
    for (let i = this.snapshots.length - 1; i >= 0; i -= 1) {
      const snap = this.snapshots[i];
      if (snap?.url.toLowerCase().includes(needle)) return snap;
    }
    return undefined;
  }

  clear() {
    this.requests.clear();
    this.endpoints.clear();
    this.snapshots.length = 0;
    this.burpTasks.length = 0;
    this.burpIssues.clear();
    this.outboundActions.length = 0;
  }

  ingestBurpTask(raw) {
    if (!raw || typeof raw !== 'object') return { ok: false, reason: 'not an object' };
    const obj = raw;
    const action = obj.action;
    if (action !== 'scan' && action !== 'plan' && action !== 'scope') {
      return { ok: false, reason: 'action must be scan, plan, or scope' };
    }
    const task = {
      id: `burp-task-${this.nextSeq++}`,
      action,
      target: typeof obj.target === 'string' ? obj.target : undefined,
      method: typeof obj.method === 'string' ? obj.method : undefined,
      url: typeof obj.url === 'string' ? obj.url : undefined,
      host: typeof obj.host === 'string' ? obj.host : undefined,
      rawRequestB64: typeof obj.rawRequestB64 === 'string' ? obj.rawRequestB64 : undefined,
      notes: typeof obj.notes === 'string' ? obj.notes : undefined,
      source: 'burp',
      createdAt: Date.now(),
    };
    this.burpTasks.push(task);
    if (this.burpTasks.length > 1000) this.burpTasks.splice(0, this.burpTasks.length - 1000);
    this.lastActivityAt = Date.now();
    return { ok: true, task };
  }

  listBurpTasks() {
    return [...this.burpTasks].reverse();
  }

  ingestBurpIssue(raw) {
    if (!raw || typeof raw !== 'object') return { ok: false, reason: 'not an object' };
    const obj = raw;
    const title = typeof obj.title === 'string' ? obj.title : '';
    const url = typeof obj.url === 'string' ? obj.url : '';
    const detail = typeof obj.detail === 'string' ? obj.detail : '';
    if (!title || !url || !detail) return { ok: false, reason: 'title, url, and detail required' };
    const issue = {
      id: typeof obj.id === 'string' ? obj.id : `burp-issue-${this.nextSeq++}`,
      title,
      severity: typeof obj.severity === 'string' ? obj.severity : 'Information',
      confidence: typeof obj.confidence === 'string' ? obj.confidence : 'Tentative',
      url,
      method: typeof obj.method === 'string' ? obj.method : undefined,
      parameter: typeof obj.parameter === 'string' ? obj.parameter : undefined,
      detail,
      remediation: typeof obj.remediation === 'string' ? obj.remediation : undefined,
      path: typeof obj.path === 'string' ? obj.path : undefined,
      rawRequestB64: typeof obj.rawRequestB64 === 'string' ? obj.rawRequestB64 : undefined,
      rawResponseB64: typeof obj.rawResponseB64 === 'string' ? obj.rawResponseB64 : undefined,
      createdAt: typeof obj.createdAt === 'number' ? obj.createdAt : Date.now(),
    };
    this._upsertBurpIssue(issue);
    this.lastActivityAt = Date.now();
    return { ok: true, issue };
  }

  addBurpIssue(issue) {
    this._upsertBurpIssue({
      ...issue,
      id: issue.id ?? `pf-finding-${this.nextSeq++}`,
      createdAt: issue.createdAt ?? Date.now(),
    });
    this.lastActivityAt = Date.now();
  }

  listBurpIssues() {
    return [...this.burpIssues.values()].reverse();
  }

  _upsertBurpIssue(issue) {
    this.burpIssues.set(issue.id, issue);
    if (this.burpIssues.size > 1000) {
      const drop = this.burpIssues.size - 1000;
      let i = 0;
      for (const k of this.burpIssues.keys()) {
        if (i++ >= drop) break;
        this.burpIssues.delete(k);
      }
    }
  }

  _recordEndpoint(method, url, body, queryParamsHint) {
    const noQuery = this._urlNoQuery(url);
    const key = `${method} ${noQuery}`;
    let rec = this.endpoints.get(key);
    if (rec) {
      this.endpoints.delete(key);
    } else {
      rec = {
        method,
        url: noQuery,
        queryParams: new Set(),
        bodyParams: new Set(),
        hitCount: 0,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
      };
    }
    this.endpoints.set(key, rec);
    rec.hitCount += 1;
    rec.lastSeen = Date.now();
    const qp = queryParamsHint ?? this._queryParams(url);
    for (const q of qp) {
      if (rec.queryParams.size >= MAX_PARAMS_PER_ENDPOINT) break;
      rec.queryParams.add(q);
    }
    for (const b of this._bodyParamNames(body)) {
      if (rec.bodyParams.size >= MAX_PARAMS_PER_ENDPOINT) break;
      rec.bodyParams.add(b);
    }
    this._pruneEndpointsIfNeeded();
  }

  _pruneEndpointsIfNeeded() {
    if (this.endpoints.size <= MAX_ENDPOINTS) return;
    const drop = this.endpoints.size - MAX_ENDPOINTS;
    let i = 0;
    for (const k of this.endpoints.keys()) {
      if (i++ >= drop) break;
      this.endpoints.delete(k);
    }
  }

  _urlNoQuery(url) {
    try {
      const u = new URL(url);
      return `${u.origin}${u.pathname}`;
    } catch {
      const i = url.indexOf('?');
      return i >= 0 ? url.slice(0, i) : url;
    }
  }

  _queryParams(url) {
    try {
      const u = new URL(url);
      return [...u.searchParams.keys()];
    } catch {
      return [];
    }
  }

  _bodyParamNames(body) {
    if (!body) return [];
    if (typeof body === 'object') {
      const obj = body;
      if (obj.type === 'form' && obj.data && typeof obj.data === 'object') {
        return Object.keys(obj.data);
      }
      if (obj.type === 'raw' && typeof obj.data === 'string') {
        return this._parseRawBody(obj.data);
      }
      return Object.keys(obj);
    }
    if (typeof body === 'string') return this._parseRawBody(body);
    return [];
  }

  _parseRawBody(raw) {
    const trimmed = raw.trim();
    if (!trimmed) return [];
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          return Object.keys(parsed);
        }
      } catch { /* fall through */ }
    }
    if (trimmed.includes('=')) {
      try {
        return [...new URLSearchParams(trimmed).keys()];
      } catch { return []; }
    }
    return [];
  }

  _coerceHeaders(v) {
    if (!v) return undefined;
    if (Array.isArray(v)) {
      const out = [];
      for (const item of v) {
        if (item && typeof item === 'object') {
          const o = item;
          if (typeof o.name === 'string') {
            out.push({ name: o.name, value: typeof o.value === 'string' ? o.value : '' });
          }
        } else if (Array.isArray(item) && item.length === 2) {
          out.push({ name: String(item[0]), value: String(item[1]) });
        } else if (typeof item === 'string') {
          const i = item.indexOf(':');
          if (i > 0) out.push({ name: item.slice(0, i).trim(), value: item.slice(i + 1).trim() });
        }
      }
      return out.length ? out : undefined;
    }
    if (typeof v === 'object') {
      return Object.entries(v).map(([name, value]) => ({
        name,
        value: typeof value === 'string' ? value : String(value),
      }));
    }
    return undefined;
  }

  _coerceStringMap(v) {
    if (!v || typeof v !== 'object') return undefined;
    const out = {};
    for (const [k, val] of Object.entries(v)) {
      out[k] = typeof val === 'string' ? val : String(val);
    }
    return out;
  }

  _pruneIfNeeded() {
    if (this.requests.size <= this.maxEntries) return;
    const drop = this.requests.size - this.maxEntries;
    let i = 0;
    for (const k of this.requests.keys()) {
      if (i++ >= drop) break;
      this.requests.delete(k);
    }
  }

  _capBody(value) {
    if (typeof value === 'string') return this._capString(value);
    if (!value || typeof value !== 'object') return value;
    if (Array.isArray(value)) return value.map(v => this._capBody(v));
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = this._capBody(item);
    }
    return out;
  }

  _capString(value) {
    if (value.length <= BODY_STRING_CAP) return value;
    return `${value.slice(0, BODY_STRING_CAP)}...<truncated ${value.length - BODY_STRING_CAP} chars>`;
  }
}

// ──────────────────────────────────────────────
// HTTP Ingest Server
// ──────────────────────────────────────────────

const MAX_BODY_BYTES = 4 * 1024 * 1024;

function startIngestServer(store, port, token) {
  const host = '127.0.0.1';
  const server = createServer((req, res) => handleHttp(req, res, store, token));

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const addr = server.address();
      const boundPort = addr && typeof addr === 'object' && 'port' in addr ? addr.port : port;
      const url = `http://${host}:${boundPort}`;
      console.error(`[burp-mcp] ingest server listening at ${url}`);
      resolve({
        port: boundPort,
        host,
        url,
        token,
        close: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}

function handleHttp(req, res, store, token) {
  const rawHost = req.headers.host;
  if (rawHost) {
    const host = rawHost.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase();
    if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
      sendJSON(res, 403, { ok: false, error: 'invalid host' });
      return;
    }
  }

  const origin = req.headers.origin;
  if (typeof origin === 'string' && origin.startsWith('chrome-extension://')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Pentesterflow-Source, X-Pentesterflow-Token');

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  const header = req.headers['x-pentesterflow-token'];
  const headerToken = Array.isArray(header) ? (header[0] ?? '') : (header ?? '');
  if (headerToken) {
    const ab = Buffer.from(headerToken);
    const bb = Buffer.from(token);
    const authorized = ab.length === bb.length && timingSafeEqual(ab, bb);
    if (!authorized) {
      sendJSON(res, 401, { ok: false, error: 'unauthorized' });
      return;
    }
  }

  const parsedURL = new URL(req.url ?? '/', 'http://127.0.0.1');
  const url = parsedURL.pathname;

  if (req.method === 'GET' && (url === '/' || url === '/status')) {
    sendJSON(res, 200, { ok: true, ...store.status() });
    return;
  }

  if (req.method === 'GET' && url === '/endpoints') {
    sendJSON(res, 200, store.listEndpoints());
    return;
  }

  if (req.method === 'GET' && url === '/requests') {
    sendJSON(res, 200, store.listRequests({ limit: 500 }));
    return;
  }

  if (req.method === 'GET' && url === '/burp/tasks') {
    sendJSON(res, 200, store.listBurpTasks());
    return;
  }

  if (req.method === 'GET' && url === '/burp/issues') {
    sendJSON(res, 200, store.listBurpIssues());
    return;
  }

  if (req.method === 'GET' && url === '/burp/outbound') {
    sendJSON(res, 200, store.drainOutboundActions());
    return;
  }

  if (req.method === 'DELETE' && url === '/clear') {
    store.clear();
    sendJSON(res, 200, { ok: true });
    return;
  }

  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.end('method not allowed');
    return;
  }

  if (url === '/burp/outbound') {
    const actions = store.drainOutboundActions();
    sendJSON(res, 200, actions);
    return;
  }

  if (!['/ingest', '/snapshot', '/burp/task', '/burp/issues'].includes(url)) {
    res.statusCode = 404;
    res.end('not found');
    return;
  }

  readBody(req).then((body) => {
    let parsed;
    try {
      parsed = JSON.parse(body);
    } catch {
      sendJSON(res, 400, { ok: false, error: 'invalid JSON' });
      return;
    }
    let result;
    if (url === '/snapshot') result = store.ingestSnapshot(parsed);
    else if (url === '/burp/task') result = store.ingestBurpTask(parsed);
    else if (url === '/burp/issues') result = store.ingestBurpIssue(parsed);
    else result = store.ingest(parsed);

    if (!result.ok) {
      sendJSON(res, 400, { ok: false, error: result.reason });
      return;
    }
    sendJSON(res, 202, { ok: true });
  }).catch((err) => {
    console.error('[burp-mcp] ingest error:', err.message);
    res.statusCode = 400;
    res.end('bad request');
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJSON(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(payload));
}

// ──────────────────────────────────────────────
// MCP Server
// ──────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  let port = 9999;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port') port = parseInt(args[++i], 10) || 9999;
    if (args[i] === '--help' || args[i] === '-h') {
      console.error(`Burp MCP Server for OpenCode

Usage: node src/index.js [options]

Options:
  --port <n>    HTTP ingest server port (default: 9999)
  --help        Show this help

Register in opencode.json:
  "mcp": {
    "burp": {
      "type": "local",
      "command": ["node", "/path/to/oh-my-open-pentest/packages/burp-mcp/src/index.js"]
    }
  }

The burp-mcp package is bundled with oh-my-open-pentest.
After install, the plugin is at:
  packages/burp-mcp/plugin/pentesterflow_burp.py

Load it in Burp: Extensions -> Add -> Python, then select pentesterflow_burp.py.
On Windows + WSL, copy the file from WSL to Windows Downloads/ first.

Auto-register during install:
  oh-my-open-pentest install --burp
`);
      process.exit(0);
    }
  }

  const token = randomBytes(16).toString('hex');
  const store = new CaptureStore(5000);

  // Start HTTP ingest server
  let ingestHandle;
  try {
    ingestHandle = await startIngestServer(store, port, token);
    console.error(`[burp-mcp] Burp bridge URL: ${ingestHandle.url}`);
    console.error(`[burp-mcp] Auth token: ${token}`);
  } catch (err) {
    console.error(`[burp-mcp] failed to start ingest server on :${port}: ${err.message}`);
    process.exit(1);
  }

  const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');

  const mcp = new McpServer({
    name: 'burp-bridge',
    version: '1.0.0',
  });

  // ── MCP Tools (using Zod raw shapes for params) ──

  mcp.tool(
    'burp_status',
    'Show Burp bridge connection status and store statistics (requests, tasks, issues captured). Call first to confirm bridge is running.',
    {},
    async () => {
      const s = store.status();
      return {
        content: [{ type: 'text', text: JSON.stringify({
          connected: true,
          ingestUrl: ingestHandle ? `${ingestHandle.url}/ingest` : null,
          requests: s.requestCount,
          endpoints: s.endpointCount,
          snapshots: s.snapshotCount,
          burpTasks: s.burpTaskCount,
          burpIssues: s.burpIssueCount,
          lastActivityAt: s.lastActivityAt ? new Date(s.lastActivityAt).toISOString() : 'never',
        }, null, 2) }],
      };
    },
  );

  mcp.tool(
    'burp_requests',
    'List recent HTTP requests captured from Burp (most-recent first). Returns id, method, url, and status for each captured request.',
    {
      url_contains: z.string().optional().describe('Filter to requests whose URL contains this substring'),
      method: z.string().optional().describe('Filter to a single HTTP method (GET, POST, PUT, etc.)'),
      limit: z.number().int().min(1).max(500).optional().describe('Maximum number to return (default 50)'),
    },
    async (input) => {
      const requested = Math.min(Math.max(1, input.limit ?? 50), 500);
      const rows = store.listRequests({
        urlSubstr: input.url_contains || undefined,
        method: input.method || undefined,
        limit: requested,
      });
      if (rows.length === 0) return { content: [{ type: 'text', text: 'No matching requests captured.' }] };
      const slim = rows.map((r) => ({
        id: r.id,
        method: r.method,
        url: r.url,
        status: r.status,
        type: r.type,
        elapsedMs: r.elapsedMs,
        receivedAt: new Date(r.receivedAt).toISOString(),
      }));
      return { content: [{ type: 'text', text: JSON.stringify(slim, null, 2) }] };
    },
  );

  mcp.tool(
    'burp_request_detail',
    'Fetch full details for one captured request: headers, request body, and response body (when available). Pass the id from burp_requests.',
    {
      id: z.string().describe('Request id from burp_requests output'),
      body_max_chars: z.number().int().min(0).optional().describe('Cap for response body excerpt (default 4000)'),
    },
    async (input) => {
      if (!input.id) return { content: [{ type: 'text', text: 'error: id is required' }], isError: true };
      const r = store.getRequest(input.id);
      if (!r) return { content: [{ type: 'text', text: `error: no request with id ${input.id}` }], isError: true };
      const cap = input.body_max_chars ?? 4000;
      const trimmed = {
        ...r,
        responseBody: r.responseBody && r.responseBody.length > cap
          ? `${r.responseBody.slice(0, cap)}...<truncated ${r.responseBody.length - cap} chars>`
          : r.responseBody,
        receivedAt: new Date(r.receivedAt).toISOString(),
      };
      return { content: [{ type: 'text', text: JSON.stringify(trimmed, null, 2) }] };
    },
  );

  mcp.tool(
    'burp_endpoints',
    'List unique endpoints (METHOD + path) observed from Burp traffic, with query/body parameter names and hit counts. Helps identify attack surface.',
    {
      url_contains: z.string().optional().describe('Filter to endpoints whose URL contains this substring'),
      method: z.string().optional().describe('Filter to a single HTTP method'),
    },
    async (input) => {
      const eps = store.listEndpoints({
        urlSubstr: input.url_contains || undefined,
        method: input.method || undefined,
      });
      if (eps.length === 0) {
        return { content: [{ type: 'text', text: 'No endpoints captured yet. Send requests from Burp context menu.' }] };
      }
      return { content: [{ type: 'text', text: JSON.stringify(eps, null, 2) }] };
    },
  );

  mcp.tool(
    'burp_tasks',
    'List scan / plan / scope tasks queued from the Burp extension. Use these to decide what to analyze next.',
    {},
    async () => {
      const tasks = store.listBurpTasks();
      if (tasks.length === 0) return { content: [{ type: 'text', text: 'No Burp tasks queued.' }] };
      return { content: [{ type: 'text', text: JSON.stringify(tasks.map(t => ({
        ...t,
        createdAt: new Date(t.createdAt).toISOString(),
      })), null, 2) }] };
    },
  );

  mcp.tool(
    'burp_issues',
    'List security findings/issues queued for Burp import. These are confirmed findings that can be imported as Burp Scanner issues.',
    {},
    async () => {
      const issues = store.listBurpIssues();
      if (issues.length === 0) return { content: [{ type: 'text', text: 'No issues queued for Burp import.' }] };
      return { content: [{ type: 'text', text: JSON.stringify(issues.map(i => ({
        ...i,
        rawRequestB64: i.rawRequestB64 ? `<${i.rawRequestB64.length} bytes base64>` : undefined,
        rawResponseB64: i.rawResponseB64 ? `<${i.rawResponseB64.length} bytes base64>` : undefined,
        createdAt: new Date(i.createdAt).toISOString(),
      })), null, 2) }] };
    },
  );

  mcp.tool(
    'burp_import_issue',
    'Submit a confirmed finding as a Burp-importable issue. The issue will appear in the bridge and can be pulled into Burp via the PentesterFlow Burp plugin.',
    {
      title: z.string().describe('Finding title (e.g., "SQL Injection in login parameter")'),
      severity: z.string().optional().describe('Severity: Critical, High, Medium, Low, Information'),
      url: z.string().describe('Full URL where the finding was discovered'),
      detail: z.string().describe('Detailed description of the finding with impact'),
      method: z.string().optional().describe('HTTP method (GET, POST, etc.)'),
      parameter: z.string().optional().describe('Affected parameter name'),
      remediation: z.string().optional().describe('How to fix the issue'),
      rawRequestB64: z.string().optional().describe('Base64-encoded raw HTTP request for Burp replay'),
      rawResponseB64: z.string().optional().describe('Base64-encoded raw HTTP response'),
    },
    async (input) => {
      if (!input.title || !input.url || !input.detail) {
        return { content: [{ type: 'text', text: 'error: title, url, and detail are required' }], isError: true };
      }
      store.addBurpIssue({
        id: `finding:${Date.now()}`,
        title: input.title,
        severity: input.severity || 'Information',
        url: input.url,
        detail: input.detail,
        method: input.method || undefined,
        parameter: input.parameter || undefined,
        remediation: input.remediation || undefined,
        rawRequestB64: input.rawRequestB64 || undefined,
        rawResponseB64: input.rawResponseB64 || undefined,
      });
      return { content: [{ type: 'text', text: `Issue "${input.title}" submitted successfully. Import in Burp via PentesterFlow tab -> Import Issues.` }] };
    },
  );

  mcp.tool(
    'burp_snapshot',
    'Return the most recent session snapshot (cookies, localStorage, sessionStorage). Useful for constructing authenticated requests.',
    {
      url_contains: z.string().optional().describe('Most recent snapshot whose URL contains this substring'),
    },
    async (input) => {
      const snap = store.latestSnapshot(input.url_contains || undefined);
      if (!snap) return { content: [{ type: 'text', text: 'No snapshots captured yet.' }] };
      return { content: [{ type: 'text', text: JSON.stringify({ ...snap, receivedAt: new Date(snap.receivedAt).toISOString() }, null, 2) }] };
    },
  );

  mcp.tool(
    'burp_send_to_burp',
    'Queue an action for execution in Burp Suite. The next time the Burp plugin polls, it will execute the action. Supports: send_to_repeater (open Repeater tab with a request), add_scan_issue (add scan issue to Burp), console_log (write to Burp output tab).',
    {
      type: z.enum(['send_to_repeater', 'add_scan_issue', 'console_log']).describe('Action type: send_to_repeater opens a Repeater tab; add_scan_issue adds a Scanner issue; console_log writes to Burp output'),
      host: z.string().optional().describe('Target host (required for send_to_repeater)'),
      port: z.number().int().optional().describe('Target port (required for send_to_repeater, e.g. 443)'),
      https: z.boolean().optional().describe('Use HTTPS (required for send_to_repeater)'),
      raw_request_b64: z.string().optional().describe('Base64-encoded raw HTTP request (required for send_to_repeater)'),
      tab_name: z.string().optional().describe('Tab caption in Repeater (optional, for send_to_repeater)'),
      title: z.string().optional().describe('Issue title (required for add_scan_issue)'),
      severity: z.string().optional().describe('Severity: Critical, High, Medium, Low, Information'),
      url: z.string().optional().describe('Finding URL (required for add_scan_issue)'),
      detail: z.string().optional().describe('Finding description (required for add_scan_issue)'),
      message: z.string().optional().describe('Message text (required for console_log)'),
    },
    async (input) => {
      if (!input.type) {
        return { content: [{ type: 'text', text: 'error: type is required' }], isError: true };
      }
      if (input.type === 'send_to_repeater') {
        if (!input.host || !input.port || !input.raw_request_b64) {
          return { content: [{ type: 'text', text: 'error: send_to_repeater requires host, port, and raw_request_b64' }], isError: true };
        }
      }
      if (input.type === 'add_scan_issue') {
        if (!input.title || !input.url || !input.detail) {
          return { content: [{ type: 'text', text: 'error: add_scan_issue requires title, url, and detail' }], isError: true };
        }
      }
      const entry = store.addOutboundAction(input.type, {
        host: input.host,
        port: input.port,
        https: input.https,
        rawRequestB64: input.raw_request_b64,
        tabName: input.tab_name,
        title: input.title,
        severity: input.severity || 'Medium',
        url: input.url,
        detail: input.detail,
        message: input.message,
      });
      return { content: [{ type: 'text', text: JSON.stringify({ ok: true, actionId: entry.id, type: entry.type }, null, 2) }] };
    },
  );

  mcp.tool(
    'burp_outbound_status',
    'List pending outbound actions queued for the Burp plugin to execute. Actions remain here until the Burp plugin polls and drains them.',
    {},
    async () => {
      const actions = store.listOutboundActions();
      if (actions.length === 0) return { content: [{ type: 'text', text: 'No pending outbound actions.' }] };
      return { content: [{ type: 'text', text: JSON.stringify(actions.map(a => ({
        ...a,
        createdAt: new Date(a.createdAt).toISOString(),
      })), null, 2) }] };
    },
  );

  mcp.tool(
    'burp_clear',
    'Clear all captured requests, endpoints, tasks, and issues from the bridge store.',
    {},
    async () => {
      store.clear();
      return { content: [{ type: 'text', text: 'Burp bridge store cleared.' }] };
    },
  );

  // Connect via stdio transport
  const transport = new StdioServerTransport();
  console.error('[burp-mcp] connecting MCP transport (stdio)...');
  await mcp.connect(transport);
  console.error('[burp-mcp] MCP server ready. Burp bridge running.');

  // Keep alive - wait forever (process exits via signals)
  return new Promise(() => {});
}

main().catch((err) => {
  console.error('[burp-mcp] fatal:', err.message);
  process.exit(1);
});
