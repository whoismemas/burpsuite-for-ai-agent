// Burp Suite MCP server for OpenCode
// Provides an HTTP bridge for Burp to push traffic to, and MCP tools
// for the OpenCode agent to query captured requests, tasks, and issues.
//
// Usage: node src/index.js [--port 9999]
//
// Burp plugin (burpAI.py) sends traffic to the HTTP bridge.
// OpenCode queries the store via MCP tools over stdio.

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { z } from 'zod';

// ──────────────────────────────────────────────
// Capture Store (in-memory, bounded)
// ──────────────────────────────────────────────

const MAX_ENDPOINTS = 2000;
const MAX_PARAMS_PER_ENDPOINT = 256;
const BODY_STRING_CAP = 64 * 1024;

class CaptureStore {
  constructor(maxEntries = 5000, dbPath = null) {
    this.requests = new Map();
    this.endpoints = new Map();
    this.snapshots = [];
    this.burpTasks = [];
    this.burpIssues = new Map();
    this.outboundActions = [];
    this.scanResults = [];
    this.scanIdSeq = 0;
    this.maxEntries = Math.max(100, maxEntries);
    this.nextSeq = 1;
    this.lastActivityAt = 0;
    this._dbPath = dbPath;
    this._saveTimer = null;

    if (dbPath) this._load();
  }

  ingest(raw) {
    if (!raw || typeof raw !== 'object') return { ok: false, reason: 'not an object' };
    const obj = raw;
    const kind = typeof obj.kind === 'string' ? obj.kind : undefined;

    if (kind === 'ws-open' || kind === 'ws-send' || kind === 'ws-recv') {
      this._recordEndpoint('WS', obj.url || '', undefined, undefined);
      this.lastActivityAt = Date.now();
      this._scheduleSave();
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
    this._scheduleSave();
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
    this._scheduleSave();
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
    this._scheduleSave();
    return entry;
  }

  drainOutboundActions() {
    const actions = this.outboundActions;
    this.outboundActions = [];
    this._scheduleSave();
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
    this.scanResults.length = 0;
    this.scanIdSeq = 0;
    this._scheduleSave();
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
    this._scheduleSave();
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
    this._scheduleSave();
    return { ok: true, issue };
  }

  addBurpIssue(issue) {
    this._upsertBurpIssue({
      ...issue,
      id: issue.id ?? `pf-finding-${this.nextSeq++}`,
      createdAt: issue.createdAt ?? Date.now(),
    });
    this.lastActivityAt = Date.now();
    this._scheduleSave();
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

  // ── Scan Results ──

  addScanResult(entry) {
    this.scanResults.push(entry);
    if (this.scanResults.length > 200) this.scanResults.splice(0, this.scanResults.length - 200);
    if (entry.findings && entry.findings.length) {
      for (const f of entry.findings) {
        this._upsertBurpIssue({
          id: `scan:${entry.id}:${f.templateId ?? f.name}`,
          title: `[${f.severity}] ${f.name}`,
          severity: f.severity,
          url: f.matchedAt ?? entry.url,
          detail: f.description ?? f.info ?? '',
          rawRequestB64: f.request ? Buffer.from(f.request).toString('base64') : undefined,
          rawResponseB64: f.response ? Buffer.from(f.response).toString('base64') : undefined,
          createdAt: Date.now(),
        });
      }
    }
    this.lastActivityAt = Date.now();
    this._scheduleSave();
  }

  listScanResults() {
    return this.scanResults.map(r => ({
      ...r,
      findings: r.findings.map(f => ({ ...f, request: undefined, response: undefined })),
    })).reverse();
  }

  getScanResult(id) {
    return this.scanResults.find(r => r.id === id);
  }

  // ── Persistence ──

  _saveSync() {
    if (!this._dbPath) return;
    try {
      const data = {
        requests: [...this.requests.entries()],
        endpoints: [...this.endpoints.entries()].map(([k, v]) => {
          const { queryParams, bodyParams, ...rest } = v;
          return [k, { ...rest, queryParams: [...queryParams], bodyParams: [...bodyParams] }];
        }),
        snapshots: this.snapshots,
        burpTasks: this.burpTasks,
        burpIssues: [...this.burpIssues.entries()],
        scanResults: this.scanResults,
        scanIdSeq: this.scanIdSeq,
        nextSeq: this.nextSeq,
        lastActivityAt: this.lastActivityAt,
      };
      writeFileSync(this._dbPath, JSON.stringify(data), 'utf8');
    } catch (err) {
      console.error(`[burp-mcp] save error: ${err.message}`);
    }
  }

  _load() {
    if (!this._dbPath || !existsSync(this._dbPath)) return;
    try {
      const raw = readFileSync(this._dbPath, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data.requests)) {
        this.requests = new Map(data.requests);
      }
      if (Array.isArray(data.endpoints)) {
        this.endpoints = new Map(
          data.endpoints.map(([k, v]) => [
            k,
            { ...v, queryParams: new Set(v.queryParams ?? []), bodyParams: new Set(v.bodyParams ?? []) },
          ]),
        );
      }
      if (Array.isArray(data.snapshots)) this.snapshots = data.snapshots;
      if (Array.isArray(data.burpTasks)) this.burpTasks = data.burpTasks;
      if (Array.isArray(data.burpIssues)) this.burpIssues = new Map(data.burpIssues);
      if (Array.isArray(data.scanResults)) this.scanResults = data.scanResults;
      if (typeof data.scanIdSeq === 'number') this.scanIdSeq = data.scanIdSeq;
      if (typeof data.nextSeq === 'number') this.nextSeq = data.nextSeq;
      if (typeof data.lastActivityAt === 'number') this.lastActivityAt = data.lastActivityAt;
    } catch (err) {
      console.error(`[burp-mcp] load error: ${err.message}, starting fresh`);
    }
  }

  _scheduleSave() {
    if (!this._dbPath) return;
    if (this._saveTimer) clearTimeout(this._saveTimer);
    this._saveTimer = setTimeout(() => {
      this._saveTimer = null;
      this._saveSync();
    }, 500);
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
// Nuclei Scanner
// ──────────────────────────────────────────────

function checkNuclei() {
  return new Promise((resolve) => {
    const proc = spawn('nuclei', ['-version'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 5000,
    });
    proc.on('close', (code) => resolve(code === 0));
    proc.on('error', () => resolve(false));
  });
}

function runNucleiScan(url, options = {}) {
  return new Promise((resolve) => {
    const {
      templates,
      severity,
      timeout,
      rateLimit,
      retries,
    } = options;

    const args = ['-u', url, '-json', '-silent'];
    if (templates) args.push('-t', templates);
    if (severity) args.push('-severity', severity);
    if (timeout) args.push('-timeout', String(timeout));
    if (rateLimit) args.push('-rate-limit', String(rateLimit));
    if (retries) args.push('-retries', String(retries));

    const findings = [];
    const startTime = Date.now();
    let stderr = '';

    const proc = spawn('nuclei', args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 120_000,
    });

    proc.stdout.on('data', (chunk) => {
      const lines = chunk.toString('utf8').split('\n').filter(Boolean);
      for (const line of lines) {
        try {
          findings.push(JSON.parse(line));
        } catch { /* skip unparseable lines */ }
      }
    });

    proc.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });

    proc.on('close', (code) => {
      resolve({
        findings,
        elapsedMs: Date.now() - startTime,
        exitCode: code,
        stderr: stderr.slice(0, 2000),
      });
    });

    proc.on('error', (err) => {
      resolve({
        findings: [],
        elapsedMs: Date.now() - startTime,
        exitCode: -1,
        stderr: err.message,
      });
    });
  });
}

// ──────────────────────────────────────────────
// HTTP Ingest Server
// ──────────────────────────────────────────────

const MAX_BODY_BYTES = 4 * 1024 * 1024;

function startIngestServer(store, preferredPort, token) {
  const host = '127.0.0.1';

  function tryListen(port) {
    return new Promise((resolve, reject) => {
      const server = createServer((req, res) => handleHttp(req, res, store, token));
      server.once('error', (err) => { server.close(); reject(err); });
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

  return tryListen(preferredPort).catch(() => tryListen(0));
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-BurpAI-Source, X-BurpAI-Token');

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  const header = req.headers['x-burpai-token'];
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
  let dbPath = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port') port = parseInt(args[++i], 10) || 9999;
    if (args[i] === '--db') dbPath = args[++i];
    if (args[i] === '--help' || args[i] === '-h') {
      console.error(`Burp MCP Server for OpenCode

Usage: node src/index.js [options]

Options:
  --port <n>    HTTP ingest server port (default: 9999)
  --db <path>   Data persistence file (default: burpai-data.json in cwd)
  --help        Show this help

Register in opencode.json (.mcp.json):
  "mcpServers": {
    "burp": {
      "type": "local",
      "command": ["node", "/absolute/path/to/burpsuite-for-ai-agent/src/index.js"]
    }
  }

Plugin file:
  plugin/burpAI.py

Load in Burp: Extensions -> Add -> Python, then select burpAI.py.
On Windows + WSL, copy the file from WSL to Windows Downloads/ first.
`);
      process.exit(0);
    }
  }

  if (!dbPath) dbPath = `${process.cwd()}/burpai-data.json`;

  const token = randomBytes(16).toString('hex');
  const store = new CaptureStore(5000, dbPath);

  // Graceful shutdown: save before exit
  const shutdown = () => {
    console.error('[burp-mcp] shutting down, saving data...');
    store._saveSync();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // Start HTTP ingest server (auto-find port if preferred is taken)
  const ingestHandle = await startIngestServer(store, port, token);
  console.error(`[burp-mcp] Burp bridge URL: ${ingestHandle.url}`);
  console.error(`[burp-mcp] Auth token: ${token}`);
  console.error(`[burp-mcp]`);
  console.error(`[burp-mcp] ── SETUP ──`);
  console.error(`[burp-mcp] Burp plugin URL: ${ingestHandle.url}`);
  console.error(`[burp-mcp] .mcp.json command: ["node", "${process.argv[1]}", "--port", "${ingestHandle.port}"]`);
  console.error(`[burp-mcp] ─────────────────`);
  console.error(`[burp-mcp]`);

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
    'Submit a confirmed finding as a Burp-importable issue. The issue will appear in the bridge and can be pulled into Burp via the burpAI Burp plugin.',
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
      return { content: [{ type: 'text', text: `Issue "${input.title}" submitted successfully. Import in Burp via burpAI tab -> Import Issues.` }] };
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
    'burp_replay',
    'Modify a captured request and send it to Burp Repeater. Agent specifies which parameter to inject — the modified request opens in Burp Repeater where Burp executes the HTTP call and the response auto-forwards back to the bridge.',
    {
      request_id: z.string().describe('Request id from burp_requests output'),
      set_method: z.string().optional().describe('Override HTTP method'),
      set_path: z.string().optional().describe('Override URL path + query (e.g. /api/login?user=admin)'),
      set_header: z.string().optional().describe('Add or override a header. Format: "Header-Name: value"'),
      remove_header: z.string().optional().describe('Remove a header by name (case-insensitive)'),
      set_body: z.string().optional().describe('Replace request body entirely'),
      tab_name: z.string().optional().describe('Tab label in Burp Repeater (default: "burpAI replay")'),
    },
    async (input) => {
      if (!input.request_id) {
        return { content: [{ type: 'text', text: 'error: request_id is required' }], isError: true };
      }
      const orig = store.getRequest(input.request_id);
      if (!orig) {
        return { content: [{ type: 'text', text: `error: no request with id ${input.request_id}` }], isError: true };
      }

      // Get original host/port/protocol from URL
      let u;
      try { u = new URL(orig.url); } catch {
        return { content: [{ type: 'text', text: 'error: original request URL is malformed' }], isError: true };
      }
      const host = orig.requestHeaders?.find(h => h.name?.toLowerCase() === 'host')?.value ?? u.host;
      const hostname = host.split(':')[0];
      const port = u.port ? parseInt(u.port, 10) : (u.protocol === 'https:' ? 443 : 80);
      const https = u.protocol === 'https:';

      // Build modified HTTP request
      const method = input.set_method ?? orig.method ?? 'GET';
      const path = input.set_path || (u.pathname + u.search) || '/';
      const body = input.set_body ?? orig.requestBody ?? '';

      // Collect headers
      const headerLines = [`${method} ${path} HTTP/1.1`];
      const removeHdr = (input.remove_header ?? '').toLowerCase();
      const setHdrRaw = input.set_header ?? '';
      let setHdrApplied = false;

      const origHeaders = orig.requestHeaders ?? [];
      for (const h of origHeaders) {
        const hName = h.name?.trim() ?? '';
        if (!hName) continue;
        if (hName.toLowerCase() === removeHdr) continue;
        if (setHdrRaw && hName.toLowerCase() === setHdrRaw.split(':')[0]?.trim().toLowerCase()) {
          headerLines.push(setHdrRaw);
          setHdrApplied = true;
          continue;
        }
        headerLines.push(`${hName}: ${h.value ?? ''}`);
      }
      if (setHdrRaw && !setHdrApplied) headerLines.push(setHdrRaw);
      headerLines.push(`Host: ${host}`);
      headerLines.push('Connection: close');
      if (body) {
        const hasCL = origHeaders.some(h => h.name?.toLowerCase() === 'content-length');
        if (!hasCL && !setHdrRaw?.toLowerCase().startsWith('content-length')) {
          headerLines.push(`Content-Length: ${Buffer.byteLength(body, 'utf8')}`);
        }
      }

      const raw = headerLines.join('\r\n') + '\r\n\r\n' + body;
      const rawB64 = Buffer.from(raw).toString('base64');

      store.addOutboundAction('send_to_repeater', {
        host: hostname,
        port,
        https,
        rawRequestB64: rawB64,
        tabName: input.tab_name || 'burpAI replay',
      });

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: true,
            sent_to: 'Burp Repeater',
            host: hostname,
            port,
            https,
            tab: input.tab_name || 'burpAI replay',
            method,
            path,
            headers: headerLines.length,
            bodyLength: body.length,
            modified_request: raw.slice(0, 2000),
          }, null, 2),
        }],
      };
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

  // ── Scan Tools ──

  mcp.tool(
    'burp_scan_url',
    'Run nuclei scan against a single URL. Returns findings with severity, name, and matched details. High/Critical findings are auto-imported as Burp issues.',
    {
      url: z.string().describe('Full URL to scan (e.g. https://target.com/api/login)'),
      templates: z.string().optional().describe('Nuclei template filter (e.g. "cves,misconfig" or path to custom .yaml)'),
      severity: z.string().optional().describe('Minimum severity: info, low, medium, high, critical (default: low)'),
      timeout: z.number().int().optional().describe('Request timeout per template in seconds (default: 10)'),
      rate_limit: z.number().int().optional().describe('Max requests per second (default: 150)'),
      retries: z.number().int().optional().describe('Retry count per request (default: 1)'),
    },
    async (input) => {
      const hasNuclei = await checkNuclei();
      if (!hasNuclei) {
        return { content: [{ type: 'text', text: 'nuclei not found. Install: https://docs.projectdiscovery.io/tools/nuclei/install' }], isError: true };
      }
      const result = await runNucleiScan(input.url, {
        templates: input.templates,
        severity: input.severity || 'low',
        timeout: input.timeout,
        rateLimit: input.rate_limit,
        retries: input.retries,
      });
      const scanEntry = {
        id: ++store.scanIdSeq,
        url: input.url,
        type: 'nuclei',
        startedAt: Date.now() - result.elapsedMs,
        finishedAt: Date.now(),
        elapsedMs: result.elapsedMs,
        exitCode: result.exitCode,
        findings: result.findings.map(f => ({
          templateId: f['template-id'] ?? '',
          name: f.name ?? f.info?.name ?? 'unknown',
          severity: f.severity ?? 'unknown',
          description: f.description ?? f.info?.description ?? '',
          matchedAt: f['matched-at'] ?? input.url,
          extractedResults: f['extracted-results'] ?? [],
          curlCommand: f['curl-command'] ?? '',
          tags: (f['template-id'] ?? '').split('-'),
          request: f.request ?? '',
          response: f.response ?? '',
        })),
        stderr: result.stderr || undefined,
      };
      store.addScanResult(scanEntry);
      const findings = scanEntry.findings.map(f => ({
        templateId: f.templateId,
        severity: f.severity,
        name: f.name,
        matchedAt: f.matchedAt,
      }));
      const summary = {
        scanId: scanEntry.id,
        url: input.url,
        total: scanEntry.findings.length,
        elapsedMs: result.elapsedMs,
        exitCode: result.exitCode,
        findings,
      };
      return { content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }] };
    },
  );

  mcp.tool(
    'burp_scan_bulk',
    'Run nuclei scan against all unique endpoints from captured traffic. Capped at 25 URLs to avoid excessive load.',
    {
      severity: z.string().optional().describe('Minimum severity filter'),
      templates: z.string().optional().describe('Nuclei template filter'),
      max_urls: z.number().int().optional().describe('Maximum URLs to scan (default: 25)'),
    },
    async (input) => {
      const hasNuclei = await checkNuclei();
      if (!hasNuclei) {
        return { content: [{ type: 'text', text: 'nuclei not found. Install: https://docs.projectdiscovery.io/tools/nuclei/install' }], isError: true };
      }
      const eps = store.listEndpoints({});
      const urls = [...new Set(eps.map(e => e.url))].slice(0, input.max_urls ?? 25);
      if (urls.length === 0) {
        return { content: [{ type: 'text', text: 'No endpoints in store to scan.' }] };
      }
      const results = [];
      for (const url of urls) {
        const result = await runNucleiScan(url, {
          templates: input.templates,
          severity: input.severity || 'low',
        });
        const scanEntry = {
          id: ++store.scanIdSeq,
          url,
          type: 'nuclei',
          startedAt: Date.now() - result.elapsedMs,
          finishedAt: Date.now(),
          elapsedMs: result.elapsedMs,
          exitCode: result.exitCode,
          findings: result.findings.map(f => ({
            templateId: f['template-id'] ?? '',
            name: f.name ?? f.info?.name ?? 'unknown',
            severity: f.severity ?? 'unknown',
            description: f.description ?? f.info?.description ?? '',
            matchedAt: f['matched-at'] ?? url,
            extractedResults: f['extracted-results'] ?? [],
            curlCommand: f['curl-command'] ?? '',
            tags: (f['template-id'] ?? '').split('-'),
            request: f.request ?? '',
            response: f.response ?? '',
          })),
          stderr: result.stderr || undefined,
        };
        store.addScanResult(scanEntry);
        results.push({
          scanId: scanEntry.id,
          url,
          findings: scanEntry.findings.length,
          elapsedMs: result.elapsedMs,
          exitCode: result.exitCode,
        });
      }
      return { content: [{ type: 'text', text: JSON.stringify({ scanned: urls.length, results }, null, 2) }] };
    },
  );

  mcp.tool(
    'burp_scan_results',
    'List previous nuclei scan runs with finding counts. Use burp_issues to see auto-imported findings.',
    {
      scan_id: z.number().int().optional().describe('Return detail for a specific scan ID'),
    },
    async (input) => {
      if (input.scan_id) {
        const detail = store.getScanResult(input.scan_id);
        if (!detail) return { content: [{ type: 'text', text: `No scan found with id ${input.scan_id}` }], isError: true };
        return { content: [{ type: 'text', text: JSON.stringify(detail, null, 2) }] };
      }
      const list = store.listScanResults().map(r => ({
        scanId: r.id,
        url: r.url,
        type: r.type,
        findings: r.findings.length,
        elapsedMs: r.elapsedMs,
        exitCode: r.exitCode,
        finishedAt: new Date(r.finishedAt).toISOString(),
      }));
      if (list.length === 0) return { content: [{ type: 'text', text: 'No scans performed yet.' }] };
      return { content: [{ type: 'text', text: JSON.stringify(list, null, 2) }] };
    },
  );

  mcp.tool(
    'burp_scan_import_all',
    'Manually import all nuclei findings from a specific scan as Burp issues. By default, High/Critical findings are auto-imported; use this for lower severity findings.',
    {
      scan_id: z.number().int().optional().describe('Scan ID to import findings from. If omitted, imports from all scans.'),
      min_severity: z.string().optional().describe('Minimum severity to import: info, low, medium, high, critical (default: info)'),
    },
    async (input) => {
      const sevOrder = ['info', 'low', 'medium', 'high', 'critical'];
      const minSev = input.min_severity ? sevOrder.indexOf(input.min_severity.toLowerCase()) : 0;
      let imported = 0;
      const scans = input.scan_id ? [store.getScanResult(input.scan_id)].filter(Boolean) : store.scanResults;
      for (const scan of scans) {
        for (const f of scan.findings) {
          const fSevIdx = sevOrder.indexOf(f.severity?.toLowerCase() ?? '');
          if (fSevIdx < minSev) continue;
          store.addBurpIssue({
            id: `scan-manual:${scan.id}:${f.templateId ?? f.name}`,
            title: `[${f.severity}] ${f.name}`,
            severity: f.severity,
            url: f.matchedAt ?? scan.url,
            detail: f.description || f.info || '',
            rawRequestB64: f.request ? Buffer.from(f.request).toString('base64') : undefined,
            createdAt: Date.now(),
          });
          imported++;
        }
      }
      return { content: [{ type: 'text', text: `Imported ${imported} finding(s) as Burp issues. Use burp_issues to list them, then Burp plugin -> Import Issues to push into Burp.` }] };
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
