<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=600&size=24&duration=3000&pause=500&color=FF6633&center=true&vCenter=true&width=500&lines=Burp+Suite+for+AI+Agent;MCP+Bridge+%2B+Jython+Plugin;Two-Way+Burp+Control" alt="Typing SVG" />
</p>

<p align="center">
  <b>Burp Suite MCP bridge — let AI agents capture traffic, analyze endpoints, queue scan tasks, and send findings back to Burp.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/runtime-Node.js_18%2B-339933?style=flat&logo=nodedotjs" />
  <img src="https://img.shields.io/badge/Burp-Jython_2.7-FF6633?style=flat&logo=burpsuite" />
  <img src="https://img.shields.io/badge/license-MIT-blue" />
  <img src="https://img.shields.io/badge/MCP-server-000000?style=flat" />
</p>

---

## Architecture

```
Burp Suite (Linux / Windows)
  └─ plugin/burpAI.py (Jython plugin)
       │  HTTP POST /ingest (127.0.0.1:9999)
       │  GET /burp/outbound (poll every 2s)
       ▼
src/index.js  ← MCP server (HTTP bridge + 11 MCP tools)
       │
       ▼
AI Agent ←→ MCP tools
```

**Linux**: Burp + server + agent — all on one machine.
**Windows + WSL**: Burp on Windows, server + agent in WSL. Communication over localhost.

---

## Quick Start

### 1. Install MCP server

```bash
npm install
node src/index.js
```

### 2. Load Burp plugin

1. Burp Suite → **Extensions** → **Installed** → **Add**
2. Extension type: `Python` (requires Jython 2.7)
3. File: `plugin/burpAI.py`

### 3. Verify

In Burp's **burpAI** tab, click **Check Status**. Should show:
```json
{ "ok": true, "requests": 0, "endpoints": 0 }
```

---

## MCP Tools (11 tools)

| Tool | Description |
|------|-------------|
| `burp_status` | Bridge connection status + store statistics |
| `burp_requests` | List captured HTTP requests (filter by url/method) |
| `burp_request_detail` | Full request/response (headers, body) |
| `burp_endpoints` | Unique endpoints with parameter names, hit counts |
| `burp_tasks` | Scan/plan/scope tasks queued from Burp context menu |
| `burp_issues` | Security findings queued for Burp import |
| `burp_import_issue` | Submit a finding (title, url, severity, detail) |
| `burp_snapshot` | Latest session snapshot (cookies, storage) |
| `burp_send_to_burp` | Queue action: send_to_repeater, add_scan_issue, console_log |
| `burp_outbound_status` | Pending outbound actions |
| `burp_clear` | Clear all captured data |

---

## Workflow

### Capture traffic
Right-click a request in Burp (Proxy/Repeater) → `burpAI: send request(s)`

Then ask the agent:
- `"burp_requests — show me what we captured"`
- `"burp_endpoints — list all endpoints"`
- `"burp_request_detail — get full details on request X"`

### Queue scan tasks
Right-click → `burpAI: send + queue scan`
Agent picks it up via `burp_tasks`.

### Send findings back to Burp
Agent calls `burp_import_issue` → then in Burp: burpAI tab → **Import Issues**

### Send requests to Repeater
Agent calls `burp_send_to_burp` with type `send_to_repeater` → Burp opens a Repeater tab automatically.

---

## Auto-forwarding

In the burpAI tab, enable:
- **Auto-send Proxy responses** — all Proxy traffic sent to MCP server
- **Auto-send Repeater responses** — Repeater traffic automatically forwarded
- **Forward Burp Scanner issues** — scanner findings pushed to agent
- **Auto import issues on click actions** — pull agent findings on context menu

---

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `9999` | HTTP ingest server port |

```bash
node src/index.js --port 9999
```

The Burp plugin URL is configurable from the burpAI settings tab.

---

## Requirements

- **Node.js 18+**
- **Burp Suite** (Community or Professional)
- **Jython 2.7** standalone JAR (configured in Burp Extensions → Environment)

---

<p align="center">
  <i>Built for AI-driven penetration testing workflows.</i>
  <br />
  <samp>#burpsuite #mcp #pentest #ai #bugbounty</samp>
</p>
