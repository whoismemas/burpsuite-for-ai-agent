<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=600&size=28&duration=3000&pause=500&color=FF6633&center=true&vCenter=true&width=500&lines=Burp+Suite+for+AI+Agent;MCP+Bridge+%2B+Jython+Plugin" alt="Typing SVG" />
</p>

<p align="center">
  <b>Two-way Burp Suite MCP bridge — AI agents capture traffic, analyze endpoints, queue scans, and send findings back to Burp.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js_18%2B-339933?style=flat&logo=nodedotjs&logoColor=white" />
  <img src="https://img.shields.io/badge/Burp_Jython_2.7-FF6633?style=flat&logo=burpsuite&logoColor=white" />
  <img src="https://img.shields.io/github/license/whoismemas/burpsuite-for-ai-agent" />
</p>

---

## 📁 Structure

```
burpsuite-for-ai-agent/
├── src/
│   └── index.js          ← MCP server (HTTP bridge + 11 MCP tools)
├── plugin/
│   └── burpAI.py         ← Jython 2.7 Burp plugin (context menu, auto-forward, outbound polling)
├── package.json          ← Node.js manifest (dependencies: @modelcontextprotocol/sdk, zod)
├── .gitignore
└── README.md
```

---

## Architecture

```
Burp Suite (Linux / Windows)
  └─ plugin/burpAI.py (Jython plugin)
       │  POST /ingest (127.0.0.1:9999)
       │  GET /burp/outbound (poll every 2s)
       ▼
src/index.js  ← MCP server (HTTP bridge + 11 MCP tools)
       │
       ▼
AI Agent ←→ MCP tools
```

**Linux**: Burp + server + agent — all on one machine.
**Windows + WSL**: Burp on Windows, server + agent in WSL over localhost.

---

## Quick Start

### 1. Start MCP server

```bash
npm install
node src/index.js
```

### 2. Load Burp plugin

1. Burp Suite → **Extensions** → **Installed** → **Add**
2. Extension type: `Python` (requires Jython 2.7 standalone JAR)
3. File: `plugin/burpAI.py`

### 3. Verify

In Burp's **burpAI** tab, click **Check Status**. Connected:
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

### Capture → Analyze
Right-click a request in Burp (Proxy/Repeater) → `burpAI: send request(s)`

Agent:
- `burp_requests` — list captured requests
- `burp_endpoints` — enumerate endpoints
- `burp_request_detail` — full request/response

### Queue scan → Execute
Right-click → `burpAI: send + queue scan`  
Agent picks up via `burp_tasks`.

### Finding → Burp Scanner
Agent calls `burp_import_issue` → Burp tab → **Import Issues**

### Agent → Burp Repeater
Agent calls `burp_send_to_burp` with type `send_to_repeater` → Burp opens Repeater tab.

---

## Auto-Forwarding

| Feature | Description |
|---------|-------------|
| Auto-send Proxy responses | All Proxy traffic sent to MCP server |
| Auto-send Repeater responses | Repeater traffic automatically forwarded |
| Forward Burp Scanner issues | Scanner findings pushed to agent |
| Auto import issues | Pull agent findings on context menu |

---

## Options

```bash
node src/index.js --port 9999     # Custom port (default: 9999)
```

Burp plugin URL configurable from the burpAI settings tab in Burp.

---

## Requirements

- **Node.js 18+**
- **Burp Suite** (Community or Professional)
- **Jython 2.7** standalone JAR (configured in Burp Extensions → Environment)

---

<p align="center">
  <i>Built for AI-assisted penetration testing.</i>
  <br />
  <samp>#burpsuite #mcp #pentest #bugbounty</samp>
</p>
