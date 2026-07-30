# burpAI — Burp Suite AI Agent Bridge

You have access to **burpai MCP tools** that connect to a running Burp Suite instance. These tools let you analyze captured HTTP traffic, modify requests, send them to Burp Repeater, run nuclei scans, and import security findings.

## Available MCP Tools

### Capture & Analysis
- **burp_status** — Check bridge connection + store statistics
- **burp_requests** — List captured HTTP requests (filter by url/method)
- **burp_request_detail** — Full request detail: headers, body, response
- **burp_endpoints** — Unique endpoints with parameter names and hit counts
- **burp_tasks** — Tasks queued from Burp context menu (scan/plan/scope)
- **burp_snapshot** — Latest session snapshot (cookies, storage)

### Agent-Driven Scanning (core feature)
- **burp_replay** — Take a captured request, modify it (method/path/headers/body), and send to Burp Repeater. Burp executes the actual HTTP call, and the response auto-forwards back to you.
- **burp_send_to_burp** — Queue raw action: send_to_repeater, add_scan_issue, console_log

### External Scanning (nuclei)
- **burp_scan_url** — Run nuclei scan against a URL
- **burp_scan_bulk** — Scan all captured endpoints
- **burp_scan_results** — List previous scan results
- **burp_scan_import_all** — Import nuclei findings as Burp issues

### Findings
- **burp_issues** — List security findings queued for Burp import
- **burp_import_issue** — Submit a finding (title, url, severity, detail)

### Management
- **burp_outbound_status** — Pending actions waiting for Burp
- **burp_clear** — Clear all captured data

## Workflow: Agent-Driven Scanner

This is the primary pentest workflow. The goal: **Burp captures real traffic (already logged in, no WAF) → you analyze → you modify → Burp executes.**

```
1. burp_status → confirm bridge is connected
2. burp_requests → see what requests have been captured
   (or user right-clicks in Burp → send to burpAI)
3. burp_request_detail → examine the interesting request
4. burp_replay → modify request (change body, headers, etc.)
   → opens in Burp Repeater → user clicks Send → response auto-forwards
5. burp_request_detail → read the response
6. Loop: modify payload → replay → analyze
7. burp_import_issue → submit finding if vulnerable
```

### Example: Testing SQL Injection

```
User: "Ada request /api/login, coba injection"
1. burp_requests({method: "POST"}) → find request
2. burp_request_detail({id: "burp:burp-12345"}) → see body:
   {"username":"admin","password":"test"}
3. burp_replay({
     request_id: "burp:burp-12345",
     set_body: '{"username":"admin\\' OR 1=1--","password":"x"}'
   })
   → Burp Repeater tab opens → user clicks Send
4. burp_request_detail → check response for SQL error
5. If not vulnerable → try NoSQLi, SSTI, etc. → burp_replay again
6. If vulnerable → burp_import_issue({...})
```

### Key Principles

- **Burp executes, not you.** You tell Burp what to send via burp_replay. Burp handles auth, session, certificates, and WAF avoidance.
- **Auto-forward must be enabled.** In Burp → burpAI tab, check "Auto-send Repeater responses" so responses come back to you automatically.
- **You think of payloads.** burp_replay is a tool — you decide what to inject based on context.
- **Loop is the strategy.** Inject → analyze → refine → inject again. Each iteration gets deeper.
