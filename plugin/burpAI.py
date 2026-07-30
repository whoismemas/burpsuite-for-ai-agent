# -*- coding: utf-8 -*-
# burpAI Burp Suite integration.
#
# Load in Burp: Extender -> Extensions -> Add -> Extension type: Python.
# Requires Jython 2.7.x configured in Burp.

from burp import (
    IBurpExtender,
    IContextMenuFactory,
    IHttpListener,
    IHttpRequestResponse,
    IScanIssue,
    IScannerListener,
    ITab,
)
from java.awt import BorderLayout
from java.awt.event import ActionListener
from java.net import URL
from javax.swing import JPanel, JLabel, JTextField, JButton, JCheckBox, JTextArea, JScrollPane, JMenuItem, Timer
from java.util import ArrayList
import base64
import json
import traceback

try:
    import urllib2
except ImportError:
    urllib2 = None


DEFAULT_BASE_URL = "http://127.0.0.1:9999"


class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener, IScannerListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.base_url = DEFAULT_BASE_URL
        self.auto_import_issues = False
        self.auto_send_proxy = False
        self.auto_send_repeater = False
        self.forward_scanner_issues = False
        self.imported_issue_keys = set()
        self.auto_sent_keys = set()
        self.auto_sent_order = []

        callbacks.setExtensionName("burpAI")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerListener(self)
        callbacks.addSuiteTab(self)
        self.stdout = callbacks.getStdout()
        self.stderr = callbacks.getStderr()

        self._poll_timer_on = True
        self._poll_timer = Timer(2000, _OutboundPoller(self))
        self._poll_timer.start()

        self._println("burpAI Burp extension loaded. Run MCP server: node src/index.js")

    def getTabCaption(self):
        return "burpAI"

    def getUiComponent(self):
        panel = JPanel(BorderLayout())
        top = JPanel()
        top.add(JLabel("burpAI URL:"))
        self.url_field = JTextField(self.base_url, 32)
        top.add(self.url_field)

        save = JButton("Save", actionPerformed=self._save_settings)
        status = JButton("Check Status", actionPerformed=self._check_status)
        pull = JButton("Import Issues", actionPerformed=self._import_issues)
        requests = JButton("Show Requests", actionPerformed=self._show_requests)
        tasks = JButton("Show Tasks", actionPerformed=self._show_tasks)
        clear = JButton("Clear Bridge", actionPerformed=self._clear_bridge)
        clear_log = JButton("Clear Log", actionPerformed=self._clear_log)
        self.auto_box = JCheckBox("Auto import issues on click actions")
        self.auto_proxy_box = JCheckBox("Auto-send Proxy responses")
        self.auto_repeater_box = JCheckBox("Auto-send Repeater responses")
        self.forward_scanner_box = JCheckBox("Forward Burp Scanner issues")
        top.add(save)
        top.add(status)
        top.add(pull)
        top.add(requests)
        top.add(tasks)
        top.add(clear)
        top.add(clear_log)
        top.add(self.auto_box)
        top.add(self.auto_proxy_box)
        top.add(self.auto_repeater_box)
        top.add(self.forward_scanner_box)

        self.log_area = JTextArea(12, 80)
        self.log_area.setEditable(False)
        panel.add(top, BorderLayout.NORTH)
        panel.add(JScrollPane(self.log_area), BorderLayout.CENTER)
        return panel

    def createMenuItems(self, invocation):
        items = ArrayList()
        selected = invocation.getSelectedMessages()
        if not selected:
            return items

        items.add(JMenuItem("burpAI: send request(s)", actionPerformed=lambda e: self._send_requests(selected)))
        items.add(JMenuItem("burpAI: send + queue scan", actionPerformed=lambda e: self._send_and_queue(selected, "scan")))
        items.add(JMenuItem("burpAI: send + queue /plan", actionPerformed=lambda e: self._send_and_queue(selected, "plan")))
        items.add(JMenuItem("burpAI: queue scan for request(s)", actionPerformed=lambda e: self._queue_task(selected, "scan")))
        items.add(JMenuItem("burpAI: queue /plan for request(s)", actionPerformed=lambda e: self._queue_task(selected, "plan")))
        items.add(JMenuItem("burpAI: add host/domain to scope", actionPerformed=lambda e: self._queue_task(selected, "scope")))
        items.add(JMenuItem("burpAI: import issues into Burp", actionPerformed=self._import_issues))
        items.add(JMenuItem("Burp: active scan selected request(s)", actionPerformed=lambda e: self._burp_active_scan(selected)))
        return items

    def _save_settings(self, _event):
        self.base_url = self.url_field.getText().strip().rstrip("/") or DEFAULT_BASE_URL
        self.auto_import_issues = self.auto_box.isSelected()
        self.auto_send_proxy = self.auto_proxy_box.isSelected()
        self.auto_send_repeater = self.auto_repeater_box.isSelected()
        self.forward_scanner_issues = self.forward_scanner_box.isSelected()
        self._log("settings saved: %s" % self.base_url)

    def _check_status(self, _event):
        try:
            data = self._get_json("/status")
            self._log("status: %s" % json.dumps(data))
        except Exception as exc:
            self._log_error("status failed", exc)

    def _send_requests(self, messages):
        count = 0
        for msg in messages:
            try:
                payload = self._message_to_ingest_payload(msg)
                self._post_json("/ingest", payload)
                count += 1
            except Exception as exc:
                self._log_error("send request failed", exc)
        self._log("sent %d request(s) to burpAI capture" % count)
        self._maybe_import_issues()

    def _send_and_queue(self, messages, action):
        self._send_requests(messages)
        self._queue_task(messages, action)

    def _queue_task(self, messages, action):
        count = 0
        for msg in messages:
            try:
                payload = self._message_to_task_payload(msg, action)
                self._post_json("/burp/task", payload)
                count += 1
            except Exception as exc:
                self._log_error("queue %s failed" % action, exc)
        self._log("queued %d %s task(s) for burpAI" % (count, action))
        self._maybe_import_issues()

    def _burp_active_scan(self, messages):
        count = 0
        for msg in messages:
            try:
                service = msg.getHttpService()
                req_info = self.helpers.analyzeRequest(service, msg.getRequest())
                url = req_info.getUrl()
                self.callbacks.doActiveScan(
                    service.getHost(),
                    service.getPort(),
                    service.getProtocol() == "https",
                    msg.getRequest(),
                )
                count += 1
                self._log("sent to Burp active scanner: %s" % url.toString())
            except Exception as exc:
                self._log_error("Burp active scan failed", exc)
        self._log("sent %d request(s) to Burp active scanner" % count)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        if not self._should_auto_forward(toolFlag):
            return
        if self._is_bridge_message(messageInfo):
            return
        key = self._message_key(messageInfo)
        if key in self.auto_sent_keys:
            return
        self._remember_auto_key(key)
        try:
            payload = self._message_to_ingest_payload(messageInfo)
            payload["notes"] = "Auto-forwarded from Burp listener"
            self._post_json("/ingest", payload)
            self._log("auto-sent %s %s" % (payload.get("method", ""), payload.get("url", "")))
        except Exception as exc:
            self._log_error("auto-send failed", exc)

    def newScanIssue(self, issue):
        if not self.forward_scanner_issues:
            return
        try:
            self._post_json("/burp/issues", self._scanner_issue_to_payload(issue))
            self._log("forwarded Burp Scanner issue: %s" % issue.getIssueName())
        except Exception as exc:
            self._log_error("forward scanner issue failed", exc)

    def _import_issues(self, _event=None):
        try:
            issues = self._get_json("/burp/issues")
            if not isinstance(issues, list):
                self._log("unexpected issue response: %s" % json.dumps(issues))
                return
            imported = 0
            for item in issues:
                key = self._issue_import_key(item)
                if key in self.imported_issue_keys:
                    continue
                self.callbacks.addScanIssue(burpAIIssue(item, self.helpers))
                self.imported_issue_keys.add(key)
                imported += 1
            self._log("imported %d burpAI issue(s) into Burp" % imported)
        except Exception as exc:
            self._log_error("import issues failed", exc)

    def _maybe_import_issues(self):
        if self.auto_import_issues:
            self._import_issues()

    def _issue_import_key(self, item):
        evidence = item.get("rawRequestB64", "") or item.get("detail", "")
        return "%s|%s|%s" % (item.get("id", ""), item.get("url", ""), evidence[:64])

    def _show_requests(self, _event=None):
        try:
            data = self._get_json("/requests")
            self._log("recent burpAI requests: %s" % json.dumps(data[:10]))
        except Exception as exc:
            self._log_error("show requests failed", exc)

    def _show_tasks(self, _event=None):
        try:
            data = self._get_json("/burp/tasks")
            self._log("queued burpAI tasks: %s" % json.dumps(data[:10]))
        except Exception as exc:
            self._log_error("show tasks failed", exc)

    def _clear_log(self, _event=None):
        self.log_area.setText("")

    def _clear_bridge(self, _event=None):
        try:
            self._delete("/clear")
            self.imported_issue_keys.clear()
            self.auto_sent_keys.clear()
            self.auto_sent_order = []
            self._log("cleared burpAI bridge state")
        except Exception as exc:
            self._log_error("clear bridge failed", exc)

    def _message_to_ingest_payload(self, msg):
        service = msg.getHttpService()
        request = msg.getRequest()
        response = msg.getResponse()
        req_info = self.helpers.analyzeRequest(service, request)
        url = req_info.getUrl().toString()
        method = req_info.getMethod()

        payload = {
            "kind": "burp",
            "id": "burp-%s" % str(abs(hash(url + method + str(len(request))))),
            "method": method,
            "url": url,
            "requestHeaders": self._headers(req_info.getHeaders()),
            "requestBody": self._body_to_text(request, req_info.getBodyOffset()),
            "rawRequestB64": self._b64encode(self._raw_bytes(request)),
            "source": "burp",
        }
        if response:
            resp_info = self.helpers.analyzeResponse(response)
            payload["status"] = resp_info.getStatusCode()
            payload["responseHeaders"] = self._headers(resp_info.getHeaders())
            payload["respBody"] = self._body_to_text(response, resp_info.getBodyOffset())
            payload["rawResponseB64"] = self._b64encode(self._raw_bytes(response))
        return payload

    def _message_to_task_payload(self, msg, action):
        service = msg.getHttpService()
        req_info = self.helpers.analyzeRequest(service, msg.getRequest())
        url = req_info.getUrl()
        host = service.getHost()
        payload = {
            "action": action,
            "target": url.toString() if action != "scope" else host,
            "host": host,
            "method": req_info.getMethod(),
            "url": url.toString(),
            "rawRequestB64": self._b64encode(self._raw_bytes(msg.getRequest())),
            "notes": "Queued from Burp context menu",
        }
        return payload

    def _headers(self, headers):
        out = []
        for header in headers:
            text = str(header)
            idx = text.find(":")
            if idx > 0:
                out.append({"name": text[:idx].strip(), "value": text[idx + 1:].strip()})
        return out

    def _body_to_text(self, data, offset):
        try:
            if data is None:
                return ""
            raw = self._raw_bytes(data[offset:])
            try:
                return raw.decode("utf-8", "replace")
            except AttributeError:
                return raw.encode("latin-1", "replace").decode("utf-8", "replace")
        except Exception:
            return ""

    def _raw_bytes(self, data):
        return "".join(chr((int(b) + 256) % 256) for b in data)

    def _b64encode(self, raw):
        encoded = base64.b64encode(raw)
        return encoded.decode("ascii") if hasattr(encoded, "decode") else encoded

    def _scanner_issue_to_payload(self, issue):
        url = issue.getUrl().toString()
        messages = issue.getHttpMessages()
        raw_req = None
        raw_resp = None
        method = None
        if messages and len(messages) > 0:
            first = messages[0]
            if first.getRequest():
                raw_req = self._b64encode(self._raw_bytes(first.getRequest()))
                try:
                    method = self.helpers.analyzeRequest(first.getHttpService(), first.getRequest()).getMethod()
                except Exception:
                    method = None
            if first.getResponse():
                raw_resp = self._b64encode(self._raw_bytes(first.getResponse()))
        payload = {
            "id": "burp-scanner-%s" % str(abs(hash(issue.getIssueName() + url))),
            "title": issue.getIssueName(),
            "severity": issue.getSeverity(),
            "confidence": issue.getConfidence(),
            "url": url,
            "method": method,
            "detail": issue.getIssueDetail() or issue.getIssueBackground() or "",
            "remediation": issue.getRemediationDetail() or issue.getRemediationBackground(),
        }
        if raw_req:
            payload["rawRequestB64"] = raw_req
        if raw_resp:
            payload["rawResponseB64"] = raw_resp
        return payload

    def _should_auto_forward(self, toolFlag):
        try:
            if toolFlag == self.callbacks.TOOL_PROXY:
                return self.auto_send_proxy
            if toolFlag == self.callbacks.TOOL_REPEATER:
                return self.auto_send_repeater
        except Exception:
            return False
        return False

    def _is_bridge_message(self, msg):
        try:
            service = msg.getHttpService()
            return service.getHost() in ["127.0.0.1", "localhost"] and str(service.getPort()) in self.base_url
        except Exception:
            return False

    def _message_key(self, msg):
        service = msg.getHttpService()
        req = msg.getRequest()
        info = self.helpers.analyzeRequest(service, req)
        resp = msg.getResponse()
        status = ""
        if resp:
            try:
                status = str(self.helpers.analyzeResponse(resp).getStatusCode())
            except Exception:
                status = ""
        return "%s|%s|%s|%s" % (info.getMethod(), info.getUrl().toString(), len(req), status)

    def _remember_auto_key(self, key):
        self.auto_sent_keys.add(key)
        self.auto_sent_order.append(key)
        if len(self.auto_sent_order) > 1000:
            old = self.auto_sent_order.pop(0)
            self.auto_sent_keys.discard(old)

    def _post_json(self, path, payload):
        body = json.dumps(payload).encode("utf-8")
        req = urllib2.Request(
            self.base_url + path,
            body,
            {
                "Accept": "application/json; charset=utf-8",
                "Content-Type": "application/json; charset=utf-8",
            },
        )
        res = urllib2.urlopen(req, timeout=10)
        status = res.getcode()
        text = res.read()
        if status < 200 or status >= 300:
            raise Exception(u"HTTP %s: %s" % (status, self._response_text(text)))
        return text

    def _get_json(self, path):
        res = urllib2.urlopen(self.base_url + path, timeout=10)
        text = res.read()
        return self._decode_json_response(path, text)

    def _decode_json_response(self, path, raw):
        text = self._strip_bom(self._response_text(raw)).strip()
        try:
            return json.loads(text)
        except ValueError as exc:
            # Some embedded Python/Burp environments can surface duplicated
            # response bytes or proxy/debug text after a valid JSON document.
            # `json.loads` rejects that as "Extra data"; raw_decode lets the
            # plugin import the first complete bridge response and ignore
            # trailing noise while still failing on genuinely invalid JSON.
            decoder = json.JSONDecoder()
            try:
                data, end = decoder.raw_decode(text)
                trailing = text[end:].strip()
                if trailing:
                    self._log(
                        "warning: ignored %d trailing byte(s) after JSON from %s"
                        % (len(trailing), path)
                    )
                return data
            except Exception:
                preview = text[:500].replace("\n", "\\n")
                raise Exception(
                    u"invalid JSON from %s: %s; preview=%s"
                    % (path, self._safe_unicode(exc), preview)
                )

    def _response_text(self, raw):
        if raw is None:
            return u""
        if hasattr(raw, "decode"):
            try:
                return raw.decode("utf-8-sig", "replace")
            except TypeError:
                try:
                    return raw.decode("utf-8-sig")
                except Exception:
                    return self._safe_unicode(raw)
            except Exception:
                return self._safe_unicode(raw)
        return self._safe_unicode(raw)

    def _strip_bom(self, text):
        text = self._safe_unicode(text)
        if text.startswith(u"\ufeff"):
            return text[1:]
        # Handles UTF-8 BOM bytes that were widened before decoding.
        if text.startswith(u"\xef\xbb\xbf"):
            return text[3:]
        return text

    def _safe_unicode(self, value):
        if value is None:
            return u""
        try:
            unicode_type = unicode
        except NameError:
            unicode_type = str
        try:
            if isinstance(value, unicode_type):
                return value
        except Exception:
            pass
        if hasattr(value, "decode"):
            try:
                return value.decode("utf-8-sig", "replace")
            except TypeError:
                try:
                    return value.decode("utf-8-sig")
                except Exception:
                    pass
            except Exception:
                pass
        try:
            return unicode_type(value)
        except Exception:
            try:
                return str(value).decode("utf-8", "replace")
            except Exception:
                return u"<unprintable>"

    def _delete(self, path):
        req = urllib2.Request(self.base_url + path)
        req.get_method = lambda: "DELETE"
        res = urllib2.urlopen(req, timeout=10)
        return res.read()

    def _log(self, message):
        message = self._safe_unicode(message)
        try:
            self.log_area.append(message + u"\n")
        except Exception:
            pass
        self._println(message)

    def _log_error(self, prefix, exc):
        self._log(u"%s: %s" % (self._safe_unicode(prefix), self._safe_unicode(exc)))
        try:
            traceback.print_exc(file=self.stderr)
        except Exception:
            pass

    def _println(self, message):
        message = self._safe_unicode(message)
        try:
            self.stdout.println(u"[burpAI] " + message)
        except Exception:
            try:
                self.stdout.println(("[burpAI] " + message).encode("utf-8", "replace"))
            except Exception:
                pass

    # ── Outbound action handlers ──

    def _poll_outbound(self):
        if not self._poll_timer_on:
            return
        try:
            actions = self._get_json("/burp/outbound")
        except Exception:
            return
        if not isinstance(actions, list) or len(actions) == 0:
            return
        for action in actions:
            try:
                self._execute_action(action)
            except Exception as exc:
                self._log_error("action %s failed" % action.get("id", ""), exc)

    def _execute_action(self, action):
        atype = action.get("type")
        params = action.get("params", {})
        if atype == "send_to_repeater":
            self._handle_send_to_repeater(params)
        elif atype == "add_scan_issue":
            self._handle_add_scan_issue(params)
        elif atype == "console_log":
            self._handle_console_log(params)

    def _handle_send_to_repeater(self, params):
        host = params.get("host")
        port = params.get("port")
        https = params.get("https", False)
        raw_b64 = params.get("rawRequestB64")
        tab_name = params.get("tabName", "burpAI")
        if not host or not port or not raw_b64:
            self._log("send_to_repeater: missing host, port, or rawRequestB64")
            return
        raw_bytes = base64.b64decode(raw_b64)
        self.callbacks.sendToRepeater(host, int(port), bool(https), raw_bytes, str(tab_name))
        self._log("sent request to Repeater: %s:%s" % (host, port))

    def _handle_add_scan_issue(self, params):
        url = params.get("url")
        title = params.get("title", "burpAI Finding")
        detail = params.get("detail", "")
        severity = params.get("severity", "Medium")
        if not url or not detail:
            self._log("add_scan_issue: missing url or detail")
            return
        issue_data = {
            "url": url,
            "title": title,
            "severity": severity,
            "detail": detail,
            "confidence": "Certain",
            "rawRequestB64": params.get("rawRequestB64"),
            "rawResponseB64": params.get("rawResponseB64"),
        }
        try:
            self.callbacks.addScanIssue(burpAIIssue(issue_data, self.helpers))
            self._log("added scan issue: %s - %s" % (severity, title))
        except Exception as exc:
            self._log_error("add_scan_issue failed", exc)

    def _handle_console_log(self, params):
        msg = params.get("message", "")
        if msg:
            self._println("[Agent] %s" % msg)


class _OutboundPoller(ActionListener):
    def __init__(self, ext):
        self.ext = ext

    def actionPerformed(self, e):
        self.ext._poll_outbound()


class burpAIIssue(IScanIssue):
    def __init__(self, data, helpers):
        self.data = data
        self.helpers = helpers
        self._issue_url = URL(self.data.get("url", "http://localhost/"))
        port = self._issue_url.getPort()
        if port == -1:
            port = 443 if self._issue_url.getProtocol() == "https" else 80
        self._http_service = self.helpers.buildHttpService(
            self._issue_url.getHost(),
            port,
            self._issue_url.getProtocol() == "https",
        )
        self._http_message = self._build_http_message()

    def getUrl(self):
        return self._issue_url

    def getIssueName(self):
        return self.data.get("title", "burpAI Issue")

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        sev = str(self.data.get("severity", "Information")).lower()
        mapping = {
            "critical": "High",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Information",
            "information": "Information",
        }
        return mapping.get(sev, "Information")

    def getConfidence(self):
        conf = str(self.data.get("confidence", "Tentative")).lower()
        if conf in ["certain", "firm", "tentative"]:
            return conf.title()
        return "Tentative"

    def getIssueBackground(self):
        return "Imported from burpAI confirmed findings or bridge issue queue."

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        parts = [self.data.get("detail", "")]
        if self.data.get("method"):
            parts.append("<p><b>Method:</b> %s</p>" % self.data.get("method"))
        if self.data.get("parameter"):
            parts.append("<p><b>Parameter:</b> %s</p>" % self.data.get("parameter"))
        if self.data.get("path"):
            parts.append("<p><b>burpAI report:</b> %s</p>" % self.data.get("path"))
        return "\n".join(parts)

    def getRemediationDetail(self):
        return self.data.get("remediation", None)

    def getHttpMessages(self):
        return [self._http_message] if self._http_message else None

    def getHttpService(self):
        return self._http_service

    def _build_http_message(self):
        raw_req = self._b64_to_bytes(self.data.get("rawRequestB64"))
        if not raw_req:
            raw_req = self._fallback_request()
        raw_resp = self._b64_to_bytes(self.data.get("rawResponseB64"))
        return self.callbacks_make_http_message(raw_req, raw_resp)

    def callbacks_make_http_message(self, request, response):
        return HttpRequestResponse(self._http_service, request, response)

    def _fallback_request(self):
        path = self._issue_url.getPath() or "/"
        if self._issue_url.getQuery():
            path += "?" + self._issue_url.getQuery()
        method = self.data.get("method", "GET")
        req = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: burpAI\r\n\r\n" % (
            method,
            path,
            self._issue_url.getHost(),
        )
        return self.helpers.stringToBytes(req)

    def _b64_to_bytes(self, value):
        if not value:
            return None
        try:
            return base64.b64decode(value)
        except Exception:
            return None


class HttpRequestResponse(IHttpRequestResponse):
    def __init__(self, service, request, response):
        self._service = service
        self._request = request
        self._response = response

    def getRequest(self):
        return self._request

    def setRequest(self, request):
        self._request = request

    def getResponse(self):
        return self._response

    def setResponse(self, response):
        self._response = response

    def getHttpService(self):
        return self._service

    def setHttpService(self, service):
        self._service = service

    def getComment(self):
        return "Imported from burpAI"

    def setComment(self, _comment):
        pass

    def getHighlight(self):
        return None

    def setHighlight(self, _color):
        pass
