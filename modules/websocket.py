"""
OXHUNTER - websocket.py
WebSocket Security Testing
"""

import json
import time
from typing import Dict, List, Optional

try:
    import websocket as ws_lib
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><svg onload=alert(1)>",
]
SQLI_PAYLOADS = ["' OR 1=1--", "\" OR \"1\"=\"1", "' AND SLEEP(5)--"]
PROTO_PAYLOADS = [
    '{"__proto__":{"admin":true}}',
    '{"constructor":{"prototype":{"admin":true}}}',
]


class WebSocketTester:

    def __init__(self, timeout: int = 10, proxy: Optional[str] = None):
        self.timeout = timeout
        self.proxy   = proxy

    def _check_lib(self) -> bool:
        if not WS_AVAILABLE:
            print("[!] Install: pip install websocket-client")
            return False
        return True

    # ── Connect Test ──────────────────────────

    def test_connection(self, url: str) -> Dict:
        if not self._check_lib():
            return {"error": "websocket-client not installed"}
        result = {"url": url, "connectable": False, "error": None}
        try:
            conn = ws_lib.create_connection(url, timeout=self.timeout)
            result["connectable"] = True
            conn.close()
        except Exception as e:
            result["error"] = str(e)
        return result

    # ── Auth Check ────────────────────────────

    def test_auth(self, url: str) -> Dict:
        """Check if WS endpoint requires authentication."""
        if not self._check_lib():
            return {}
        result = {"auth_required": False, "detail": ""}
        try:
            conn = ws_lib.create_connection(url, timeout=self.timeout)
            conn.send(json.dumps({"action": "getUser", "token": "invalid_token_test"}))
            resp = conn.recv()
            conn.close()
            body = resp.lower()
            if any(k in body for k in ["unauthorized","forbidden","invalid token","auth"]):
                result["auth_required"] = True
                result["detail"] = "Auth enforced"
            else:
                result["detail"] = f"No auth check — response: {resp[:100]}"
        except Exception as e:
            result["detail"] = str(e)
        return result

    # ── Injection Tests ───────────────────────

    def _send_recv(self, url: str, payload: str) -> Optional[str]:
        try:
            conn = ws_lib.create_connection(url, timeout=self.timeout)
            conn.send(payload)
            resp = conn.recv()
            conn.close()
            return resp
        except Exception:
            return None

    def test_xss(self, url: str) -> List[Dict]:
        findings = []
        for p in XSS_PAYLOADS:
            resp = self._send_recv(url, json.dumps({"msg": p}))
            if resp and p in resp:
                findings.append({"type": "xss", "severity": "HIGH",
                                 "payload": p, "reflected": True})
        return findings

    def test_sqli(self, url: str) -> List[Dict]:
        findings = []
        for p in SQLI_PAYLOADS:
            t0   = time.time()
            resp = self._send_recv(url, json.dumps({"query": p}))
            elapsed = time.time() - t0
            if elapsed >= 5:
                findings.append({"type": "sqli_timebased", "severity": "CRITICAL",
                                 "payload": p, "delay": round(elapsed, 2)})
            elif resp and any(e in resp.lower() for e in ["sql","syntax","mysql","error"]):
                findings.append({"type": "sqli_error", "severity": "HIGH",
                                 "payload": p})
        return findings

    def test_prototype_pollution(self, url: str) -> List[Dict]:
        findings = []
        for p in PROTO_PAYLOADS:
            resp = self._send_recv(url, p)
            if resp and "admin" in resp.lower():
                findings.append({"type": "prototype_pollution", "severity": "HIGH",
                                 "payload": p, "response": resp[:100]})
        return findings

    def test_origin(self, url: str) -> Dict:
        """Check if server validates Origin header."""
        if not self._check_lib():
            return {}
        try:
            conn = ws_lib.create_connection(
                url, timeout=self.timeout,
                header=["Origin: https://evil.attacker.com"])
            conn.close()
            return {"vulnerable": True, "severity": "MEDIUM",
                    "detail": "Server accepted cross-origin WebSocket connection"}
        except Exception as e:
            return {"vulnerable": False, "detail": str(e)}

    # ── Full Scan ─────────────────────────────

    def scan(self, url: str) -> Dict:
        if not self._check_lib():
            return {"error": "websocket-client not installed"}

        conn    = self.test_connection(url)
        if not conn.get("connectable"):
            return {"url": url, "error": conn.get("error"), "findings": []}

        findings = []
        findings += self.test_xss(url)
        findings += self.test_sqli(url)
        findings += self.test_prototype_pollution(url)

        origin = self.test_origin(url)
        if origin.get("vulnerable"):
            findings.append({**origin, "type": "cors_websocket"})

        return {"url": url, "connectable": True,
                "total": len(findings), "findings": findings}
