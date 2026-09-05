"""
OXHUNTER - business_logic.py
Business Logic Testing Templates
"""

import time
import requests
import urllib3
from typing import Dict, List, Optional
urllib3.disable_warnings()


class BusinessLogicTester:

    def __init__(self, session: Optional[requests.Session] = None, timeout: int = 10):
        self.s       = session or requests.Session()
        self.timeout = timeout

    def _get(self, url: str, **kw) -> Optional[requests.Response]:
        try:
            return self.s.get(url, timeout=self.timeout, verify=False, **kw)
        except Exception:
            return None

    def _post(self, url: str, **kw) -> Optional[requests.Response]:
        try:
            return self.s.post(url, timeout=self.timeout, verify=False, **kw)
        except Exception:
            return None

    # ── 1. Price Manipulation ─────────────────

    def test_price_manipulation(self, checkout_url: str,
                                 product_id: str) -> List[Dict]:
        """Test negative/zero/float price tampering."""
        findings = []
        for price in ["0", "-1", "0.001", "0.00", "-99999"]:
            r = self._post(checkout_url, data={"product_id": product_id, "price": price})
            if r and r.status_code in [200, 302]:
                if "success" in r.text.lower() or "order" in r.text.lower():
                    findings.append({"type": "price_manipulation", "severity": "CRITICAL",
                                     "payload": f"price={price}", "url": checkout_url,
                                     "detail": f"Order placed with price={price}"})
        return findings

    # ── 2. Coupon/Promo Abuse ─────────────────

    def test_coupon_abuse(self, coupon_url: str,
                          valid_coupon: str) -> List[Dict]:
        """Test coupon reuse, stacking, and negative discount."""
        findings = []

        # Reuse same coupon multiple times
        for i in range(3):
            r = self._post(coupon_url, data={"coupon": valid_coupon})
            if r and "discount" in r.text.lower() and i > 0:
                findings.append({"type": "coupon_reuse", "severity": "HIGH",
                                 "url": coupon_url, "detail": f"Coupon reused {i+1}x"})
                break

        # Negative coupon
        r = self._post(coupon_url, data={"coupon": "-100"})
        if r and r.status_code == 200 and "error" not in r.text.lower():
            findings.append({"type": "negative_coupon", "severity": "HIGH",
                             "url": coupon_url, "payload": "coupon=-100"})
        return findings

    # ── 3. Quantity Abuse ─────────────────────

    def test_quantity_abuse(self, cart_url: str,
                             product_id: str) -> List[Dict]:
        findings = []
        for qty in ["-1", "0", "99999", "-99999"]:
            r = self._post(cart_url, data={"product_id": product_id, "quantity": qty})
            if r and r.status_code == 200 and "error" not in r.text.lower():
                findings.append({"type": "quantity_abuse", "severity": "HIGH",
                                 "payload": f"quantity={qty}", "url": cart_url,
                                 "detail": f"Accepted invalid quantity: {qty}"})
        return findings

    # ── 4. Account Enumeration ────────────────

    def test_account_enumeration(self, login_url: str,
                                  valid_user: str,
                                  invalid_user: str = "nonexistent_xyz_123") -> Dict:
        """Detect timing/message differences between valid/invalid usernames."""
        t1  = time.time()
        r1  = self._post(login_url, data={"username": valid_user,   "password": "wrong_pass_xyz"})
        t1  = time.time() - t1

        t2  = time.time()
        r2  = self._post(login_url, data={"username": invalid_user, "password": "wrong_pass_xyz"})
        t2  = time.time() - t2

        if not r1 or not r2:
            return {}

        msg_diff   = r1.text[:200] != r2.text[:200]
        time_diff  = abs(t1 - t2) > 1.0

        return {
            "type"       : "account_enumeration",
            "severity"   : "MEDIUM",
            "url"        : login_url,
            "vulnerable" : msg_diff or time_diff,
            "detail"     : f"Message diff={msg_diff}, Time diff={round(abs(t1-t2),2)}s",
        }

    # ── 5. IDOR ───────────────────────────────

    def test_idor(self, resource_url: str,
                  own_id: str, other_ids: List[str] = None) -> List[Dict]:
        """Test IDOR by accessing other users' resources."""
        findings = []
        test_ids  = other_ids or [str(int(own_id) + i) for i in [1,-1,2,-2,100]]
        own_resp  = self._get(resource_url.replace(own_id, own_id))

        for oid in test_ids:
            url  = resource_url.replace(own_id, oid)
            r    = self._get(url)
            if r and r.status_code == 200:
                if own_resp and r.text != own_resp.text:
                    findings.append({"type": "idor", "severity": "HIGH",
                                     "url": url, "accessed_id": oid,
                                     "detail": f"Accessed resource of ID {oid}"})
        return findings

    # ── 6. Rate Limit / Brute Force ──────────

    def test_rate_limit(self, url: str, method: str = "POST",
                        data: Dict = None, attempts: int = 20) -> Dict:
        """Check if endpoint rate-limits repeated requests."""
        blocked = False
        for i in range(attempts):
            r = self._post(url, data=data) if method == "POST" else self._get(url)
            if r and r.status_code in [429, 403]:
                blocked = True
                return {"type": "rate_limit_ok", "severity": "INFO",
                        "detail": f"Blocked after {i+1} attempts", "vulnerable": False}
        return {"type": "no_rate_limit", "severity": "HIGH", "url": url,
                "detail": f"No block after {attempts} attempts", "vulnerable": True}

    # ── 7. Workflow Bypass ────────────────────

    def test_workflow_bypass(self, steps: List[Dict]) -> List[Dict]:
        """
        Test if multi-step workflow can be bypassed by skipping steps.
        steps = [{"url": ..., "data": ..., "method": "POST"}, ...]
        """
        findings = []
        # Try to jump directly to last step
        last = steps[-1]
        r    = self._post(last["url"], data=last.get("data", {})) \
               if last.get("method","GET") == "POST" \
               else self._get(last["url"])

        if r and r.status_code in [200, 302]:
            if not any(k in r.text.lower() for k in ["unauthorized","forbidden","step","invalid"]):
                findings.append({"type": "workflow_bypass", "severity": "HIGH",
                                 "url": last["url"],
                                 "detail": "Final step accessible without completing prior steps"})
        return findings

    # ── Full Scan ─────────────────────────────

    def scan(self, config: Dict) -> Dict:
        """
        Run all configured business logic tests.
        config keys: checkout_url, coupon_url, cart_url,
                     login_url, resource_url, own_id
        """
        findings = []

        if config.get("checkout_url"):
            findings += self.test_price_manipulation(
                config["checkout_url"], config.get("product_id","1"))

        if config.get("coupon_url"):
            findings += self.test_coupon_abuse(
                config["coupon_url"], config.get("valid_coupon","SAVE10"))

        if config.get("cart_url"):
            findings += self.test_quantity_abuse(
                config["cart_url"], config.get("product_id","1"))

        if config.get("login_url") and config.get("valid_user"):
            enum = self.test_account_enumeration(
                config["login_url"], config["valid_user"])
            if enum.get("vulnerable"):
                findings.append(enum)

        if config.get("resource_url") and config.get("own_id"):
            findings += self.test_idor(
                config["resource_url"], config["own_id"])

        if config.get("rate_limit_url"):
            rl = self.test_rate_limit(config["rate_limit_url"])
            if rl.get("vulnerable"):
                findings.append(rl)

        return {"total": len(findings), "findings": findings}
