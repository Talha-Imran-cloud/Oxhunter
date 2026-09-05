"""
OXHUNTER - proxy.py
Proxy Support: Burp Suite, Custom Proxy, Rotation
"""

import requests
import random
from typing import Optional, List, Dict


# ─────────────────────────────────────────────
#  PROXY PRESETS
# ─────────────────────────────────────────────
BURP_PROXY    = "http://127.0.0.1:8080"
ZAP_PROXY     = "http://127.0.0.1:8090"
MITMPROXY     = "http://127.0.0.1:8082"


class ProxyManager:
    """Manage single proxy, proxy rotation, and Burp integration."""

    def __init__(self, proxy: Optional[str] = None, proxy_list: Optional[List[str]] = None):
        self.proxy       = proxy
        self.proxy_list  = proxy_list or []
        self._index      = 0
        self._fail_count : Dict[str, int] = {}

    # ── Setup ─────────────────────────────────

    def use_burp(self) -> "ProxyManager":
        self.proxy = BURP_PROXY
        return self

    def use_zap(self) -> "ProxyManager":
        self.proxy = ZAP_PROXY
        return self

    def use_custom(self, proxy_url: str) -> "ProxyManager":
        self.proxy = proxy_url
        return self

    def load_list(self, proxies: List[str]) -> "ProxyManager":
        """Load proxy rotation list."""
        self.proxy_list = proxies
        return self

    def load_from_file(self, filepath: str) -> "ProxyManager":
        """Load proxies from file (one per line)."""
        try:
            with open(filepath) as f:
                self.proxy_list = [l.strip() for l in f if l.strip()]
        except Exception as e:
            print(f"[!] Proxy file error: {e}")
        return self

    # ── Get Proxy ─────────────────────────────

    def get(self) -> Optional[Dict]:
        """Return proxy dict for requests session."""
        p = self._pick()
        if not p:
            return None
        return {"http": p, "https": p}

    def _pick(self) -> Optional[str]:
        """Pick next proxy (rotation or single)."""
        if self.proxy_list:
            # Round-robin
            p = self.proxy_list[self._index % len(self.proxy_list)]
            self._index += 1
            return p
        return self.proxy

    def random(self) -> Optional[Dict]:
        """Return random proxy from list."""
        if not self.proxy_list:
            return self.get()
        p = random.choice(self.proxy_list)
        return {"http": p, "https": p}

    # ── Apply to Session ──────────────────────

    def apply(self, session: requests.Session) -> requests.Session:
        """Apply proxy to requests session."""
        proxies = self.get()
        if proxies:
            session.proxies.update(proxies)
        return session

    # ── Test Proxy ────────────────────────────

    def test(self, proxy: Optional[str] = None, test_url: str = "http://httpbin.org/ip") -> Dict:
        """Test if proxy is working."""
        p = proxy or self.proxy
        if not p:
            return {"working": False, "error": "No proxy set"}
        try:
            resp = requests.get(
                test_url,
                proxies={"http": p, "https": p},
                timeout=8, verify=False
            )
            return {"working": True, "proxy": p, "status": resp.status_code, "ip": resp.json().get("origin", "")}
        except Exception as e:
            self._fail_count[p] = self._fail_count.get(p, 0) + 1
            return {"working": False, "proxy": p, "error": str(e)}

    def test_all(self) -> List[Dict]:
        """Test all proxies in list."""
        return [self.test(p) for p in self.proxy_list]

    def healthy(self) -> List[str]:
        """Return only working proxies from list."""
        return [r["proxy"] for r in self.test_all() if r.get("working")]

    # ── Info ──────────────────────────────────

    def info(self) -> Dict:
        return {
            "active_proxy" : self.proxy,
            "pool_size"    : len(self.proxy_list),
            "failures"     : self._fail_count,
        }

    def __repr__(self):
        return f"<ProxyManager proxy={self.proxy} pool={len(self.proxy_list)}>"


# ─────────────────────────────────────────────
#  QUICK FACTORY
# ─────────────────────────────────────────────
def burp() -> ProxyManager:
    return ProxyManager().use_burp()

def zap() -> ProxyManager:
    return ProxyManager().use_zap()

def from_list(proxies: List[str]) -> ProxyManager:
    return ProxyManager(proxy_list=proxies)

def from_file(path: str) -> ProxyManager:
    return ProxyManager().load_from_file(path)
