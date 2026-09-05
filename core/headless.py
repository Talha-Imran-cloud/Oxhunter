"""
OXHUNTER - headless.py
Headless Browser Mode via Playwright — Screenshots + DOM XSS + JS rendering
"""

from typing import Dict, List, Optional
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright, Page, Browser
    PW_AVAILABLE = True
except ImportError:
    PW_AVAILABLE = False

SCREENSHOT_DIR = Path("reports/screenshots")


def _check() -> bool:
    if not PW_AVAILABLE:
        print("[!] Install: pip install playwright && playwright install chromium")
        return False
    return True


class HeadlessBrowser:

    def __init__(self, proxy: Optional[str] = None,
                 timeout: int = 15000, headless: bool = True):
        self.proxy    = {"server": proxy} if proxy else None
        self.timeout  = timeout
        self.headless = headless
        self._pw      = None
        self._browser : Optional[Browser] = None
        SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    def start(self):
        if not _check(): return
        self._pw      = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=self.headless,
            proxy=self.proxy,
            args=["--no-sandbox","--disable-dev-shm-usage"],
        )

    def stop(self):
        if self._browser: self._browser.close()
        if self._pw:      self._pw.stop()

    def _page(self, cookies: List[Dict] = None) -> Page:
        ctx  = self._browser.new_context(ignore_https_errors=True)
        if cookies:
            ctx.add_cookies(cookies)
        page = ctx.new_page()
        page.set_default_timeout(self.timeout)
        return page

    # ── Screenshot ────────────────────────────

    def screenshot(self, url: str, filename: str = "") -> str:
        """Take full-page screenshot, return file path."""
        if not _check(): return ""
        page = self._page()
        try:
            page.goto(url, wait_until="networkidle")
            name = filename or url.replace("://","_").replace("/","_")[:50] + ".png"
            path = str(SCREENSHOT_DIR / name)
            page.screenshot(path=path, full_page=True)
            return path
        except Exception as e:
            print(f"[!] Screenshot error: {e}")
            return ""
        finally:
            page.close()

    # ── DOM XSS Detection ─────────────────────

    def test_dom_xss(self, url: str, payloads: List[str] = None) -> List[Dict]:
        """Inject XSS payloads and detect DOM execution via dialog/console."""
        if not _check(): return []
        default = ["<img src=x onerror=alert('OXHUNTER')>",
                   "<svg onload=alert('OXHUNTER')>",
                   "javascript:alert('OXHUNTER')"]
        payloads = payloads or default
        findings = []

        for payload in payloads:
            page     = self._page()
            triggered = []
            page.on("dialog", lambda d, t=triggered: (t.append(d.message), d.dismiss()))  # BUG-005 FIX: capture by default arg
            try:
                page.goto(f"{url}?q={payload}", wait_until="domcontentloaded")
                page.wait_for_timeout(2000)
                if triggered:
                    findings.append({"type": "dom_xss", "severity": "HIGH",
                                     "payload": payload, "url": url,
                                     "detail": f"Alert triggered: {triggered[0]}"})
            except Exception:
                pass
            finally:
                page.close()

        return findings

    # ── JS Form Discovery ─────────────────────

    def get_forms(self, url: str) -> List[Dict]:
        """Extract all forms + inputs from JS-rendered page."""
        if not _check(): return []
        page = self._page()
        try:
            page.goto(url, wait_until="networkidle")
            return page.evaluate("""() => {
                return [...document.forms].map(f => ({
                    action : f.action,
                    method : f.method,
                    inputs : [...f.elements].map(i => ({
                        name: i.name, type: i.type, value: i.value
                    }))
                }))
            }""")
        except Exception:
            return []
        finally:
            page.close()

    # ── Network Requests Capture ──────────────

    def capture_requests(self, url: str) -> Dict:
        """Capture all network requests made by page (API endpoints discovery)."""
        if not _check(): return {}
        page     = self._page()
        requests = []
        page.on("request", lambda r: requests.append({
            "url": r.url, "method": r.method,
            "type": r.resource_type,
        }))
        try:
            page.goto(url, wait_until="networkidle")
            page.wait_for_timeout(2000)
            apis = [r for r in requests if r["type"] in ["xhr","fetch"]]
            return {"total": len(requests), "api_calls": apis, "all": requests}
        except Exception:
            return {}
        finally:
            page.close()

    # ── Evidence Screenshot ───────────────────

    def capture_evidence(self, url: str, vuln_type: str,
                         payload: str = "") -> Dict:
        """Take screenshot as evidence for a finding."""
        page = self._page()
        try:
            page.goto(url, wait_until="domcontentloaded")
            if payload:
                page.wait_for_timeout(1500)
            fname = f"{vuln_type}_{url.split('//')[-1][:30]}.png"
            path  = str(SCREENSHOT_DIR / fname)
            page.screenshot(path=path, full_page=True)
            return {"screenshot": path, "url": url, "vuln_type": vuln_type}
        except Exception as e:
            return {"error": str(e)}
        finally:
            page.close()

    # ── Full Scan ─────────────────────────────

    def scan(self, url: str) -> Dict:
        dom_xss  = self.test_dom_xss(url)
        forms    = self.get_forms(url)
        network  = self.capture_requests(url)
        shot     = self.screenshot(url)
        return {
            "url"       : url,
            "screenshot": shot,
            "dom_xss"   : dom_xss,
            "forms"     : forms,
            "api_calls" : network.get("api_calls", []),
            "findings"  : dom_xss,
        }

    def __enter__(self):
        self.start(); return self

    def __exit__(self, *args):
        self.stop()
