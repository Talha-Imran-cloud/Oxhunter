"""
OXHUNTER - screenshots.py
Evidence Screenshots for vulnerability findings
"""

import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

SHOT_DIR = Path("reports/screenshots")

try:
    from playwright.sync_api import sync_playwright
    PW = True
except ImportError:
    PW = False

try:
    PIL = True
except ImportError:
    PIL = False


def _check() -> bool:
    if not PW:
        print("[!] Install: pip install playwright && playwright install chromium")
        return False
    return True


class ScreenshotCapture:

    def __init__(self, output_dir: str = str(SHOT_DIR),
                 proxy: Optional[str] = None, timeout: int = 15000):
        self.out     = Path(output_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.proxy   = {"server": proxy} if proxy else None
        self.timeout = timeout

    def _fname(self, vuln_type: str, url: str) -> str:
        ts   = datetime.now().strftime("%H%M%S")
        safe = url.split("//")[-1].replace("/","_")[:30]
        return f"{vuln_type}_{safe}_{ts}.png"

    # ── Single Screenshot ─────────────────────

    def capture(self, url: str, filename: str = "",
                cookies: List[Dict] = None,
                highlight_selector: str = "") -> Dict:
        """Capture screenshot of a URL."""
        if not _check():
            return {"error": "playwright not installed"}

        fname = filename or self._fname("page", url)
        path  = str(self.out / fname)

        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True, proxy=self.proxy,
                args=["--no-sandbox"])
            ctx  = browser.new_context(ignore_https_errors=True)
            if cookies:
                ctx.add_cookies(cookies)
            page = ctx.new_page()
            page.set_default_timeout(self.timeout)

            try:
                page.goto(url, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)

                # Highlight element if selector given
                if highlight_selector:
                    page.evaluate(f"""
                        const el = document.querySelector('{highlight_selector}');
                        if(el) el.style.border = '3px solid red';
                    """)

                page.screenshot(path=path, full_page=True)
                return {"path": path, "url": url, "size": os.path.getsize(path)}

            except Exception as e:
                return {"error": str(e), "url": url}
            finally:
                browser.close()

    # ── XSS Evidence ─────────────────────────

    def capture_xss(self, url: str, payload: str,
                    param: str = "q") -> Dict:
        """Capture XSS alert dialog as evidence."""
        if not _check():
            return {"error": "playwright not installed"}

        fname    = self._fname("xss", url)
        path     = str(self.out / fname)
        dialog   = []

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            ctx     = browser.new_context(ignore_https_errors=True)
            page    = ctx.new_page()
            page.set_default_timeout(self.timeout)
            page.on("dialog", lambda d: (dialog.append(d.message), d.dismiss()))

            try:
                target = f"{url}?{param}={payload}"
                page.goto(target, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)
                page.screenshot(path=path, full_page=True)
                return {
                    "path"          : path,
                    "url"           : target,
                    "dialog_fired"  : bool(dialog),
                    "dialog_message": dialog[0] if dialog else "",
                }
            except Exception as e:
                return {"error": str(e)}
            finally:
                browser.close()

    # ── Before/After ─────────────────────────

    def capture_before_after(self, url: str,
                              attack_url: str,
                              vuln_type: str) -> Dict:
        """Capture normal vs attack response for comparison."""
        before = self.capture(url,      self._fname(f"{vuln_type}_before", url))
        after  = self.capture(attack_url, self._fname(f"{vuln_type}_after", attack_url))
        return {"before": before, "after": after, "vuln_type": vuln_type}

    # ── Bulk Evidence ─────────────────────────

    def capture_findings(self, findings: List[Dict],
                         cookies: List[Dict] = None) -> List[Dict]:
        """Auto-capture screenshots for all findings."""
        results = []
        for f in findings:
            url      = f.get("url","")
            vtype    = f.get("vuln_type","vuln")
            payload  = f.get("payload","")

            if not url:
                continue

            if vtype == "xss" and payload:
                shot = self.capture_xss(url, payload)
            else:
                fname = self._fname(vtype, url)
                shot  = self.capture(url, fname, cookies=cookies)

            results.append({**f, "screenshot": shot.get("path",""),
                            "screenshot_error": shot.get("error")})
        return results

    # ── HTML Evidence Report ──────────────────

    def html_evidence(self, findings_with_shots: List[Dict],
                      target: str = "") -> str:
        """Generate simple HTML evidence report."""
        rows = ""
        for f in findings_with_shots:
            shot  = f.get("screenshot","")
            img   = f'<img src="{shot}" style="max-width:600px">' if shot and Path(shot).exists() else "No screenshot"
            rows += f"""
            <tr>
                <td>{f.get('severity','')}</td>
                <td>{f.get('vuln_type','')}</td>
                <td><a href="{f.get('url','')}">{f.get('url','')[:60]}</a></td>
                <td>{img}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html><head><title>OXHUNTER Evidence</title>
<style>body{{font-family:monospace;background:#111;color:#eee}}
table{{width:100%;border-collapse:collapse}}
th{{background:#333;padding:8px}}td{{padding:8px;border:1px solid #333}}
img{{border:2px solid #f00;border-radius:4px}}</style></head>
<body>
<h1>🔐 OXHUNTER Evidence Report</h1>
<p>Target: {target} | Findings: {len(findings_with_shots)}</p>
<table><tr><th>Severity</th><th>Type</th><th>URL</th><th>Evidence</th></tr>
{rows}</table></body></html>"""

    def save_html(self, findings: List[Dict],
                  target: str = "", filename: str = "evidence.html") -> str:
        html = self.html_evidence(findings, target)
        path = str(self.out / filename)
        Path(path).write_text(html)
        return path
