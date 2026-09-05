"""
OXHUNTER - email_harvest.py
Email + Username Harvesting from web pages, JS files, metadata
"""

import re
import requests
import urllib3
from urllib.parse import urljoin
from typing import Dict, List, Set, Optional

urllib3.disable_warnings()

EMAIL_RE    = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
USERNAME_RE = re.compile(r"(?:user|username|author|handle|profile)[\"'\s:=]+([a-zA-Z0-9_\-\.]{3,30})", re.I)
PHONE_RE    = re.compile(r"(\+?\d[\d\s\-().]{7,}\d)")
JS_SECRET_RE= re.compile(r"(?:api_key|apikey|secret|token|password|passwd|auth)[\"'\s:=]+[\"']([a-zA-Z0-9_\-]{8,})[\"']", re.I)


class EmailHarvester:

    def __init__(self, timeout: int = 10, proxy: Optional[str] = None):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0"
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _get(self, url: str) -> str:
        try:
            return self.session.get(url, timeout=self.timeout, verify=False).text
        except Exception:
            return ""

    # ── Extract from text ─────────────────────

    @staticmethod
    def extract_emails(text: str) -> Set[str]:
        return set(EMAIL_RE.findall(text))

    @staticmethod
    def extract_usernames(text: str) -> Set[str]:
        return set(USERNAME_RE.findall(text))

    @staticmethod
    def extract_phones(text: str) -> Set[str]:
        return set(PHONE_RE.findall(text))

    @staticmethod
    def extract_secrets(text: str) -> List[Dict]:
        return [{"match": m[0], "value": m[1]}
                for m in JS_SECRET_RE.findall(text)]

    # ── Scan page ─────────────────────────────

    def scan_url(self, url: str) -> Dict:
        body = self._get(url)
        return {
            "url"      : url,
            "emails"   : list(self.extract_emails(body)),
            "usernames": list(self.extract_usernames(body)),
            "phones"   : list(self.extract_phones(body)),
        }

    def scan_js(self, url: str) -> Dict:
        """Scan JS file for secrets + emails."""
        body = self._get(url)
        return {
            "url"    : url,
            "emails" : list(self.extract_emails(body)),
            "secrets": self.extract_secrets(body),
        }

    # ── Discover JS files ─────────────────────

    def find_js_files(self, base_url: str) -> List[str]:
        body  = self._get(base_url)
        links = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
        return [urljoin(base_url, l) for l in links]

    # ── Full Harvest ──────────────────────────

    def harvest(self, target: str) -> Dict:
        """Full email/username harvest from target + its JS files."""
        emails, usernames, phones, secrets = set(), set(), set(), []

        # Main page
        main = self.scan_url(target)
        emails.update(main["emails"])
        usernames.update(main["usernames"])
        phones.update(main["phones"])

        # JS files
        js_files = self.find_js_files(target)
        for js in js_files[:10]:   # max 10 JS files
            r = self.scan_js(js)
            emails.update(r["emails"])
            secrets.extend(r["secrets"])

        # Filter out common false positives
        skip = {"example.com","sentry.io","schema.org","w3.org","googleapis.com"}
        emails = {e for e in emails if not any(s in e for s in skip)}

        return {
            "target"    : target,
            "emails"    : list(emails),
            "usernames" : list(usernames),
            "phones"    : list(phones),
            "secrets"   : secrets,
            "js_files"  : js_files,
            "total"     : len(emails) + len(secrets),
        }

    # ── Common pages check ────────────────────

    def check_common_pages(self, base_url: str) -> Dict:
        """Check common pages that often expose emails."""
        pages   = ["/contact", "/about", "/team", "/staff",
                   "/support", "/security.txt", "/.well-known/security.txt"]
        results = {}
        for page in pages:
            url  = base_url.rstrip("/") + page
            body = self._get(url)
            if body:
                e = list(self.extract_emails(body))
                if e:
                    results[page] = e
        return results
