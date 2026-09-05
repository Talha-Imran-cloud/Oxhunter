"""
OXHUNTER - api_versioning.py
API Versioning Attack — Old/deprecated endpoints discovery
"""

import requests
import urllib3
from urllib.parse import urlparse
from typing import Dict, List, Optional
urllib3.disable_warnings()

# Common version patterns
VERSIONS = [
    "v1","v2","v3","v4","v0","v1.0","v2.0","v3.0",
    "v1.1","v1.2","v2.1","v0.1","beta","alpha","old",
    "legacy","dev","test","staging","internal","private",
]

VERSION_PATHS = [
    "/api/{v}/", "/api/{v}", "/{v}/api/", "/rest/{v}/",
    "/service/{v}/", "/{v}/", "/api/v/{v}/",
]

SENSITIVE_ENDPOINTS = [
    "users","user","admin","auth","login","token","keys",
    "config","settings","debug","health","info","status",
    "accounts","profile","roles","permissions","export","dump",
]


class APIVersionTester:

    def __init__(self, timeout: int = 10,
                 session: Optional[requests.Session] = None,
                 proxy: Optional[str] = None):
        self.timeout = timeout
        self.s       = session or requests.Session()
        self.s.headers["User-Agent"] = "Mozilla/5.0"
        self.s.verify = False
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}

    def _get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.s.get(url, timeout=self.timeout)
        except Exception:
            return None

    # ── Discover versioned endpoints ──────────

    def discover_versions(self, base_url: str) -> List[Dict]:
        """Find accessible API version endpoints."""
        parsed  = urlparse(base_url)
        base    = f"{parsed.scheme}://{parsed.netloc}"
        found   = []

        for v in VERSIONS:
            for pattern in VERSION_PATHS:
                url  = base + pattern.format(v=v)
                r    = self._get(url)
                if r and r.status_code not in [404, 400]:
                    found.append({
                        "version"    : v,
                        "url"        : url,
                        "status"     : r.status_code,
                        "size"       : len(r.content),
                        "deprecated" : v in ["v1","v0","beta","alpha","legacy","old"],
                    })
        return found

    # ── Test deprecated endpoints ─────────────

    def test_deprecated(self, base_url: str,
                        active_version: str = "v2") -> List[Dict]:
        """
        Compare old vs current API responses.
        Old versions may lack auth checks or expose extra data.
        """
        parsed   = urlparse(base_url)
        base     = f"{parsed.scheme}://{parsed.netloc}"
        findings = []
        old_vers = [v for v in VERSIONS if v != active_version]

        for endpoint in SENSITIVE_ENDPOINTS:
            current_url = f"{base}/api/{active_version}/{endpoint}"
            current_r   = self._get(current_url)
            if not current_r or current_r.status_code == 404:
                continue

            for old_v in old_vers[:8]:
                old_url = f"{base}/api/{old_v}/{endpoint}"
                old_r   = self._get(old_url)
                if not old_r or old_r.status_code == 404:
                    continue

                # Old version accessible but current requires auth
                if (current_r.status_code in [401,403]
                        and old_r.status_code == 200):
                    findings.append({
                        "type"       : "api_version_auth_bypass",
                        "severity"   : "CRITICAL",
                        "url"        : old_url,
                        "detail"     : f"{active_version} requires auth but {old_v} doesn't",
                        "endpoint"   : endpoint,
                        "old_version": old_v,
                    })

                # Old version exposes more data
                elif (old_r.status_code == 200
                      and len(old_r.content) > len(current_r.content) + 100):
                    findings.append({
                        "type"       : "api_version_data_exposure",
                        "severity"   : "HIGH",
                        "url"        : old_url,
                        "detail"     : f"{old_v} returns {len(old_r.content)-len(current_r.content)} more bytes",
                        "endpoint"   : endpoint,
                        "old_version": old_v,
                    })

        return findings

    # ── Header-based version switching ────────

    def test_header_version(self, url: str) -> List[Dict]:
        """Test version switching via Accept/X-API-Version headers."""
        findings = []
        headers_to_try = [
            {"Accept"          : "application/vnd.api+json;version=1"},
            {"X-API-Version"   : "1"},
            {"API-Version"     : "v1"},
            {"Accept"          : "application/v1+json"},
        ]
        base_r = self._get(url)
        if not base_r:
            return []

        for h in headers_to_try:
            try:
                r = self.s.get(url, headers=h, timeout=self.timeout)
                if r.status_code == 200 and len(r.content) != len(base_r.content):
                    findings.append({
                        "type"    : "api_header_version_switch",
                        "severity": "MEDIUM",
                        "url"     : url,
                        "header"  : h,
                        "detail"  : "Different response via version header",
                    })
            except Exception:
                pass
        return findings

    # ── GraphQL version check ─────────────────

    def test_graphql_versions(self, base_url: str) -> List[Dict]:
        """Check common GraphQL endpoint paths."""
        parsed   = urlparse(base_url)
        base     = f"{parsed.scheme}://{parsed.netloc}"
        paths    = ["/graphql","/graphql/v1","/graphql/v2",
                    "/api/graphql","/v1/graphql","/gql"]
        findings = []

        for path in paths:
            url = base + path
            try:
                r = self.s.post(url, json={"query": "{__typename}"},
                                timeout=self.timeout)
                if r.status_code == 200 and "__typename" in r.text:
                    findings.append({
                        "type"    : "graphql_endpoint_found",
                        "severity": "INFO",
                        "url"     : url,
                        "detail"  : "GraphQL endpoint accessible",
                    })
            except Exception:
                pass
        return findings

    # ── Full Scan ─────────────────────────────

    def scan(self, base_url: str,
             active_version: str = "v2") -> Dict:
        versions   = self.discover_versions(base_url)
        deprecated = self.test_deprecated(base_url, active_version)
        headers    = self.test_header_version(base_url)
        graphql    = self.test_graphql_versions(base_url)
        all_finds  = deprecated + headers + graphql

        return {
            "target"            : base_url,
            "versions_found"    : versions,
            "deprecated_count"  : sum(1 for v in versions if v["deprecated"]),
            "findings"          : all_finds,
            "total"             : len(all_finds),
        }
