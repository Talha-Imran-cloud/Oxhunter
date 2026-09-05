"""
JavaScript File Deep Analysis Module
Extracts hidden endpoints, API keys, secrets, and sensitive data from JS files
"""

import asyncio
import re
from urllib.parse import urlparse, urljoin
from typing import List, Optional, Set, Dict
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class JSFinding:
    """Represents a finding from JS file analysis"""
    url: str
    js_file: str
    type: str        # 'api_key', 'endpoint', 'secret', 'token', 'credential', 'internal_url'
    severity: str
    confidence: str
    match: str
    context: str
    remediation: str


class JSAnalyzer:
    """
    JavaScript Deep Analysis Module
    Extracts from JS files:
    - Hidden API endpoints (/api/v1/admin, /internal/*)
    - API keys and tokens (AWS, Google, Stripe, etc.)
    - Hardcoded credentials (username/password)
    - JWT secrets and private keys
    - Internal URLs and IP addresses
    - GraphQL queries and mutations
    - S3 bucket names
    - Debug/dev endpoints
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("JSAnalysis")
        self.findings: List[JSFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(20.0, connect=10.0)
        self.scanned_js: Set[str] = set()

        # Regex patterns for sensitive data
        self.patterns = self._build_patterns()

        # JS file extensions/paths to look for
        self.js_extensions = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']

    def _build_patterns(self) -> List[Dict]:
        return [
            # API Keys - Critical
            {
                "name": "AWS Access Key",
                "type": "api_key",
                "severity": "critical",
                "pattern": re.compile(r'AKIA[0-9A-Z]{16}'),
                "context_chars": 50,
            },
            {
                "name": "AWS Secret Key",
                "type": "api_key",
                "severity": "critical",
                "pattern": re.compile(r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]'),
                "context_chars": 80,
            },
            {
                "name": "Google API Key",
                "type": "api_key",
                "severity": "high",
                "pattern": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
                "context_chars": 50,
            },
            {
                "name": "Google OAuth",
                "type": "api_key",
                "severity": "high",
                "pattern": re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
                "context_chars": 60,
            },
            {
                "name": "Stripe API Key",
                "type": "api_key",
                "severity": "critical",
                "pattern": re.compile(r'sk_(live|test)_[0-9a-zA-Z]{24,}'),
                "context_chars": 50,
            },
            {
                "name": "Stripe Publishable Key",
                "type": "api_key",
                "severity": "medium",
                "pattern": re.compile(r'pk_(live|test)_[0-9a-zA-Z]{24,}'),
                "context_chars": 50,
            },
            {
                "name": "GitHub Token",
                "type": "api_key",
                "severity": "critical",
                "pattern": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}'),
                "context_chars": 50,
            },
            {
                "name": "GitHub Classic Token",
                "type": "api_key",
                "severity": "critical",
                "pattern": re.compile(r'ghp_[A-Za-z0-9]{36}'),
                "context_chars": 50,
            },
            {
                "name": "Slack Token",
                "type": "api_key",
                "severity": "high",
                "pattern": re.compile(r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}'),
                "context_chars": 50,
            },
            {
                "name": "Slack Webhook",
                "type": "api_key",
                "severity": "high",
                "pattern": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'),
                "context_chars": 80,
            },
            {
                "name": "Twilio API Key",
                "type": "api_key",
                "severity": "high",
                "pattern": re.compile(r'SK[0-9a-fA-F]{32}'),
                "context_chars": 50,
            },
            {
                "name": "SendGrid API Key",
                "type": "api_key",
                "severity": "high",
                "pattern": re.compile(r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}'),
                "context_chars": 50,
            },
            {
                "name": "Mailchimp API Key",
                "type": "api_key",
                "severity": "high",
                "pattern": re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}'),
                "context_chars": 50,
            },
            {
                "name": "Firebase URL",
                "type": "api_key",
                "severity": "medium",
                "pattern": re.compile(r'https://[a-z0-9-]+\.firebaseio\.com'),
                "context_chars": 80,
            },
            {
                "name": "Firebase API Key",
                "type": "api_key",
                "severity": "high",
                "pattern": re.compile(r'(?i)firebase.{0,20}[\'"][A-Za-z0-9_\-]{35,45}[\'"]'),
                "context_chars": 80,
            },
            {
                "name": "Mapbox Token",
                "type": "api_key",
                "severity": "medium",
                "pattern": re.compile(r'pk\.eyJ1[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+'),
                "context_chars": 80,
            },

            # Credentials - Critical
            {
                "name": "Hardcoded Password",
                "type": "credential",
                "severity": "critical",
                "pattern": re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]{6,}[\'"]'),
                "context_chars": 80,
            },
            {
                "name": "Hardcoded Username+Password",
                "type": "credential",
                "severity": "critical",
                "pattern": re.compile(r'(?i)(username|user|login)\s*[:=]\s*[\'"][^\'"]+[\'"]'),
                "context_chars": 80,
            },
            {
                "name": "Basic Auth Hardcoded",
                "type": "credential",
                "severity": "critical",
                "pattern": re.compile(r'(?i)(Authorization|auth)\s*:\s*[\'"]?Basic\s+[A-Za-z0-9+/=]{10,}'),
                "context_chars": 80,
            },
            {
                "name": "JWT Token Hardcoded",
                "type": "token",
                "severity": "critical",
                "pattern": re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
                "context_chars": 60,
            },
            {
                "name": "Private Key",
                "type": "secret",
                "severity": "critical",
                "pattern": re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
                "context_chars": 80,
            },
            {
                "name": "JWT Secret",
                "type": "secret",
                "severity": "critical",
                "pattern": re.compile(r'(?i)(jwt_secret|jwt_key|secret_key|JWT_SECRET)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]'),
                "context_chars": 80,
            },

            # Internal Endpoints - High
            {
                "name": "Internal API Endpoint",
                "type": "endpoint",
                "severity": "high",
                "pattern": re.compile(r'[\'"`](/(?:api|internal|admin|v\d+|graphql|rest|private)/[^\s\'"`<>]{3,80})[\'"`]'),
                "context_chars": 80,
            },
            {
                "name": "Absolute Internal URL",
                "type": "internal_url",
                "severity": "high",
                "pattern": re.compile(r'https?://(?:localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^\s\'"`<>]*'),
                "context_chars": 80,
            },
            {
                "name": "S3 Bucket",
                "type": "internal_url",
                "severity": "high",
                "pattern": re.compile(r's3\.amazonaws\.com/([a-z0-9.\-_]{3,63})|([a-z0-9.\-_]{3,63})\.s3\.amazonaws\.com'),
                "context_chars": 80,
            },
            {
                "name": "Database Connection String",
                "type": "credential",
                "severity": "critical",
                "pattern": re.compile(r'(?i)(mongodb|mysql|postgres|redis|mssql|oracle)://[^\s\'"`<>]{10,}'),
                "context_chars": 80,
            },
            {
                "name": "GraphQL Endpoint",
                "type": "endpoint",
                "severity": "medium",
                "pattern": re.compile(r'[\'"`](/graphql[^\s\'"`<>]*)[\'"`]'),
                "context_chars": 60,
            },
            {
                "name": "Debug/Dev Endpoint",
                "type": "endpoint",
                "severity": "medium",
                "pattern": re.compile(r'[\'"`](/(?:debug|test|dev|staging|internal|backdoor|shell)[^\s\'"`<>]*)[\'"`]'),
                "context_chars": 60,
            },
            {
                "name": "IP Address Internal",
                "type": "internal_url",
                "severity": "medium",
                "pattern": re.compile(r'(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}'),
                "context_chars": 60,
            },

            # Miscellaneous secrets
            {
                "name": "Generic Secret/Token",
                "type": "secret",
                "severity": "high",
                "pattern": re.compile(r'(?i)(secret|token|api_key|apikey|access_key)\s*[:=]\s*[\'"][a-zA-Z0-9_\-]{16,}[\'"]'),
                "context_chars": 80,
            },
            {
                "name": "SSH Private Key",
                "type": "secret",
                "severity": "critical",
                "pattern": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
                "context_chars": 60,
            },
            {
                "name": "Google reCAPTCHA Secret",
                "type": "api_key",
                "severity": "high",
                "pattern": re.compile(r'6L[0-9a-zA-Z_\-]{38}'),
                "context_chars": 50,
            },
        ]

    def _get_context(self, content: str, match_start: int,
                     match_end: int, context_chars: int) -> str:
        """Get surrounding context of a match"""
        start = max(0, match_start - context_chars)
        end   = min(len(content), match_end + context_chars)
        ctx = content[start:end].replace('\n', ' ').replace('\r', '').strip()
        return ctx[:200]

    def _extract_js_urls(self, html: str, base_url: str) -> Set[str]:
        """Extract all JS file URLs from HTML"""
        js_urls = set()

        # src= attributes
        src_pattern = re.compile(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
        for match in src_pattern.finditer(html):
            src = match.group(1)
            if any(src.endswith(ext) for ext in self.js_extensions) or '.js' in src:
                full_url = urljoin(base_url, src)
                js_urls.add(full_url)

        # Also look for lazy-loaded chunks
        chunk_pattern = re.compile(r'[\'"]([^\'"]*(?:chunk|bundle|vendor|app|main)[^\'"]*\.js)[\'"]')
        for match in chunk_pattern.finditer(html):
            src = match.group(1)
            if src.startswith('/') or src.startswith('http'):
                full_url = urljoin(base_url, src)
                js_urls.add(full_url)

        return js_urls

    def _analyze_js_content(self, js_content: str, js_url: str) -> List[JSFinding]:
        """Analyze JS file content for sensitive data"""
        findings = []
        seen_matches = set()

        for pattern_info in self.patterns:
            for match in pattern_info["pattern"].finditer(js_content):
                matched_text = match.group(0)

                # Deduplicate
                dedup_key = f"{pattern_info['name']}:{matched_text[:40]}"
                if dedup_key in seen_matches:
                    continue
                seen_matches.add(dedup_key)

                context = self._get_context(
                    js_content, match.start(), match.end(),
                    pattern_info["context_chars"]
                )

                findings.append(JSFinding(
                    url=js_url,
                    js_file=js_url,
                    type=pattern_info["type"],
                    severity=pattern_info["severity"],
                    confidence="high",
                    match=matched_text[:100],
                    context=context,
                    remediation=self._get_remediation(pattern_info["type"], pattern_info["name"])
                ))

        return findings

    def _get_remediation(self, finding_type: str, name: str) -> str:
        remediations = {
            "api_key": (
                f"1. Revoke/rotate the exposed {name} immediately.\n"
                "2. Never hardcode API keys in frontend JavaScript.\n"
                "3. Use environment variables on server-side only.\n"
                "4. Use restricted API keys with minimal permissions.\n"
                "5. Implement secret scanning in CI/CD pipeline (truffleHog, git-secrets)."
            ),
            "credential": (
                "1. Rotate all exposed credentials immediately.\n"
                "2. Never store credentials in client-side JavaScript.\n"
                "3. Use server-side authentication — never pass credentials to frontend.\n"
                "4. Implement proper secrets management (HashiCorp Vault, AWS Secrets Manager)."
            ),
            "secret": (
                "1. Rotate/revoke the exposed secret immediately.\n"
                "2. Remove from codebase and git history (BFG Repo Cleaner).\n"
                "3. Use server-side secrets management.\n"
                "4. Add pre-commit hooks to prevent future exposure."
            ),
            "endpoint": (
                "1. Review if this endpoint should be publicly accessible.\n"
                "2. Implement authentication on all internal endpoints.\n"
                "3. Use API gateway to restrict endpoint access.\n"
                "4. Remove debug/test endpoints from production builds."
            ),
            "internal_url": (
                "1. Remove internal URLs/IPs from client-side code.\n"
                "2. Use relative URLs or environment-specific config.\n"
                "3. Ensure internal services are not accessible from public internet.\n"
                "4. Review firewall rules for internal service exposure."
            ),
            "token": (
                "1. Revoke the exposed token immediately.\n"
                "2. Never embed tokens in JavaScript files.\n"
                "3. Use short-lived tokens and secure storage (httpOnly cookies).\n"
                "4. Implement token rotation."
            ),
        }
        return remediations.get(finding_type, "Remove sensitive data from client-side JavaScript.")

    async def _fetch_js(self, url: str) -> Optional[str]:
        """Fetch JS file content"""
        try:
            async def _do_request():
                return await self.client.get(url, follow_redirects=True)
            response = await self.rate_limiter.execute_with_retry(_do_request)
            if response and response.status_code == 200:
                ct = response.headers.get('content-type', '')
                if 'javascript' in ct or 'text' in ct or url.endswith('.js'):
                    return response.text
        except Exception as e:
            self.logger.debug(f"JS fetch failed {url}: {e}")
        return None

    async def _fetch_html(self, url: str) -> Optional[str]:
        """Fetch HTML page"""
        try:
            async def _do_request():
                return await self.client.get(url, follow_redirects=True)
            response = await self.rate_limiter.execute_with_retry(_do_request)
            if response and response.status_code == 200:
                return response.text
        except Exception as e:
            self.logger.debug(f"HTML fetch failed {url}: {e}")
        return None

    async def analyze_js_file(self, js_url: str) -> List[JSFinding]:
        """Fetch and analyze a single JS file"""
        if js_url in self.scanned_js:
            return []
        self.scanned_js.add(js_url)

        self.logger.info(f"Analyzing JS: {js_url}")
        content = await self._fetch_js(js_url)
        if not content:
            return []

        findings = self._analyze_js_content(content, js_url)
        for f in findings:
            self.logger.warning(
                f"JS FINDING [{f.severity.upper()}]: {f.type} — {f.match[:60]} | {js_url}"
            )
        return findings

    async def scan(self, target_urls: List[str], forms: List = None) -> List[JSFinding]:  # NEW-BUG-001 FIX
        forms = forms or []  # NEW-BUG-001 FIX
        """Main JS analysis scan"""
        self.logger.info(f"Starting JS deep analysis on {len(target_urls)} URLs")

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client
            all_js_urls: Set[str] = set()

            # Step 1: Find all JS files from HTML pages
            for url in target_urls:
                parsed = urlparse(url)

                # If URL is already a JS file
                if any(parsed.path.endswith(ext) for ext in self.js_extensions):
                    all_js_urls.add(url)
                    continue

                # Extract JS from HTML
                html = await self._fetch_html(url)
                if html:
                    js_urls = self._extract_js_urls(html, url)
                    all_js_urls.update(js_urls)

                    # Also analyze inline scripts
                    inline_pattern = re.compile(
                        r'<script(?![^>]*src)[^>]*>(.*?)</script>',
                        re.DOTALL | re.IGNORECASE
                    )
                    for inline_match in inline_pattern.finditer(html):
                        inline_content = inline_match.group(1)
                        if len(inline_content) > 50:
                            findings = self._analyze_js_content(inline_content, url + "#inline")
                            self.findings.extend(findings)

            self.logger.info(f"Found {len(all_js_urls)} JS files to analyze")

            # Step 2: Analyze all JS files concurrently
            tasks = [self.analyze_js_file(js_url) for js_url in all_js_urls]

            # Batch processing
            batch_size = 10
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                results = await asyncio.gather(*batch, return_exceptions=True)
                for result in results:
                    if isinstance(result, list):
                        self.findings.extend(result)

        self.logger.info(f"JS analysis complete. Found {len(self.findings)} issues in {len(self.scanned_js)} JS files")
        return self.findings
