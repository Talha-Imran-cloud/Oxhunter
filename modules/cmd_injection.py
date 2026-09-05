"""
Command Injection Detection Module
Tests for OS command injection vulnerabilities in parameters and forms
"""

import asyncio
import time
import re
from urllib.parse import urlparse, parse_qsl, urlencode
from typing import List, Dict, Optional
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from core.paths import PAYLOADS_DIR
from utils.logger import setup_logger


@dataclass
class CMDFinding:
    """Represents a confirmed or potential Command Injection vulnerability"""
    url: str
    parameter: str
    payload: str
    type: str        # 'error_based', 'time_based', 'output_based', 'blind'
    severity: str    # 'critical', 'high', 'medium'
    confidence: str  # 'high', 'medium', 'low'
    evidence: str
    remediation: str


class CMDInjectionScanner:
    """
    Command Injection Detection Module
    Detects OS command injection via:
    - Output-based (command output visible in response)
    - Error-based (shell errors in response)
    - Time-based blind (sleep/ping delay detection)
    """

    def __init__(self, rate_limiter: RateLimiter, payload_file: str = None):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("CMDInjection")
        self.payloads: List[str] = []
        self.findings: List[CMDFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(8.0, connect=5.0)

        # Output-based payloads with expected output patterns
        self.output_payloads = [
            ("; echo 0xHUNTER_CMD_TEST",   "0xHUNTER_CMD_TEST",  "echo injection via semicolon"),
            ("| echo 0xHUNTER_CMD_TEST",   "0xHUNTER_CMD_TEST",  "echo injection via pipe"),
            ("&& echo 0xHUNTER_CMD_TEST",  "0xHUNTER_CMD_TEST",  "echo injection via AND"),
            ("& echo 0xHUNTER_CMD_TEST",   "0xHUNTER_CMD_TEST",  "echo injection via background"),
            ("`echo 0xHUNTER_CMD_TEST`",   "0xHUNTER_CMD_TEST",  "echo injection via backtick"),
            ("$(echo 0xHUNTER_CMD_TEST)",  "0xHUNTER_CMD_TEST",  "echo injection via subshell"),
            ("%0a echo 0xHUNTER_CMD_TEST", "0xHUNTER_CMD_TEST",  "echo injection via newline"),
        ]

        # Time-based blind payloads (5 second delay)
        self.time_payloads = [
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5",
            "& sleep 5",
            "$(sleep 5)",
            "`sleep 5`",
            "%0a sleep 5",
            "; ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1",
        ]
        resolved = str(PAYLOADS_DIR / "cmd_injection/cmd_injection.txt") if payload_file is None else payload_file
        self.payloads = self._load_payloads(resolved)

        # Error patterns that indicate command injection
        self.error_patterns = [
            r"sh:\s+\d+:",
            r"/bin/sh",
            r"command not found",
            r"syntax error",
            r"unexpected token",
            r"not recognized as an internal",
            r"'[^']+' is not recognized",
            r"Permission denied",
            r"No such file or directory",
            r"bash:",
            r"zsh:",
            r"cmd\.exe",
        ]

        # Common output patterns from system commands
        self.cmd_output_patterns = [
            r"root:x:0:0",          # /etc/passwd
            r"uid=\d+\(",           # id command
            r"gid=\d+\(",           # id command
            r"Windows IP Configuration",  # ipconfig
            r"Volume in drive",     # dir command
            r"Directory of",        # dir command
        ]

        # Params likely to be command-injectable
        self.cmd_prone_params = [
            'cmd', 'exec', 'execute', 'command', 'run', 'query',
            'ping', 'host', 'ip', 'domain', 'lookup', 'search',
            'file', 'path', 'dir', 'folder', 'name', 'input',
            'process', 'shell', 'bash', 'terminal', 'system'
        ]

    def _load_payloads(self, filepath: str) -> List[str]:
        """Load payloads from file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.logger.info(f"Loaded {len(payloads)} CMD injection payloads")
            return payloads
        except FileNotFoundError:
            self.logger.warning(f"Payload file not found: {filepath}. Using defaults.")
            return [p[0] for p in self.output_payloads] + self.time_payloads

    def _is_cmd_prone_param(self, param: str) -> bool:
        """Check if parameter name suggests command injection potential"""
        param_lower = param.lower()
        return any(p in param_lower for p in self.cmd_prone_params)

    def _check_output(self, response_text: str, expected: str) -> bool:
        """Check if expected output is in response"""
        return expected in response_text

    def _check_error_based(self, response_text: str) -> Optional[str]:
        """Check for shell error messages in response"""
        for pattern in self.error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        for pattern in self.cmd_output_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    async def _fetch(self, url: str, method: str = "GET", data: Optional[Dict] = None) -> Optional[tuple]:
        """Make HTTP request and return (response, elapsed_seconds)"""
        try:
            start = time.monotonic()
            async def _do_request():
                if method.upper() == "POST" and data:
                    return await self.client.post(url, data=data, follow_redirects=True)
                return await self.client.get(url, follow_redirects=True)
            response = await self.rate_limiter.execute_with_retry(_do_request)
            elapsed = time.monotonic() - start
            return response, elapsed
        except Exception as e:
            self.logger.debug(f"Request failed {url}: {e}")
            return None, 0

    async def test_output_based(self, url: str, param: str) -> Optional[CMDFinding]:
        """Test parameter with output-based CMD injection payloads"""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        if param not in params:
            return None

        for payload, expected_output, description in self.output_payloads:
            test_params = params.copy()
            test_params[param] = params[param] + payload
            test_url = parsed._replace(query=urlencode(test_params)).geturl()

            response, _ = await self._fetch(test_url)
            if not response:
                continue

            if self._check_output(response.text, expected_output):
                return CMDFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    type="output_based",
                    severity="critical",
                    confidence="high",
                    evidence=f"Command output '{expected_output}' found in response. Method: {description}",
                    remediation=(
                        "1. Never pass user input to OS commands.\n"
                        "2. Use language-native libraries instead of shell commands.\n"
                        "3. If shell is necessary, use strict allowlist for input validation.\n"
                        "4. Escape shell metacharacters using shlex.quote() (Python) or escapeshellarg() (PHP).\n"
                        "5. Run application with least privilege."
                    )
                )

            # Also check error-based on same response
            error_match = self._check_error_based(response.text)
            if error_match:
                return CMDFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    type="error_based",
                    severity="high",
                    confidence="medium",
                    evidence=f"Shell error/output pattern detected: '{error_match}'",
                    remediation=(
                        "1. Disable detailed error messages in production.\n"
                        "2. Sanitize all user input before use in system calls.\n"
                        "3. Use subprocess with argument list (not shell=True) in Python.\n"
                        "4. Implement Web Application Firewall (WAF)."
                    )
                )

        return None

    async def test_time_based(self, url: str, param: str) -> Optional[CMDFinding]:
        """Test parameter with time-based blind CMD injection"""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        if param not in params:
            return None

        # First get baseline response time
        baseline_response, baseline_time = await self._fetch(url)
        if not baseline_response:
            return None

        for payload in self.time_payloads:
            test_params = params.copy()
            test_params[param] = params[param] + payload
            test_url = parsed._replace(query=urlencode(test_params)).geturl()

            response, elapsed = await self._fetch(test_url)
            if not response:
                continue

            # If response took 4+ seconds more than baseline = time-based injection
            if elapsed >= (baseline_time + 4.0):
                return CMDFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    type="time_based",
                    severity="critical",
                    confidence="high",
                    evidence=(
                        f"Response delayed by {elapsed:.1f}s (baseline: {baseline_time:.1f}s). "
                        f"Payload: '{payload}' caused {elapsed - baseline_time:.1f}s extra delay."
                    ),
                    remediation=(
                        "1. Never use user input in OS command execution.\n"
                        "2. Use parameterized APIs instead of shell commands.\n"
                        "3. Implement input validation with strict allowlist.\n"
                        "4. Apply principle of least privilege to the server process."
                    )
                )

        return None

    async def test_form(self, form_action: str, form_method: str,
                        inputs: List[Dict], payload: str, expected: str) -> Optional[CMDFinding]:
        """Test form inputs for command injection"""
        data = {}
        target_input = None

        for inp in inputs:
            name = inp.get('name', '')
            if name:
                if self._is_cmd_prone_param(name) or inp.get('type') in ['text', '']:
                    data[name] = inp.get('value', 'test') + payload
                    target_input = name
                else:
                    data[name] = inp.get('value', 'test')

        if not target_input:
            return None

        if form_method.upper() == "POST":
            response, _ = await self._fetch(form_action, method="POST", data=data)
        else:
            test_url = f"{form_action}?{urlencode(data)}"
            response, _ = await self._fetch(test_url)

        if not response:
            return None

        if self._check_output(response.text, expected):
            return CMDFinding(
                url=form_action,
                parameter=target_input,
                payload=payload,
                type="output_based",
                severity="critical",
                confidence="high",
                evidence=f"Command output '{expected}' reflected in form response",
                remediation=(
                    "1. Sanitize all form inputs before processing.\n"
                    "2. Use safe APIs instead of shell execution.\n"
                    "3. Apply strict server-side input validation."
                )
            )

        error_match = self._check_error_based(response.text)
        if error_match:
            return CMDFinding(
                url=form_action,
                parameter=target_input,
                payload=payload,
                type="error_based",
                severity="high",
                confidence="medium",
                evidence=f"Shell error pattern in form response: '{error_match}'",
                remediation="Sanitize inputs and disable verbose error messages."
            )

        return None

    async def scan(self, target_urls: List[str], forms: List) -> List[CMDFinding]:
        """
        Main Command Injection scan method.
        target_urls: List of URLs with parameters
        forms: List of Form objects from crawler
        """
        self.logger.info(f"Starting CMD Injection scan on {len(target_urls)} URLs and {len(forms)} forms")

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
                    # Output-based test
                    tasks.append(self.test_output_based(url, param))
                    # Time-based only on cmd-prone params to save time
                    if self._is_cmd_prone_param(param):
                        tasks.append(self.test_time_based(url, param))

            # Test forms
            for form in forms:
                for payload, expected, _ in self.output_payloads[:4]:
                    tasks.append(self.test_form(
                        form.action, form.method, form.inputs, payload, expected
                    ))

            self.logger.info(f"Running {len(tasks)} CMD injection tests...")
            results = await asyncio.gather(*tasks, return_exceptions=True)

            seen = set()
            for result in results:
                if isinstance(result, Exception):
                    self.logger.debug(f"CMD test error: {result}")
                    continue
                if result:
                    key = f"{result.url}:{result.parameter}:{result.type}"
                    if key not in seen:
                        seen.add(key)
                        self.findings.append(result)
                        self.logger.warning(
                            f"CMD Injection [{result.severity.upper()}]: {result.url} | "
                            f"Param: {result.parameter} | Type: {result.type} | "
                            f"Confidence: {result.confidence}"
                        )

        self.logger.info(f"CMD Injection scan complete. Found {len(self.findings)} issues")
        return self.findings
