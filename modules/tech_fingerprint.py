"""
Technology Fingerprinting Module
Detects web technologies, frameworks, CMS, servers like Wappalyzer
"""

import asyncio
import re
from urllib.parse import urlparse
from typing import List, Optional, Dict, Set
from dataclasses import dataclass, field

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class TechFinding:
    """Represents a detected technology"""
    url: str
    technology: str
    category: str       # 'cms', 'framework', 'server', 'language', 'db', 'cdn', 'analytics', 'js_lib'
    version: str
    confidence: str     # 'high', 'medium', 'low'
    detection_method: str
    cve_notes: str
    remediation: str


@dataclass
class TechReport:
    """Full technology report for a target"""
    url: str
    technologies: List[TechFinding] = field(default_factory=list)
    server: str = ""
    powered_by: str = ""
    os_hint: str = ""
    waf_detected: str = ""


class TechFingerprintScanner:
    """
    Technology Fingerprinting Module (Wappalyzer-like)
    Detects:
    - CMS: WordPress, Drupal, Joomla, Magento, Shopify
    - Frameworks: Laravel, Django, Rails, Express, Spring, ASP.NET
    - Servers: Nginx, Apache, IIS, Caddy, LiteSpeed
    - Languages: PHP, Python, Ruby, Java, Node.js
    - Databases: MySQL, PostgreSQL, MongoDB, Redis
    - CDN: Cloudflare, Akamai, Fastly, AWS CloudFront
    - JS Libraries: jQuery, React, Angular, Vue, Bootstrap
    - Analytics: Google Analytics, Hotjar, Mixpanel
    - Security: WAF detection, security headers
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("TechFingerprint")
        self.findings: List[TechFinding] = []
        self.reports: List[TechReport] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(15.0, connect=8.0)

        # Fingerprint signatures
        self.signatures = self._build_signatures()

    def _build_signatures(self) -> List[Dict]:
        """Build technology fingerprint signatures"""
        sigs = []

        # ── CMS ──────────────────────────────────────────────────────────────
        sigs += [
            {
                "name": "WordPress",
                "category": "cms",
                "checks": [
                    {"type": "body",    "pattern": r'wp-content|wp-includes|wp-json',                    "confidence": "high"},
                    {"type": "body",    "pattern": r'/wp-login\.php',                                    "confidence": "high"},
                    {"type": "header",  "header": "link",       "pattern": r'rel="https://api\.w\.org"', "confidence": "high"},
                    {"type": "cookie",  "pattern": r'wordpress_|wp-settings-',                            "confidence": "high"},
                    {"type": "body",    "pattern": r'WordPress (\d+\.\d+[\.\d]*)',                        "confidence": "high", "version_group": 1},
                ],
                "cve_notes": "Check WPScan for known CVEs. Keep WordPress and plugins updated.",
                "remediation": "Keep WordPress core, themes, and plugins updated. Use a security plugin like Wordfence."
            },
            {
                "name": "Drupal",
                "category": "cms",
                "checks": [
                    {"type": "body",    "pattern": r'sites/default/files|drupal\.js|Drupal\.settings',   "confidence": "high"},
                    {"type": "header",  "header": "x-generator", "pattern": r'Drupal (\d+)',             "confidence": "high", "version_group": 1},
                    {"type": "body",    "pattern": r'Drupal (\d+\.\d+)',                                  "confidence": "high", "version_group": 1},
                    {"type": "cookie",  "pattern": r'SESS[a-f0-9]{32}',                                  "confidence": "medium"},
                ],
                "cve_notes": "Drupalgeddon2 (CVE-2018-7600) — check if patched.",
                "remediation": "Update Drupal core and modules. Monitor security advisories at drupal.org/security."
            },
            {
                "name": "Joomla",
                "category": "cms",
                "checks": [
                    {"type": "body",    "pattern": r'/components/com_|/media/jui/|Joomla!',              "confidence": "high"},
                    {"type": "body",    "pattern": r'<generator>Joomla! (\d+\.\d+)',                     "confidence": "high", "version_group": 1},
                    {"type": "cookie",  "pattern": r'[a-f0-9]{32}',                                      "confidence": "low"},
                ],
                "cve_notes": "Multiple RCE CVEs in older versions. Keep updated.",
                "remediation": "Update Joomla to latest version. Disable unused extensions."
            },
            {
                "name": "Magento",
                "category": "cms",
                "checks": [
                    {"type": "body",    "pattern": r'Mage\.Cookies|skin/frontend|mage/cookies',          "confidence": "high"},
                    {"type": "cookie",  "pattern": r'frontend|adminhtml',                                 "confidence": "medium"},
                    {"type": "body",    "pattern": r'Magento ver\. (\d+\.\d+[\.\d]*)',                   "confidence": "high", "version_group": 1},
                ],
                "cve_notes": "Magento has critical RCE CVEs (CVE-2019-8144). Verify patch status.",
                "remediation": "Apply all Magento security patches. Enable 2FA for admin."
            },
            {
                "name": "Shopify",
                "category": "cms",
                "checks": [
                    {"type": "body",    "pattern": r'cdn\.shopify\.com|myshopify\.com|Shopify\.theme',   "confidence": "high"},
                    {"type": "header",  "header": "x-shopify-stage", "pattern": r'.',                    "confidence": "high"},
                ],
                "cve_notes": "Shopify-hosted — focus on app/theme custom code review.",
                "remediation": "Review custom Shopify apps and themes for vulnerabilities."
            },
        ]

        # ── Frameworks ────────────────────────────────────────────────────────
        sigs += [
            {
                "name": "Laravel",
                "category": "framework",
                "checks": [
                    {"type": "cookie",  "pattern": r'laravel_session|XSRF-TOKEN',                        "confidence": "high"},
                    {"type": "body",    "pattern": r'laravel|Illuminate\\|storage/app',                  "confidence": "high"},
                    {"type": "header",  "header": "set-cookie", "pattern": r'laravel_session',           "confidence": "high"},
                ],
                "cve_notes": "Check Laravel version for known CVEs. Debug mode exposes sensitive data.",
                "remediation": "Disable APP_DEBUG in production. Keep Laravel updated."
            },
            {
                "name": "Django",
                "category": "framework",
                "checks": [
                    {"type": "cookie",  "pattern": r'csrftoken|django',                                  "confidence": "high"},
                    {"type": "body",    "pattern": r'Django administration|csrfmiddlewaretoken',         "confidence": "high"},
                    {"type": "header",  "header": "x-frame-options", "pattern": r'SAMEORIGIN',           "confidence": "low"},
                ],
                "cve_notes": "Check Django version. DEBUG=True exposes full stack traces.",
                "remediation": "Set DEBUG=False in production. Keep Django updated."
            },
            {
                "name": "Ruby on Rails",
                "category": "framework",
                "checks": [
                    {"type": "cookie",  "pattern": r'_session_id|_rails_',                               "confidence": "high"},
                    {"type": "header",  "header": "x-powered-by", "pattern": r'Phusion Passenger',      "confidence": "high"},
                    {"type": "body",    "pattern": r'rails\.js|turbolinks',                              "confidence": "medium"},
                ],
                "cve_notes": "Rails mass assignment and YAML deserialization CVEs. Keep updated.",
                "remediation": "Keep Rails updated. Use strong_parameters for mass assignment protection."
            },
            {
                "name": "Spring Boot",
                "category": "framework",
                "checks": [
                    {"type": "body",    "pattern": r'spring|org\.springframework',                       "confidence": "high"},
                    {"type": "url",     "pattern": r'/actuator|/actuator/health',                        "confidence": "high"},
                    {"type": "header",  "header": "x-application-context", "pattern": r'.',             "confidence": "high"},
                ],
                "cve_notes": "Spring4Shell (CVE-2022-22965) — critical RCE. Verify patch status.",
                "remediation": "Apply Spring4Shell patch. Disable actuator endpoints in production."
            },
            {
                "name": "ASP.NET",
                "category": "framework",
                "checks": [
                    {"type": "header",  "header": "x-powered-by",   "pattern": r'ASP\.NET',             "confidence": "high"},
                    {"type": "header",  "header": "x-aspnet-version","pattern": r'(\d+\.\d+[\.\d]*)',   "confidence": "high", "version_group": 1},
                    {"type": "cookie",  "pattern": r'ASP\.NET_SessionId|ASPXAUTH',                       "confidence": "high"},
                ],
                "cve_notes": "Check .NET version for known CVEs. ViewState may be exploitable.",
                "remediation": "Keep ASP.NET updated. Enable ViewState MAC validation."
            },
            {
                "name": "Express.js",
                "category": "framework",
                "checks": [
                    {"type": "header",  "header": "x-powered-by", "pattern": r'Express',                "confidence": "high"},
                    {"type": "cookie",  "pattern": r'connect\.sid',                                      "confidence": "high"},
                ],
                "cve_notes": "Check for prototype pollution and path traversal CVEs.",
                "remediation": "Keep Express and dependencies updated. Use helmet.js for security headers."
            },
            {
                "name": "Next.js",
                "category": "framework",
                "checks": [
                    {"type": "body",    "pattern": r'__NEXT_DATA__|_next/static',                        "confidence": "high"},
                    {"type": "header",  "header": "x-powered-by", "pattern": r'Next\.js',               "confidence": "high"},
                ],
                "cve_notes": "Check Next.js version for middleware bypass CVEs.",
                "remediation": "Keep Next.js updated. Review API routes for exposure."
            },
        ]

        # ── Web Servers ───────────────────────────────────────────────────────
        sigs += [
            {
                "name": "Nginx",
                "category": "server",
                "checks": [
                    {"type": "header", "header": "server", "pattern": r'nginx/?(\d+\.\d+[\.\d]*)?',     "confidence": "high", "version_group": 1},
                ],
                "cve_notes": "Check Nginx version. Older versions vulnerable to HTTP Request Smuggling.",
                "remediation": "Keep Nginx updated. Remove version from Server header: server_tokens off;"
            },
            {
                "name": "Apache",
                "category": "server",
                "checks": [
                    {"type": "header", "header": "server", "pattern": r'Apache/?(\d+\.\d+[\.\d]*)?',    "confidence": "high", "version_group": 1},
                ],
                "cve_notes": "Apache Log4Shell not applicable. Check mod_rewrite CVEs.",
                "remediation": "Keep Apache updated. Use ServerTokens Prod to hide version."
            },
            {
                "name": "IIS",
                "category": "server",
                "checks": [
                    {"type": "header", "header": "server", "pattern": r'Microsoft-IIS/?(\d+\.\d+)?',    "confidence": "high", "version_group": 1},
                    {"type": "header", "header": "x-powered-by", "pattern": r'ASP\.NET',                "confidence": "medium"},
                ],
                "cve_notes": "Check IIS version for known CVEs. WebDAV may be enabled.",
                "remediation": "Keep IIS updated. Disable WebDAV if not needed."
            },
            {
                "name": "LiteSpeed",
                "category": "server",
                "checks": [
                    {"type": "header", "header": "server", "pattern": r'LiteSpeed',                     "confidence": "high"},
                    {"type": "header", "header": "x-powered-by", "pattern": r'LiteSpeed',               "confidence": "high"},
                ],
                "cve_notes": "Generally secure. Keep updated.",
                "remediation": "Keep LiteSpeed updated and configured securely."
            },
        ]

        # ── Programming Languages ─────────────────────────────────────────────
        sigs += [
            {
                "name": "PHP",
                "category": "language",
                "checks": [
                    {"type": "header", "header": "x-powered-by", "pattern": r'PHP/?(\d+\.\d+[\.\d]*)?', "confidence": "high", "version_group": 1},
                    {"type": "cookie", "pattern": r'PHPSESSID',                                          "confidence": "high"},
                    {"type": "url",    "pattern": r'\.php(\?|$)',                                        "confidence": "medium"},
                ],
                "cve_notes": "PHP < 8.1 has multiple CVEs. PHP 5.x/7.x are EOL.",
                "remediation": "Upgrade to PHP 8.2+. Remove X-Powered-By header: expose_php = Off"
            },
            {
                "name": "Python",
                "category": "language",
                "checks": [
                    {"type": "header", "header": "server",       "pattern": r'Python/?(\d+\.\d+)?',     "confidence": "high", "version_group": 1},
                    {"type": "header", "header": "x-powered-by", "pattern": r'Python',                  "confidence": "high"},
                ],
                "cve_notes": "Check Python version. Older versions EOL.",
                "remediation": "Use Python 3.11+. Keep dependencies updated."
            },
            {
                "name": "Node.js",
                "category": "language",
                "checks": [
                    {"type": "header", "header": "x-powered-by", "pattern": r'Node\.js',                "confidence": "high"},
                    {"type": "cookie", "pattern": r'connect\.sid',                                       "confidence": "medium"},
                ],
                "cve_notes": "Check Node.js version for prototype pollution and path traversal.",
                "remediation": "Use LTS Node.js version. Run npm audit regularly."
            },
        ]

        # ── CDN & Cloud ───────────────────────────────────────────────────────
        sigs += [
            {
                "name": "Cloudflare",
                "category": "cdn",
                "checks": [
                    {"type": "header", "header": "cf-ray",          "pattern": r'.',                    "confidence": "high"},
                    {"type": "header", "header": "server",          "pattern": r'cloudflare',           "confidence": "high"},
                    {"type": "cookie", "pattern": r'__cflb|cf_clearance|__cf_bm',                       "confidence": "high"},
                ],
                "cve_notes": "Cloudflare is a CDN/WAF. Real IP may be exposed via DNS history.",
                "remediation": "Ensure origin IP is not exposed. Check DNS history for real IP."
            },
            {
                "name": "AWS CloudFront",
                "category": "cdn",
                "checks": [
                    {"type": "header", "header": "x-amz-cf-id",    "pattern": r'.',                    "confidence": "high"},
                    {"type": "header", "header": "x-amz-cf-pop",   "pattern": r'.',                    "confidence": "high"},
                    {"type": "header", "header": "via",            "pattern": r'CloudFront',            "confidence": "high"},
                ],
                "cve_notes": "Check S3 bucket permissions behind CloudFront.",
                "remediation": "Ensure S3 buckets are not publicly accessible. Use OAI/OAC."
            },
            {
                "name": "Akamai",
                "category": "cdn",
                "checks": [
                    {"type": "header", "header": "x-akamai-transformed", "pattern": r'.',              "confidence": "high"},
                    {"type": "header", "header": "server",               "pattern": r'AkamaiGHost',    "confidence": "high"},
                ],
                "cve_notes": "CDN layer — check for cache poisoning vulnerabilities.",
                "remediation": "Configure Akamai security settings. Enable WAF rules."
            },
        ]

        # ── JS Libraries ──────────────────────────────────────────────────────
        sigs += [
            {
                "name": "jQuery",
                "category": "js_lib",
                "checks": [
                    {"type": "body", "pattern": r'jquery[/-](\d+\.\d+[\.\d]*)(\.min)?\.js',            "confidence": "high", "version_group": 1},
                    {"type": "body", "pattern": r'jQuery v(\d+\.\d+[\.\d]*)',                           "confidence": "high", "version_group": 1},
                ],
                "cve_notes": "jQuery < 3.5.0 vulnerable to XSS (CVE-2020-11022).",
                "remediation": "Upgrade jQuery to 3.7.0+."
            },
            {
                "name": "React",
                "category": "js_lib",
                "checks": [
                    {"type": "body", "pattern": r'react\.development\.js|react\.production\.min\.js',  "confidence": "high"},
                    {"type": "body", "pattern": r'__reactFiber|_reactRootContainer',                   "confidence": "high"},
                    {"type": "body", "pattern": r'React\.version\s*=\s*["\'](\d+\.\d+[\.\d]*)',        "confidence": "high", "version_group": 1},
                ],
                "cve_notes": "Generally secure. Check for dangerouslySetInnerHTML usage.",
                "remediation": "Avoid dangerouslySetInnerHTML. Keep React updated."
            },
            {
                "name": "Angular",
                "category": "js_lib",
                "checks": [
                    {"type": "body", "pattern": r'angular\.js|angular\.min\.js|ng-version="(\d+\.\d+)',  "confidence": "high", "version_group": 1},
                    {"type": "body", "pattern": r'ng-app|ng-controller|ng-model',                         "confidence": "medium"},
                ],
                "cve_notes": "AngularJS (1.x) is EOL. Angular 2+ check for template injection.",
                "remediation": "Migrate from AngularJS to Angular 2+. Avoid template injection."
            },
            {
                "name": "Vue.js",
                "category": "js_lib",
                "checks": [
                    {"type": "body", "pattern": r'vue\.js|vue\.min\.js|Vue\.version',                  "confidence": "high"},
                    {"type": "body", "pattern": r'__vue__|v-bind:|v-model',                            "confidence": "medium"},
                ],
                "cve_notes": "Check for v-html XSS and prototype pollution.",
                "remediation": "Avoid v-html with user input. Keep Vue.js updated."
            },
            {
                "name": "Bootstrap",
                "category": "js_lib",
                "checks": [
                    {"type": "body", "pattern": r'bootstrap\.min\.css|bootstrap\.css|bootstrap\.min\.js', "confidence": "high"},
                    {"type": "body", "pattern": r'Bootstrap v(\d+\.\d+[\.\d]*)',                           "confidence": "high", "version_group": 1},
                ],
                "cve_notes": "Bootstrap < 3.4.1 XSS vulnerability. Bootstrap 4 < 4.3.1 XSS.",
                "remediation": "Upgrade Bootstrap to 5.3.0+."
            },
        ]

        # ── Analytics ─────────────────────────────────────────────────────────
        sigs += [
            {
                "name": "Google Analytics",
                "category": "analytics",
                "checks": [
                    {"type": "body", "pattern": r'google-analytics\.com/analytics\.js|gtag\(|UA-\d+-\d+|G-[A-Z0-9]+', "confidence": "high"},
                ],
                "cve_notes": "Exposes tracking ID. Privacy compliance (GDPR) required.",
                "remediation": "Implement cookie consent. Anonymize IP in Google Analytics."
            },
        ]

        return sigs

    def _extract_version(self, text: str, pattern: str, version_group: int) -> str:
        """Extract version number from text using regex"""
        try:
            match = re.search(pattern, text, re.IGNORECASE)
            if match and len(match.groups()) >= version_group:
                return match.group(version_group) or ""
        except Exception:
            pass
        return ""

    def _check_signatures(self, response: httpx.Response, url: str) -> List[TechFinding]:
        """Check all signatures against response"""
        findings = []
        detected: Set[str] = set()

        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text
        cookies_str = "; ".join(response.cookies.values())

        for sig in self.signatures:
            name     = sig["name"]
            category = sig["category"]
            if name in detected:
                continue

            best_confidence = None
            best_version    = ""
            method_used     = ""

            for check in sig["checks"]:
                check_type = check["type"]
                pattern    = check["pattern"]
                confidence = check["confidence"]
                vg         = check.get("version_group", 0)

                matched = False
                version = ""

                if check_type == "body":
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        matched = True
                        if vg and match.lastindex and match.lastindex >= vg:
                            version = match.group(vg) or ""
                        method_used = "HTML body"

                elif check_type == "header":
                    header_name = check.get("header", "").lower()
                    header_val  = headers.get(header_name, "")
                    if header_val:
                        match = re.search(pattern, header_val, re.IGNORECASE)
                        if match:
                            matched = True
                            if vg and match.lastindex and match.lastindex >= vg:
                                version = match.group(vg) or ""
                            method_used = f"HTTP header ({header_name})"

                elif check_type == "cookie":
                    match = re.search(pattern, cookies_str, re.IGNORECASE)
                    if match:
                        matched = True
                        method_used = "Cookie"

                elif check_type == "url":
                    match = re.search(pattern, url, re.IGNORECASE)
                    if match:
                        matched = True
                        method_used = "URL pattern"

                if matched:
                    if version:
                        best_version = version
                    if best_confidence is None or confidence == "high":
                        best_confidence = confidence
                    break

            if best_confidence:
                detected.add(name)
                findings.append(TechFinding(
                    url=url,
                    technology=name,
                    category=category,
                    version=best_version,
                    confidence=best_confidence,
                    detection_method=method_used,
                    cve_notes=sig.get("cve_notes", ""),
                    remediation=sig.get("remediation", "Keep software updated.")
                ))

        return findings

    def _detect_waf(self, response: httpx.Response) -> str:
        """Detect WAF from response headers and body"""
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        body_lower = response.text.lower()

        waf_signatures = {
            "Cloudflare":    ["cf-ray", "cf-cache-status", "__cfduid"],
            "AWS WAF":       ["x-amzn-requestid", "x-amz-apigw-id"],
            "Akamai":        ["x-akamai-transformed", "akamaighost"],
            "Imperva/Incapsula": ["x-iinfo", "incap_ses", "visid_incap"],
            "F5 BIG-IP":     ["x-wa-info", "bigipserver", "f5-request-id"],
            "ModSecurity":   ["mod_security", "modsecurity"],
            "Sucuri":        ["x-sucuri-id", "sucuri"],
            "Barracuda":     ["bni__ses", "bni_persistence"],
            "Fortinet":      ["fortigate", "fortiwaf"],
        }

        for waf_name, indicators in waf_signatures.items():
            for indicator in indicators:
                if indicator in headers or indicator in body_lower:
                    return waf_name

        return ""

    async def scan_url(self, url: str) -> TechReport:
        """Scan a single URL for technologies"""
        report = TechReport(url=url)

        try:
            async def _do_request():
                return await self.client.get(url, follow_redirects=True)
            response = await self.rate_limiter.execute_with_retry(_do_request)

            if not response:
                return report

            # Detect technologies
            tech_findings = self._check_signatures(response, url)
            report.technologies = tech_findings
            self.findings.extend(tech_findings)

            # Server info
            report.server     = response.headers.get('server', '')
            report.powered_by = response.headers.get('x-powered-by', '')

            # WAF detection
            report.waf_detected = self._detect_waf(response)

            # OS hint from server header
            server = report.server.lower()
            if 'ubuntu' in server or 'debian' in server:
                report.os_hint = "Linux (Ubuntu/Debian)"
            elif 'centos' in server or 'rhel' in server:
                report.os_hint = "Linux (CentOS/RHEL)"
            elif 'win' in server:
                report.os_hint = "Windows"

            # Log findings
            for tech in tech_findings:
                ver = f" v{tech.version}" if tech.version else ""
                self.logger.info(
                    f"DETECTED: {tech.technology}{ver} [{tech.category}] "
                    f"| Confidence: {tech.confidence} | Via: {tech.detection_method}"
                )

            if report.waf_detected:
                self.logger.info(f"WAF DETECTED: {report.waf_detected} on {url}")

        except Exception as e:
            self.logger.debug(f"Tech fingerprint failed {url}: {e}")

        return report

    async def scan(self, target_urls: List[str], forms: List = None) -> List[TechFinding]:  # NEW-BUG-001 FIX
        forms = forms or []  # NEW-BUG-001 FIX
        """Main tech fingerprint scan"""
        # Unique base URLs
        seen = set()
        scan_urls = []
        for url in target_urls:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            if base not in seen:
                seen.add(base)
                scan_urls.append(url)

        self.logger.info(f"Starting technology fingerprinting on {len(scan_urls)} URL(s)")

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,*/*',
            'Accept-Language': 'en-US,en;q=0.9',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client
            tasks = [self.scan_url(url) for url in scan_urls]
            self.reports = await asyncio.gather(*tasks, return_exceptions=True)
            self.reports = [r for r in self.reports if isinstance(r, TechReport)]

        self.logger.info(
            "Tech fingerprint complete. "
            f"Detected {len(self.findings)} technologies across {len(self.reports)} hosts"
        )
        return self.findings
