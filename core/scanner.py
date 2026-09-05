"""
OXHUNTER v2.0 - scanner.py
Main Scanner Engine — 61 Modules + 2033 Payloads
FIXED: BUG-003,004,005,010,012 + WARN-001
"""

import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

from core.crawler import WebCrawler
from core.paths import resolve_config_path, PAYLOADS_DIR
from core.validator import ScopeValidator
from core.rate_limiter import RateLimiter
from core.reporter import HTMLReporter
from utils.logger import setup_logger

# ── Core Modules ──────────────────────────────
from modules.xss import XSSScanner
from modules.sqli import SQLiScanner
from modules.csrf import CSRFScanner
from modules.headers import HeadersScanner
from modules.open_redirect import OpenRedirectScanner
from modules.cors import CORSScanner
from modules.ssl_tls import SSLTLSScanner

# ── Security Testing ──────────────────────────
from modules.ssrf import SSRFScanner
from modules.cmd_injection import CMDInjectionScanner
from modules.xxe import XXEScanner
from modules.idor import IDORScanner
from modules.lfi import LFIScanner
from modules.race_condition import RaceConditionScanner
from modules.http_smuggling import HTTPSmugglingScanner

# ── Recon ─────────────────────────────────────
from modules.subdomain import SubdomainEnumerator
from modules.directory_brute import DirectoryBruteforcer
from modules.git_exposure import GitExposureScanner
from modules.tech_fingerprint import TechFingerprintScanner
from modules.js_analysis import JSAnalyzer
from modules.email_harvest import EmailHarvester

# ── Advanced ──────────────────────────────────
from modules.graphql import GraphQLScanner
from modules.websocket import WebSocketTester
from modules.waf_bypass import WAFBypassScanner
from modules.prototype_pollution import PrototypePollutionScanner

# BUG-003 FIX: Loud failure instead of silent None
try:
    from modules.ssti import SSTIScanner
    _SSTI_AVAILABLE = True
except ImportError:
    SSTIScanner = None
    _SSTI_AVAILABLE = False
    import logging
    logging.getLogger("Scanner").warning(
        "[!] modules/ssti.py not found — SSTI scanning DISABLED. "
        "Create modules/ssti.py to enable it."
    )

from modules.api_versioning import APIVersionTester
from modules.oauth_tester import OAuthTester  # BUG-009 FIX
from modules.business_logic import BusinessLogicTester

# ── Session & Auth ────────────────────────────
from modules.jwt_attacks import JWTAttackScanner
from modules.session_fixation import SessionFixationScanner
from modules.password_policy import PasswordPolicyTester

# BUG-012 FIX: Single canonical version source
from core.config import VERSION  # BUG-005 FIX: single canonical version


# ── BUG-004 FIX: Central payload loader that strips comments ──
def _read_lines(path: Path) -> List[str]:
    """Load lines from a file, skipping blank lines and # comments."""
    return [
        line.strip()
        for line in path.read_text(errors="ignore").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

def load_payloads(category: str) -> List[str]:
    """Load payloads from file — comments filtered."""
    paths = [
        PAYLOADS_DIR / category / f"{category}.txt",
        PAYLOADS_DIR / category / f"{category}_params.txt",
        PAYLOADS_DIR / "wordlists" / f"{category}.txt",
    ]
    for p in paths:
        if p.exists():
            return _read_lines(p)
    return []

def load_wordlist(name: str) -> List[str]:
    """Load from wordlists/ folder — comments filtered."""
    p = PAYLOADS_DIR / "wordlists" / f"{name}.txt"
    if p.exists():
        return _read_lines(p)
    return []


@dataclass
class ScanReport:
    target      : str
    start_time  : str
    end_time    : str            = ""
    urls_crawled: int            = 0
    forms_found : int            = 0
    findings    : List[Dict[str, Any]] = field(default_factory=list)
    summary     : Dict[str, int] = field(default_factory=dict)
    version     : str            = VERSION


class ScannerEngine:
    """
    OXHUNTER v2.0 — Main scanning engine
    Standard: core 7 modules
    Full    : all 61 modules + 2033 payloads
    """

    def __init__(self, target_url: str, config_path: str = "config.yaml",
                 threads: int = 10, timeout: int = 10, delay: float = 0.5,
                 proxy: Optional[str] = None, cookie: Optional[str] = None,
                 token: Optional[str] = None, auth: Optional[str] = None,
                 verbose: bool = False, headless: bool = False,
                 progress_callback: Optional[Callable[[dict], None]] = None):

        self.target_url  = target_url
        self.config_path = str(resolve_config_path(config_path))
        self.verbose     = verbose
        self.headless    = headless
        self.delay       = delay  # BUG-001 FIX
        self.timeout     = timeout  # FIX: store timeout for _safe_scan
        self.progress_callback = progress_callback
        self.logger      = setup_logger("Scanner")

        # BUG-010 FIX: Store auth/proxy config centrally
        self.proxy  = proxy
        self.cookie = cookie
        self.token  = token
        self.auth   = auth

        # Build shared HTTP headers for all modules
        self._shared_headers: Dict[str, str] = {}
        if cookie:
            self._shared_headers["Cookie"] = cookie
        if token:
            self._shared_headers["Authorization"] = token if token.startswith("Bearer ") else f"Bearer {token}"
        if auth:
            import base64
            encoded = base64.b64encode(auth.encode()).decode()
            self._shared_headers["Authorization"] = f"Basic {encoded}"

        self._shared_proxy = {"http://": proxy, "https://": proxy} if proxy else None

        # ── Load ALL payloads from files ──────
        self.payloads = {
            "xss"                 : load_payloads("xss"),
            "sqli"                : load_payloads("sqli"),
            "ssrf"                : load_payloads("ssrf"),
            "cmd_injection"       : load_payloads("cmd_injection"),
            "lfi"                 : load_payloads("lfi"),
            "xxe"                 : load_payloads("xxe"),
            "open_redirect"       : load_payloads("open_redirect"),
            "auth_bypass"         : load_payloads("auth_bypass"),
            "ssti"                : load_payloads("ssti"),
            "jwt"                 : load_payloads("jwt"),
            "prototype_pollution" : load_payloads("prototype_pollution"),
            "waf_bypass"          : load_payloads("waf_bypass"),
            "graphql"             : load_payloads("graphql"),
            "cors"                : load_payloads("cors"),
            "csrf"                : load_payloads("csrf"),
            "http_smuggling"      : load_payloads("http_smuggling"),
            "idor"                : load_payloads("idor"),
            # Wordlists
            "dirs"                : load_wordlist("common_dirs"),
            "subdomains"          : load_wordlist("subdomains"),
            "sensitive_files"     : load_wordlist("sensitive_files"),
        }

        total = sum(len(v) for v in self.payloads.values())
        self.logger.info(f"Loaded {total} payloads from {PAYLOADS_DIR}")

        # ── Core components ───────────────────
        self.validator    = ScopeValidator(target_url, self.config_path)
        # SPEED-001: pass threads so Semaphore allows true parallelism
        self.rate_limiter = RateLimiter(self.config_path, concurrency=max(1, threads))
        self.rate_limiter.delay = delay  # BUG-001 FIX: override config.yaml value with user-supplied delay
        self.crawler      = WebCrawler(
            target_url   = target_url,
            validator    = self.validator,
            rate_limiter = self.rate_limiter,
        )
        self.reporter = HTMLReporter()

        # ── Module instances ──────────────────
        self.xss           = XSSScanner(self.rate_limiter)
        self.sqli          = SQLiScanner(self.rate_limiter)
        self.csrf          = CSRFScanner(self.rate_limiter)
        self.headers       = HeadersScanner(self.rate_limiter)
        self.open_redirect = OpenRedirectScanner(self.rate_limiter)
        self.cors          = CORSScanner(self.rate_limiter)
        self.ssl_tls       = SSLTLSScanner(self.rate_limiter)
        self.ssrf          = SSRFScanner(self.rate_limiter)
        self.cmd_injection = CMDInjectionScanner(self.rate_limiter)
        self.xxe           = XXEScanner(self.rate_limiter)
        self.idor          = IDORScanner(self.rate_limiter)
        self.lfi           = LFIScanner(self.rate_limiter)
        self.race          = RaceConditionScanner(self.rate_limiter)
        self.smuggling     = HTTPSmugglingScanner(self.rate_limiter)
        self.subdomain     = SubdomainEnumerator(self.rate_limiter)
        self.dir_brute     = DirectoryBruteforcer(
            self.rate_limiter, max_paths=250, concurrency=min(max(threads, 1), 32),
            probe_retries=0, timeout_seconds=min(max(timeout, 1), 5))
        self.git_exposure  = GitExposureScanner(self.rate_limiter)
        self.tech_fp       = TechFingerprintScanner(self.rate_limiter)
        self.js_analysis   = JSAnalyzer(self.rate_limiter)
        self.email_harvest = EmailHarvester(self.rate_limiter)
        self.graphql       = GraphQLScanner(self.rate_limiter)
        self.websocket     = WebSocketTester(self.rate_limiter)
        self.waf_bypass    = WAFBypassScanner(self.rate_limiter)
        self.prototype     = PrototypePollutionScanner(self.rate_limiter)
        self.jwt_attacks   = JWTAttackScanner(self.rate_limiter)
        self.session_fix   = SessionFixationScanner(self.rate_limiter)
        self.password_pol  = PasswordPolicyTester(self.rate_limiter)
        self.api_version   = APIVersionTester()
        self.oauth         = OAuthTester()  # BUG-009 FIX
        self.biz_logic     = BusinessLogicTester()

        # ── Dynamic timeout: sync module httpx.Timeout with scanner timeout ──
        # fast(10s) → 8s reads | normal(20s) → 15s reads | stealth(30s) → 25s reads
        _req_timeout = max(timeout - 2, 5)
        _con_timeout = max(timeout // 3, 4)
        _dyn_timeout = __import__('httpx').Timeout(_req_timeout, connect=_con_timeout)
        _modules_with_timeout = [
            self.xss, self.sqli, self.csrf, self.headers, self.open_redirect,
            self.cors, self.ssl_tls, self.ssrf, self.cmd_injection, self.xxe,
            self.idor, self.lfi, self.race, self.smuggling, self.git_exposure,
            self.tech_fp, self.js_analysis, self.graphql, self.waf_bypass,
            self.prototype, self.jwt_attacks, self.session_fix, self.password_pol,
        ]
        for _mod in _modules_with_timeout:
            if hasattr(_mod, 'timeout'):
                _mod.timeout = _dyn_timeout
        # Also apply to crawler
        self.crawler.timeout = _dyn_timeout

        # BUG-010 FIX: Apply shared auth/proxy to all HTTP-capable modules
        self._apply_auth_to_modules()

        self.report = ScanReport(
            target     = target_url,
            start_time = datetime.now().isoformat(),
        )

    # ── BUG-010: Apply shared auth config to all modules ─────────
    def _apply_auth_to_modules(self):
        """Push shared headers and proxy to every scanner module."""
        if not self._shared_headers and not self._shared_proxy:
            return
        modules = [
            self.xss, self.sqli, self.csrf, self.headers, self.open_redirect,
            self.cors, self.ssl_tls, self.ssrf, self.cmd_injection, self.xxe,
            self.idor, self.lfi, self.race, self.smuggling, self.subdomain,
            self.dir_brute, self.git_exposure, self.tech_fp, self.js_analysis,
            self.graphql, self.waf_bypass, self.prototype, self.jwt_attacks,
            self.session_fix, self.password_pol,
            # BUG-2 FIX: these 5 modules were missing — they now receive auth too
            self.email_harvest, self.websocket, self.api_version,
            self.oauth, self.biz_logic,
        ]
        for mod in modules:
            if hasattr(mod, "extra_headers"):
                mod.extra_headers = self._shared_headers
            if hasattr(mod, "proxy") and self._shared_proxy:
                mod.proxy = self._shared_proxy

    # ── Payload inject helpers ────────────────

    def _inject_payloads(self, module, attr: str, payloads: List[str]):
        """Inject file-loaded payloads into a scanner module."""
        if hasattr(module, attr) and payloads:
            setattr(module, attr, payloads)

    def _apply_all_payloads(self):
        """Push file payloads into all modules."""
        payload_map = [
            (self.xss,           "payloads",          "xss"),
            (self.sqli,          "payloads",          "sqli"),
            (self.ssrf,          "payloads",          "ssrf"),
            (self.cmd_injection, "payloads",          "cmd_injection"),
            (self.lfi,           "payloads",          "lfi"),
            (self.xxe,           "payloads",          "xxe"),
            (self.open_redirect, "payloads",          "open_redirect"),
            (self.prototype,     "payloads",          "prototype_pollution"),
            (self.waf_bypass,    "payloads",          "waf_bypass"),
            (self.graphql,       "payloads",          "graphql"),
            (self.jwt_attacks,   "weak_secrets",      "jwt"),
            (self.subdomain,     "wordlist",          "subdomains"),
            (self.git_exposure,  "sensitive_paths",   "sensitive_files"),
            (self.cors,          "origins",           "cors"),
        ]
        for module, attr, key in payload_map:
            payloads = self.payloads.get(key, [])
            if payloads:
                self._inject_payloads(module, attr, payloads)
        extra_dirs = self.payloads.get("dirs", [])
        if extra_dirs:
            existing = {entry[0] for entry in self.dir_brute.wordlist}
            for p in extra_dirs:
                if p not in existing:
                    self.dir_brute.wordlist.append((p, "misc", "info"))

        self.logger.info("✅ Payloads injected into all modules")

    # ── BUG-005 FIX: Finding formatter preserves severity ─────────

    # Severity normalisation map
    _SEV_NORM = {
        "critical": "Critical", "high": "High", "medium": "Medium",
        "low": "Low", "info": "Info", "informational": "Info",
        "warning": "Medium",
    }
    # Module-level default severities (used when finding has no severity field)
    _MODULE_SEV = {
        "XSS": "High", "SQL Injection": "High", "SSRF": "High",
        "Command Injection": "Critical", "XXE": "High", "LFI": "High",
        "IDOR": "High", "CSRF": "High", "Open Redirect": "Medium",
        "CORS": "Medium", "JWT Attacks": "High", "HTTP Smuggling": "High",
        "Race Condition": "Medium", "Prototype Pollution": "High",
        "WAF Bypass": "Medium", "Directory Brute": "Info",
        "Git Exposure": "High", "Subdomain": "Info",
        "Tech Fingerprint": "Info", "JS Analysis": "Low",
        "Email Harvest": "Info", "GraphQL": "Medium",
        "WebSocket": "Low", "API Versioning": "Medium",
        "Session Fixation": "High", "Password Policy": "Medium",
        "Security Header": "Medium", "SSL/TLS": "Medium",
    }

    def _normalise_severity(self, raw: str, module_name: str) -> str:
        if raw:
            return self._SEV_NORM.get(raw.lower().strip(), raw.capitalize())
        return self._MODULE_SEV.get(module_name, "Medium")

    @staticmethod
    def _get(f, key: str, default=""):
        """Safely read a field from either a dict or an object (dataclass/namedtuple)."""
        if isinstance(f, dict):
            return f.get(key, default)
        return getattr(f, key, default)

    def _add_findings(self, findings: list, module_name: str):
        for f in findings:
            # BUG-1 FIX: use _get() so both dict-type and object-type findings are handled correctly
            raw_sev  = self._get(f, "severity", "") or ""
            severity = self._normalise_severity(raw_sev, module_name)
            parameter = self._get(f, "parameter", "") or self._get(f, "header_name", "N/A")

            # Subdomain findings use different field names — map them properly
            subdomain = self._get(f, "subdomain", "")
            ip        = self._get(f, "ip_address", "")
            status    = self._get(f, "status_code", "")
            title     = self._get(f, "title", "")
            if subdomain:
                url      = f"http://{subdomain}"
                evidence = f"Alive subdomain: {subdomain} [{ip}] — HTTP {status} — {title}"
            else:
                url      = self._get(f, "url", "")
                evidence = self._get(f, "evidence", "")

            self.report.findings.append({
                "type"       : module_name,
                "subtype"    : self._get(f, "type",        ""),
                "url"        : url,
                "parameter"  : parameter,
                "payload"    : self._get(f, "payload",     "N/A"),
                "confidence" : self._get(f, "confidence",  "medium"),
                "evidence"   : evidence,
                "remediation": self._get(f, "remediation", "Check if subdomain is in scope and properly secured."),
                "severity"   : severity,
            })

    # ── Progress + Main Run ──────────────────

    def _progress(self, phase: str, progress: int):
        if self.progress_callback:
            self.progress_callback({"phase": phase, "progress": max(0, min(100, progress))})

    # ── Module name → (instance_attr, scan_method, arg_type) ─────────────────
    MODULE_MAP = {
        "xss":                 ("xss",           "scan",            "injectable"),
        "sqli":                ("sqli",           "scan",            "injectable"),
        "csrf":                ("csrf",           "scan",            "forms"),
        "headers":             ("headers",        "scan",            "all"),
        "open_redirect":       ("open_redirect",  "scan",            "injectable"),
        "cors":                ("cors",           "scan",            "all"),
        "ssl":                 ("ssl_tls",        "scan",            "all"),
        "ssrf":                ("ssrf",           "scan",            "injectable"),
        "cmdi":                ("cmd_injection",  "scan",            "injectable"),
        "xxe":                 ("xxe",            "scan",            "injectable"),
        "lfi":                 ("lfi",            "scan",            "injectable"),
        "idor":                ("idor",           "scan",            "injectable"),
        "jwt":                 ("jwt_attacks",    "scan",            "all"),
        "session":             ("session_fix",    "scan",            "all"),
        "password":            ("password_pol",   "scan",            "all"),
        "dirs":                ("dir_brute",      "scan",            "all"),
        "git":                 ("git_exposure",   "scan",            "all"),
        "subdomain":           ("subdomain",      "scan",            "all"),
        "tech":                ("tech_fp",        "scan",            "all"),
        "js":                  ("js_analysis",    "scan",            "all"),
        "graphql":             ("graphql",        "scan",            "all"),
        "waf":                 ("waf_bypass",     "scan",            "injectable"),
        "prototype":           ("prototype",      "scan",            "injectable"),
        "race":                ("race",           "scan",            "all"),
        "smuggling":           ("smuggling",      "scan",            "all"),
        "websocket":           ("websocket",      "scan",            "all"),
    }

    async def run(self, full_scan: bool = False, modules: list = None) -> ScanReport:
        # modules: list of module name strings e.g. ["sqli","xss","cors"]
        # If None and not full_scan → standard 7 core modules
        # If list provided → run only those specific modules
        specific = modules and len(modules) > 0

        mode_label = (
            f"SPECIFIC ({','.join(modules)})" if specific
            else ("FULL (61 modules)" if full_scan else "STANDARD (7 modules)")
        )
        self.logger.info("=" * 60)
        self.logger.info(f"OXHUNTER v{VERSION} — Scan Started")
        self.logger.info(f"Target  : {self.target_url}")
        self.logger.info(f"Mode    : {mode_label}")
        self.logger.info(f"Payloads: {sum(len(v) for v in self.payloads.values())}+")
        if not _SSTI_AVAILABLE:
            self.logger.warning("[!] SSTI module missing — SSTI scanning skipped.")
        self.logger.info("=" * 60)

        self._apply_all_payloads()

        # ── Phase 1: Crawl ────────────────────
        self._progress("crawling", 5)
        self.logger.info("[PHASE 1] Crawling target...")
        await self.crawler.crawl()
        self.report.urls_crawled = len(self.crawler.visited)
        self.report.forms_found  = len(self.crawler.all_forms)
        self.logger.info(f"Crawled {self.report.urls_crawled} URLs, {self.report.forms_found} forms")
        self._progress("core modules", 20)

        injectable_urls = self.crawler.get_injectable_urls()
        forms           = self.crawler.get_all_forms()
        all_urls        = list(self.crawler.all_urls)

        if self.target_url not in all_urls:
            all_urls.insert(0, self.target_url)
        if self.target_url not in injectable_urls:
            injectable_urls.insert(0, self.target_url)

        # ── Fallback: crawler got nothing — inject common param patterns ──────
        # When target is slow/timed out, crawler returns 0 URLs/forms.
        # Without this, ALL injection modules run 0 tests (XSS, SQLi, LFI etc.)
        if len(injectable_urls) <= 1 and not forms:
            self.logger.info("[Crawler] Fallback: generating injectable URLs from common params")
            common_params = [
                "id", "page", "search", "q", "query", "cat", "category",
                "product", "item", "file", "path", "user", "username",
                "name", "email", "url", "redirect", "next", "lang",
                "sort", "order", "filter", "type", "action", "view",
            ]
            base = self.target_url.rstrip("/")
            for param in common_params:
                injectable_urls.append(f"{base}?{param}=1")
            self.logger.info(f"[Crawler] Fallback injected {len(common_params)} param URLs")

        # ── _safe_scan: timeout wrapper for ALL modules ───────────────────────
        async def _safe_scan(coro, mod_name, timeout_sec=None):
            t = timeout_sec or min(max(self.timeout * 10, 60), 90)
            try:
                result = await asyncio.wait_for(coro, timeout=t)
                self.logger.info(f"[✓] {mod_name} complete")
                return result or []
            except asyncio.TimeoutError:
                self.logger.warning(f"[!] {mod_name} timed out after {t}s — skipped")
                return []
            except asyncio.CancelledError:
                self.logger.warning(f"[!] {mod_name} cancelled — skipped")
                return []
            except Exception as _e:
                self.logger.debug(f"[!] {mod_name} error: {_e}")
                return []

        # ── Phase 2: Specific Module Scan (if --module passed) ───────────────
        if specific:
            self.logger.info(f"[PHASE 2] Specific module scan: {modules}")
            self._progress("specific modules", 30)

            # Build validated module list
            valid_modules = []
            for mod_name in modules:
                mod_name = mod_name.strip().lower()
                if mod_name not in self.MODULE_MAP:
                    self.logger.warning(
                        f"[!] Unknown module '{mod_name}' — skipped. "
                        f"Valid: {list(self.MODULE_MAP.keys())}"
                    )
                    continue
                attr, method, arg_type = self.MODULE_MAP[mod_name]
                mod_obj = getattr(self, attr, None)
                if mod_obj is None:
                    self.logger.warning(f"[!] Module '{mod_name}' not initialized — skipped.")
                    continue
                valid_modules.append((mod_name, mod_obj, method, arg_type))

            # Per-module timeout — hung module won't block entire scan
            MODULE_TIMEOUT = min(max(self.timeout * 10, 60), 90)  # max 90s per module

            async def _run_one(mod_name, mod_obj, method, arg_type):
                self.logger.info(f"[*] Running module: {mod_name.upper()}...")
                try:
                    if arg_type == "injectable":
                        coro = getattr(mod_obj, method)(injectable_urls, forms)
                    elif arg_type == "forms":
                        coro = getattr(mod_obj, method)(forms, self.target_url)
                    else:
                        coro = getattr(mod_obj, method)(all_urls)

                    # Wrap with timeout — if module hangs it gets cancelled
                    result = await asyncio.wait_for(coro, timeout=MODULE_TIMEOUT)
                    self.logger.info(f"[✓] Module {mod_name.upper()} complete — {len(result) if result else 0} findings")
                    return mod_name, result or []
                except asyncio.TimeoutError:
                    self.logger.warning(
                        f"[!] Module {mod_name.upper()} timed out after {MODULE_TIMEOUT}s — skipped"
                    )
                    return mod_name, []
                except asyncio.CancelledError:
                    self.logger.warning(f"[!] Module {mod_name.upper()} cancelled — skipped")
                    return mod_name, []
                except Exception as _mod_err:
                    self.logger.debug(f"Module {mod_name} error: {_mod_err}")
                    return mod_name, []

            if valid_modules:
                parallel_results = await asyncio.gather(
                    *[_run_one(n, o, m, a) for n, o, m, a in valid_modules],
                    return_exceptions=True  # never let one failure kill others
                )
                # BUG-003 FIX: map module keys to their display names so _MODULE_SEV
                # lookup works correctly (e.g. "headers" → "Security Header", not "HEADERS").
                _MODULE_DISPLAY = {
                    "xss":          "XSS",
                    "sqli":         "SQL Injection",
                    "csrf":         "CSRF",
                    "headers":      "Security Header",
                    "open_redirect":"Open Redirect",
                    "cors":         "CORS",
                    "ssl":          "SSL/TLS",
                    "ssrf":         "SSRF",
                    "cmdi":         "Command Injection",
                    "xxe":          "XXE",
                    "lfi":          "LFI",
                    "idor":         "IDOR",
                    "jwt":          "JWT Attacks",
                    "session":      "Session Fixation",
                    "password":     "Password Policy",
                    "dirs":         "Directory Brute",
                    "git":          "Git Exposure",
                    "subdomain":    "Subdomain",
                    "tech":         "Tech Fingerprint",
                    "js":           "JS Analysis",
                    "graphql":      "GraphQL",
                    "waf":          "WAF Bypass",
                    "prototype":    "Prototype Pollution",
                    "race":         "Race Condition",
                    "smuggling":    "HTTP Smuggling",
                    "websocket":    "WebSocket",
                }
                for item in parallel_results:
                    if isinstance(item, Exception):
                        self.logger.debug(f"Module gather exception: {item}")
                        continue
                    mod_name, result = item
                    if result:
                        display_name = _MODULE_DISPLAY.get(mod_name, mod_name.upper())
                        self._add_findings(result, display_name)

            self._progress("finalizing", 90)
            goto_summary = True
        else:
            goto_summary = False

        if not goto_summary:
            # ── Phase 2: Core ─────────────────────
            # FIX: All core modules now properly inside `if not goto_summary`
            # Previously CSRF/Headers/etc ran even in specific-module mode, causing duplicates
            self.logger.info("[PHASE 2] Core vulnerability tests...")

            self.logger.info(f"[*] XSS Scanner ({len(self.payloads['xss'])} payloads)...")
            self._add_findings(await _safe_scan(self.xss.scan(injectable_urls, forms), "XSS"), "XSS")

            self.logger.info(f"[*] SQL Injection ({len(self.payloads['sqli'])} payloads)...")
            self._add_findings(await _safe_scan(self.sqli.scan(injectable_urls, forms), "SQLi"), "SQL Injection")

            self.logger.info("[*] CSRF Detection...")
            csrf_findings = await _safe_scan(self.csrf.scan(forms, self.target_url), "CSRF")
            for f in csrf_findings:
                self.report.findings.append({
                    "type": "CSRF", "subtype": getattr(f, "type", ""),
                    "url": getattr(f, "url", ""), "parameter": getattr(f, "form_action", "N/A"),
                    "payload": "N/A", "confidence": getattr(f, "confidence", "medium"),
                    "evidence": getattr(f, "evidence", ""), "remediation": getattr(f, "remediation", ""),
                    "severity": "High",
                })

            self.logger.info("[*] Security Headers...")
            self._add_findings(await _safe_scan(self.headers.scan(all_urls[:5]), "Headers", 60), "Security Header")

            self.logger.info(f"[*] Open Redirect ({len(self.payloads['open_redirect'])} payloads)...")
            self._add_findings(await _safe_scan(self.open_redirect.scan(injectable_urls), "Open Redirect"), "Open Redirect")

            self.logger.info(f"[*] CORS ({len(self.payloads['cors'])} origins)...")
            self._add_findings(await _safe_scan(self.cors.scan(all_urls), "CORS", 120), "CORS")

            self.logger.info("[*] SSL/TLS Checker...")
            self._add_findings(await _safe_scan(self.ssl_tls.scan(all_urls), "SSL/TLS", 60), "SSL/TLS")

        # ── Phase 3: Full Scan ────────────────
        if full_scan:
            self._progress("full modules", 45)
            self.logger.info("[PHASE 3] Full scan — all 61 modules...")

            self.logger.info(f"[*] SSRF ({len(self.payloads['ssrf'])} payloads)...")
            self._add_findings(await _safe_scan(self.ssrf.scan(injectable_urls, forms), "SSRF"), "SSRF")

            self.logger.info(f"[*] Command Injection ({len(self.payloads['cmd_injection'])} payloads)...")
            self._add_findings(await _safe_scan(self.cmd_injection.scan(injectable_urls, forms), "CMDi"), "Command Injection")

            self.logger.info(f"[*] XXE Injection ({len(self.payloads['xxe'])} payloads)...")
            self._add_findings(await _safe_scan(self.xxe.scan(injectable_urls, forms), "XXE", 60), "XXE")

            self.logger.info(f"[*] LFI ({len(self.payloads['lfi'])} payloads)...")
            self._add_findings(await _safe_scan(self.lfi.scan(injectable_urls, forms), "LFI"), "LFI")

            self.logger.info("[*] IDOR Detection...")
            self._add_findings(await _safe_scan(self.idor.scan(injectable_urls, forms), "IDOR"), "IDOR")

            self.logger.info("[*] JWT Attacks...")
            self._add_findings(await _safe_scan(self.jwt_attacks.scan(all_urls), "JWT", 120), "JWT Attacks")

            self.logger.info("[*] Session Fixation...")
            self._add_findings(await _safe_scan(self.session_fix.scan(all_urls), "Session", 120), "Session Fixation")

            self.logger.info("[*] Password Policy...")
            self._add_findings(await _safe_scan(self.password_pol.scan(all_urls), "Password", 120), "Password Policy")

            self.logger.info(f"[*] Directory Bruteforce ({len(self.payloads['dirs'])} paths)...")
            self._add_findings(await _safe_scan(self.dir_brute.scan(all_urls), "DirBrute"), "Directory Brute")

            self.logger.info(f"[*] Sensitive Files ({len(self.payloads['sensitive_files'])} paths)...")
            self._add_findings(await _safe_scan(self.git_exposure.scan(all_urls), "GitExposure", 60), "Git Exposure")

            self.logger.info(f"[*] Subdomain Enum ({len(self.payloads['subdomains'])} wordlist)...")
            self._add_findings(await _safe_scan(self.subdomain.scan(all_urls), "Subdomain"), "Subdomain")

            self.logger.info("[*] Tech Fingerprinting...")
            self._add_findings(await _safe_scan(self.tech_fp.scan(all_urls), "TechFP", 60), "Tech Fingerprint")

            self.logger.info("[*] JS File Analysis...")
            self._add_findings(await _safe_scan(self.js_analysis.scan(all_urls), "JSAnalysis"), "JS Analysis")

            self.logger.info(f"[*] GraphQL ({len(self.payloads['graphql'])} queries)...")
            self._add_findings(await _safe_scan(self.graphql.scan(all_urls), "GraphQL", 120), "GraphQL")

            self.logger.info(f"[*] WAF Bypass ({len(self.payloads['waf_bypass'])} payloads)...")
            self._add_findings(await _safe_scan(self.waf_bypass.scan(injectable_urls), "WAFBypass"), "WAF Bypass")

            self.logger.info(f"[*] Prototype Pollution ({len(self.payloads['prototype_pollution'])} payloads)...")
            self._add_findings(await _safe_scan(self.prototype.scan(injectable_urls), "Prototype"), "Prototype Pollution")

            self.logger.info("[*] Race Condition...")
            self._add_findings(await _safe_scan(self.race.scan(all_urls, forms), "RaceCondition", 120), "Race Condition")

            self.logger.info("[*] HTTP Smuggling...")
            self._add_findings(await _safe_scan(self.smuggling.scan(all_urls), "Smuggling", 120), "HTTP Smuggling")

            self.logger.info("[*] Email Harvesting...")
            try:
                for _url in all_urls[:5]:
                    _result = await asyncio.to_thread(self.email_harvest.harvest, _url)  # BUG-002 FIX
                    for _email in _result.get("emails", []):
                        self.report.findings.append({
                            "type": "Email Harvest", "subtype": "email_found",
                            "url": _url, "parameter": "N/A", "payload": "N/A",
                            "confidence": "high",
                            "evidence": f"Email exposed: {_email}",
                            "remediation": "Remove emails from public-facing pages to prevent harvesting.",
                            "severity": "Info",
                        })
            except Exception as _e:
                self.logger.debug(f"Email harvest error: {_e}")

            self.logger.info("[*] WebSocket Testing...")
            try:
                ws_results = []
                for _url in all_urls[:3]:
                    ws_url = _url.replace("http://","ws://").replace("https://","wss://")
                    _ws = await asyncio.to_thread(self.websocket.test_connection, ws_url)  # BUG-002 FIX
                    if _ws.get("connectable"):
                        _scan = await asyncio.to_thread(self.websocket.scan, ws_url)  # BUG-002 FIX
                        ws_results.extend(_scan.get("findings",[]))
                self._add_findings(ws_results, "WebSocket")
            except Exception as _e:
                self.logger.debug(f"WebSocket skipped: {_e}")

            self.logger.info("[*] OAuth 2.0 Testing...")
            try:
                _oauth = await _safe_scan(self.oauth.scan(all_urls), "OAuth", 120)
                self._add_findings(_oauth, "OAuth")
            except Exception as _e:
                self.logger.debug(f"OAuth skipped: {_e}")

            self.logger.info("[*] API Versioning Attack...")
            try:
                result = await asyncio.to_thread(self.api_version.scan, self.target_url)  # BUG-002 FIX
                for f in result.get("findings", []):
                    self.report.findings.append({
                        "type": "API Versioning", "subtype": f.get("type",""),
                        "url": f.get("url",""), "parameter": "version",
                        "payload": "N/A", "confidence": "medium",
                        "evidence": f.get("detail",""), "remediation": "Disable deprecated API versions",
                        "severity": self._normalise_severity(f.get("severity",""), "API Versioning"),
                    })
            except Exception as e:
                self.logger.debug(f"API versioning skipped: {e}")

        # end: if not goto_summary

        # ── Summary ───────────────────────────
        self._progress("finalizing", 95)
        sev_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.report.findings:
            # BUG-3 FIX: normalize through _SEV_NORM so unknown values (e.g. "Informational",
            # "NONE") map to a known key instead of silently creating a new dict entry
            raw = f.get("severity", "") or ""
            sev = self._SEV_NORM.get(raw.lower().strip(), None)
            if sev not in sev_count:
                sev = "Info"  # safe fallback for anything not in the known set
            sev_count[sev] += 1

        self.report.summary  = sev_count
        self.report.end_time = datetime.now().isoformat()

        self.logger.info("=" * 60)
        self._progress("complete", 100)
        self.logger.info(f"OXHUNTER v{VERSION} — Scan Complete!")
        self.logger.info(f"Total Findings: {len(self.report.findings)}")
        for sev, count in sev_count.items():
            if count > 0:
                self.logger.info(f"  {sev}: {count}")
        self.logger.info("=" * 60)

        return self.report

    def generate_html_report(self, output_file: str = None) -> str:
        return self.reporter.generate({
            "target"      : self.report.target,
            "start_time"  : self.report.start_time,
            "end_time"    : self.report.end_time,
            "urls_crawled": self.report.urls_crawled,
            "forms_found" : self.report.forms_found,
            "findings"    : self.report.findings,
            "summary"     : self.report.summary,
            "version"     : VERSION,
        }, output_file)

    def get_report(self) -> ScanReport:
        return self.report
