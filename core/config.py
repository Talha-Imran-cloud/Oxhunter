"""
OXHUNTER - config.py
Global configuration, settings, and API key management
"""

import os
import json
import yaml
from pathlib import Path
import dataclasses
from dataclasses import dataclass, field
from typing import Optional, List, Dict

# ─────────────────────────────────────────────
#  PROJECT PATHS
# ─────────────────────────────────────────────
BASE_DIR        = Path(__file__).parent.parent
CONFIG_FILE     = BASE_DIR / "config.json"
PAYLOADS_DIR    = BASE_DIR / "payloads"
REPORTS_DIR     = BASE_DIR / "reports"
LOGS_DIR        = BASE_DIR / "logs"
DB_PATH         = BASE_DIR / "data" / "oxhunter.db"

# Auto-create directories if not exist
for _dir in [PAYLOADS_DIR, REPORTS_DIR, LOGS_DIR, DB_PATH.parent]:
    _dir.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────
#  VERSION INFO
# ─────────────────────────────────────────────
TOOL_NAME       = "OXHUNTER"
# BUG-005 FIX: Single canonical version from package metadata
try:
    from importlib.metadata import version as _pkg_ver
    VERSION = _pkg_ver("oxhunter")
except Exception:
    VERSION = "2.0.7"  # FIX #3: matches pyproject.toml
AUTHOR          = "OXHUNTER Team"
DESCRIPTION     = "Advanced Web Security Scanner"


# ─────────────────────────────────────────────
#  SCAN DEFAULTS
# ─────────────────────────────────────────────
DEFAULT_TIMEOUT         = 10          # seconds per request
DEFAULT_THREADS         = 10          # concurrent threads
DEFAULT_DELAY           = 0.5         # delay between requests (rate limiting)
DEFAULT_MAX_DEPTH       = 3           # crawler depth
DEFAULT_MAX_PAGES       = 100         # max pages to crawl
DEFAULT_USER_AGENT      = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
DEFAULT_FOLLOW_REDIRECTS = True
DEFAULT_VERIFY_SSL       = False       # skip SSL verify for testing


# ─────────────────────────────────────────────
#  SEVERITY LEVELS
# ─────────────────────────────────────────────
SEVERITY_LEVELS = {
    "CRITICAL" : {"score": 9.0,  "color": "\033[91m"},   # Red
    "HIGH"     : {"score": 7.0,  "color": "\033[91m"},   # Red
    "MEDIUM"   : {"score": 4.0,  "color": "\033[93m"},   # Yellow
    "LOW"      : {"score": 2.0,  "color": "\033[94m"},   # Blue
    "INFO"     : {"score": 0.0,  "color": "\033[92m"},   # Green
}


# ─────────────────────────────────────────────
#  SCAN MODULES (enable/disable)
# ─────────────────────────────────────────────
DEFAULT_MODULES = {
    # Core Modules
    "xss"               : True,
    "sqli"              : True,
    "csrf"              : True,
    "open_redirect"     : True,
    "dir_bruteforce"    : True,
    "subdomain_enum"    : True,
    "header_analyzer"   : True,
    "ssl_checker"       : True,
    "cors"              : True,

    # Security Testing
    "xxe"               : True,
    "ssrf"              : True,
    "command_injection" : True,
    "idor"              : True,
    "race_condition"    : False,   # Heavy — off by default
    "http_smuggling"    : False,   # Heavy — off by default

    # Advanced Recon
    "js_analysis"       : True,
    "graphql"           : True,
    "websocket"         : False,
    "prototype_pollution": True,

    # Session & Auth
    "jwt_attacks"       : True,
    "session_fixation"  : True,

    # Recon
    "email_harvest"     : False,
    "git_exposure"      : True,
    "sensitive_files"   : True,
    "tech_fingerprint"  : True,
}


# ─────────────────────────────────────────────
#  HTTP HEADERS (default scan headers)
# ─────────────────────────────────────────────
DEFAULT_HEADERS = {
    "User-Agent"     : DEFAULT_USER_AGENT,
    "Accept"         : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection"     : "close",
}


# ─────────────────────────────────────────────
#  PROXY SETTINGS
# ─────────────────────────────────────────────
PROXY_SETTINGS = {
    "enabled"   : False,
    "http"      : "http://127.0.0.1:8080",   # Burp Suite default
    "https"     : "http://127.0.0.1:8080",
}


# ─────────────────────────────────────────────
#  RATE LIMITING
# ─────────────────────────────────────────────
RATE_LIMIT = {
    "enabled"           : True,
    "requests_per_second": 5,
    "burst"             : 10,
}


# ─────────────────────────────────────────────
#  API KEYS
# ─────────────────────────────────────────────
API_KEYS = {
    "anthropic"     : os.getenv("ANTHROPIC_API_KEY", ""),      # AI features
    "shodan"        : os.getenv("SHODAN_API_KEY", ""),         # Recon
    "virustotal"    : os.getenv("VIRUSTOTAL_API_KEY", ""),     # Malware check
    "nvd"           : os.getenv("NVD_API_KEY", ""),            # CVE mapping
}


# ─────────────────────────────────────────────
#  REPORTING
# ─────────────────────────────────────────────
REPORT_SETTINGS = {
    "format"        : ["html", "pdf", "json"],   # Output formats
    "language"      : "en",                       # "en" or "ur" (Urdu)
    "company_name"  : "OXHUNTER Security",
    "include_evidence": True,
    "include_remediation": True,
    "cvss_calculator": True,
}


# ─────────────────────────────────────────────
#  WORDLISTS
# ─────────────────────────────────────────────
WORDLISTS = {
    "directories"   : str(PAYLOADS_DIR / "wordlists" / "common_dirs.txt"),
    "subdomains"    : str(PAYLOADS_DIR / "wordlists" / "subdomains.txt"),
    "sensitive_files": str(PAYLOADS_DIR / "wordlists" / "sensitive_files.txt"),
    "passwords"     : str(PAYLOADS_DIR / "wordlists" / "passwords.txt"),   # create this file or remove if unused,
}


# ─────────────────────────────────────────────
#  COMPLIANCE SETTINGS
# ─────────────────────────────────────────────
COMPLIANCE = {
    "owasp_top10"   : True,
    "pci_dss"       : False,
    "iso_27001"     : False,
    "bug_bounty_mode": False,
    "in_scope"      : [],     # List of in-scope domains
    "out_of_scope"  : [],     # List of out-of-scope domains
}


# ─────────────────────────────────────────────
#  INTEGRATIONS
# ─────────────────────────────────────────────
INTEGRATIONS = {
    "slack_webhook" : os.getenv("SLACK_WEBHOOK_URL", ""),
    "discord_webhook": os.getenv("DISCORD_WEBHOOK_URL", ""),
    "jira": {
        "enabled"   : False,
        "url"       : os.getenv("JIRA_URL", ""),
        "user"      : os.getenv("JIRA_USER", ""),
        "token"     : os.getenv("JIRA_TOKEN", ""),
        "project"   : os.getenv("JIRA_PROJECT", ""),
    },
    "github": {
        "enabled"   : False,
        "token"     : os.getenv("GITHUB_TOKEN", ""),
        "repo"      : os.getenv("GITHUB_REPO", ""),
    },
}


# ─────────────────────────────────────────────
#  CONFIG DATACLASS
# ─────────────────────────────────────────────
@dataclass
class ScanConfig:
    """
    Per-scan configuration object.
    Pass this to Scanner and all modules.
    """
    target              : str                       = ""
    targets             : List[str]                 = field(default_factory=list)
    modules             : Dict[str, bool]           = field(default_factory=lambda: dict(DEFAULT_MODULES))
    threads             : int                       = DEFAULT_THREADS
    timeout             : int                       = DEFAULT_TIMEOUT
    delay               : float                     = DEFAULT_DELAY
    max_depth           : int                       = DEFAULT_MAX_DEPTH
    max_pages           : int                       = DEFAULT_MAX_PAGES
    user_agent          : str                       = DEFAULT_USER_AGENT
    headers             : Dict[str, str]            = field(default_factory=lambda: dict(DEFAULT_HEADERS))
    cookies             : Dict[str, str]            = field(default_factory=dict)
    auth_token          : Optional[str]             = None
    auth_type           : str                       = "none"     # none | bearer | basic | jwt | cookie
    proxy               : Optional[str]             = None
    verify_ssl          : bool                      = DEFAULT_VERIFY_SSL
    follow_redirects    : bool                      = DEFAULT_FOLLOW_REDIRECTS
    output_dir          : str                       = str(REPORTS_DIR)
    report_formats      : List[str]                 = field(default_factory=lambda: ["html", "json"])
    severity_filter     : List[str]                 = field(default_factory=lambda: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    compliance_mode     : Optional[str]             = None       # owasp | pci | iso | bugbounty
    resume_scan         : bool                      = False
    scan_id             : Optional[str]             = None
    verbose             : bool                      = False
    silent              : bool                      = False
    ai_features         : bool                      = False      # Requires ANTHROPIC_API_KEY
    language            : str                       = "en"       # en | ur


# ─────────────────────────────────────────────
#  CONFIG LOADER / SAVER
# ─────────────────────────────────────────────
class ConfigManager:
    """Load and save configuration from JSON/YAML file."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path) if config_path else CONFIG_FILE

    def load(self) -> dict:
        """Load config from file."""
        if not self.config_path.exists():
            return {}
        try:
            suffix = self.config_path.suffix.lower()
            with open(self.config_path, "r", encoding="utf-8") as f:
                if suffix in (".yaml", ".yml"):
                    return yaml.safe_load(f) or {}
                else:
                    return json.load(f)
        except Exception as e:
            print(f"[!] Config load error: {e}")
            return {}

    def save(self, data: dict) -> bool:
        """Save config to file."""
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            return True
        except Exception as e:
            print(f"[!] Config save error: {e}")
            return False

    def build_scan_config(self, cli_args: dict) -> ScanConfig:
        """
        Merge file config + CLI args into a ScanConfig object.
        CLI args take priority over file config.
        """
        file_cfg = self.load()
        merged   = {**file_cfg, **{k: v for k, v in cli_args.items() if v is not None}}
        return ScanConfig(**{  # BUG-008 FIX: use dataclasses.fields() instead of __dataclass_fields__
            f.name: merged[f.name] for f in dataclasses.fields(ScanConfig) if f.name in merged
        })

    @staticmethod
    def from_env() -> "ConfigManager":
        """Load config path from environment variable."""
        path = os.getenv("OXHUNTER_CONFIG", str(CONFIG_FILE))
        return ConfigManager(path)


# ─────────────────────────────────────────────
#  QUICK ACCESS FUNCTIONS
# ─────────────────────────────────────────────
def get_default_config() -> ScanConfig:
    return ScanConfig()

def is_module_enabled(module_name: str) -> bool:
    return DEFAULT_MODULES.get(module_name, False)

def get_api_key(service: str) -> Optional[str]:
    key = API_KEYS.get(service, "")
    return key if key else None
