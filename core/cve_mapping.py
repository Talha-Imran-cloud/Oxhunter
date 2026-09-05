"""
OXHUNTER - cve_mapping.py
CVE Mapping via NVD API + local fallback
"""

import requests
import time
from typing import Dict, List, Optional

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Local CVE fallback (common web vulns) ─────
LOCAL_CVE = {
    "xss": [
        {"id": "CVE-2021-44228", "score": 10.0, "desc": "Log4Shell — XSS/RCE via injection"},
        {"id": "CVE-2020-11022", "score": 6.1,  "desc": "jQuery XSS via htmlPrefilter"},
    ],
    "sqli": [
        {"id": "CVE-2012-1823", "score": 7.5, "desc": "PHP CGI argument injection / SQLi"},
        {"id": "CVE-2014-3704", "score": 7.5, "desc": "Drupal SQLi (Drupalgeddon)"},
    ],
    "ssrf": [
        {"id": "CVE-2021-26855", "score": 9.8, "desc": "Exchange Server SSRF (ProxyLogon)"},
        {"id": "CVE-2019-0230",  "score": 9.8, "desc": "Apache Struts SSRF/RCE"},
    ],
    "xxe": [
        {"id": "CVE-2014-0050", "score": 7.5, "desc": "Apache Commons XXE via multipart"},
        {"id": "CVE-2018-1000838","score":9.8, "desc": "XXE in multiple Java parsers"},
    ],
    "command_injection": [
        {"id": "CVE-2014-6271", "score": 10.0, "desc": "Shellshock — bash command injection"},
        {"id": "CVE-2021-41773", "score": 9.8, "desc": "Apache path traversal + RCE"},
    ],
    "ssti": [
        {"id": "CVE-2019-11043", "score": 9.8, "desc": "PHP-FPM SSTI/RCE"},
        {"id": "CVE-2022-22965", "score": 9.8, "desc": "Spring4Shell — Spring SSTI/RCE"},
    ],
    "jwt_attacks": [
        {"id": "CVE-2015-9235", "score": 9.8, "desc": "JWT alg:none attack"},
        {"id": "CVE-2022-21449", "score": 7.4, "desc": "Java ECDSA JWT signature bypass"},
    ],
    "cors": [
        {"id": "CVE-2021-33035", "score": 8.1, "desc": "CORS misconfiguration data exposure"},
    ],
    "prototype_pollution": [
        {"id": "CVE-2019-10744", "score": 9.8, "desc": "lodash prototype pollution"},
        {"id": "CVE-2020-28477", "score": 7.5, "desc": "immer prototype pollution"},
    ],
    "open_redirect": [
        {"id": "CVE-2018-14574", "score": 6.1, "desc": "Django open redirect"},
    ],
    "ssl_issues": [
        {"id": "CVE-2014-0160", "score": 7.5, "desc": "Heartbleed — OpenSSL info disclosure"},
        {"id": "CVE-2014-3566", "score": 3.4, "desc": "POODLE — SSLv3 downgrade"},
    ],
}


class CVEMapper:

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cache: Dict[str, List] = {}

    # ── NVD API Lookup ────────────────────────

    def lookup_nvd(self, keyword: str, limit: int = 3) -> List[Dict]:
        """Fetch CVEs from NVD API by keyword."""
        if keyword in self.cache:
            return self.cache[keyword]

        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            r = requests.get(NVD_API, params={"keywordSearch": keyword,
                             "resultsPerPage": limit}, headers=headers, timeout=10)
            if r.status_code != 200:
                return []

            items = r.json().get("vulnerabilities", [])
            result = []
            for item in items:
                cve  = item.get("cve", {})
                desc = cve.get("descriptions", [{}])[0].get("value", "")
                metrics = cve.get("metrics", {})
                score = 0.0
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    m = metrics.get(key, [])
                    if m:
                        score = m[0].get("cvssData", {}).get("baseScore", 0.0)
                        break
                result.append({"id": cve.get("id"), "score": score, "desc": desc[:120]})

            self.cache[keyword] = result
            time.sleep(0.6)   # NVD rate limit
            return result

        except Exception:
            return []

    # ── Local Fallback ────────────────────────

    def lookup_local(self, vuln_type: str) -> List[Dict]:
        return LOCAL_CVE.get(vuln_type.lower(), [])

    # ── Map Findings ──────────────────────────

    def map_finding(self, vuln_type: str) -> List[Dict]:
        """Get CVEs for a vuln type — NVD first, local fallback."""
        if self.api_key:
            cves = self.lookup_nvd(vuln_type)
            if cves:
                return cves
        return self.lookup_local(vuln_type)

    def map_findings(self, findings: List[Dict]) -> List[Dict]:
        """Add CVE data to each finding."""
        result = []
        seen   = set()
        for f in findings:
            vtype = f.get("vuln_type", "")
            if vtype not in seen:
                seen.add(vtype)
                cves = self.map_finding(vtype)
            else:
                cves = self.lookup_local(vtype)
            result.append({**f, "cves": cves,
                           "top_cve": cves[0]["id"] if cves else None})
        return result

    def summary(self, findings: List[Dict]) -> Dict:
        """Return CVE mapping summary."""
        mapped = self.map_findings(findings)
        all_cves = [c["id"] for f in mapped for c in f.get("cves", [])]
        return {
            "total_findings": len(findings),
            "cves_mapped"   : len(set(all_cves)),
            "cve_ids"       : list(set(all_cves)),
            "findings"      : mapped,
        }
