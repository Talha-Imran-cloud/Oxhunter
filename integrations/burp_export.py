"""
OXHUNTER - burp_export.py
Burp Suite Integration — Import/Export findings, XML parsing, scan sync
"""

import json
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import base64
from pathlib import Path
from typing import Dict, List
from datetime import datetime
from urllib.parse import urlparse


# ─────────────────────────────────────────────
#  SEVERITY MAPPING (Burp ↔ OXHUNTER)
# ─────────────────────────────────────────────
BURP_TO_OX = {
    "High"              : "HIGH",
    "Medium"            : "MEDIUM",
    "Low"               : "LOW",
    "Information"       : "INFO",
    "False positive"    : "INFO",
}
OX_TO_BURP = {v: k for k, v in BURP_TO_OX.items()}
OX_TO_BURP["CRITICAL"] = "High"


# ─────────────────────────────────────────────
#  BURP XML EXPORTER
# ─────────────────────────────────────────────
class BurpExporter:
    """Export OXHUNTER findings to Burp Suite XML format."""

    @staticmethod
    def _issue_element(finding: Dict) -> ET.Element:
        issue = ET.Element("issue")

        def sub(tag, text=""):
            el = ET.SubElement(issue, tag)
            el.text = str(text) if text else ""
            return el

        parsed   = urlparse(finding.get("url",""))
        host     = parsed.netloc
        # BUG-013 FIX: removed unused 'port' and 'protocol' variables
        path     = parsed.path or "/"
        severity = OX_TO_BURP.get(finding.get("severity","INFO"), "Information")

        sub("serialNumber",     str(abs(hash(finding.get("url","") + finding.get("vuln_type","")))))
        sub("type",             "0x00100200")
        sub("name",             finding.get("vuln_type","Unknown").replace("_"," ").title())
        sub("host",             host).set("ip", "")
        sub("path",             path)
        sub("location",         finding.get("url",""))
        sub("severity",         severity)
        sub("confidence",       "Certain" if finding.get("cvss_score",0) >= 7 else "Firm")
        sub("issueBackground",  finding.get("detail",""))
        sub("remediationBackground", finding.get("remediation",""))
        sub("issueDetail",
            f"OXHUNTER detected: {finding.get('vuln_type','')} at {finding.get('url','')}\n"
            f"Payload: {finding.get('payload','N/A')}\n"
            f"CVSS Score: {finding.get('cvss_score','N/A')}\n"
            f"Evidence: {finding.get('evidence','N/A')}")
        sub("remediationDetail", finding.get("remediation",""))
        sub("vulnerabilityClassifications", f"CWE: {_vuln_to_cwe(finding.get('vuln_type',''))}")

        # Request/Response block
        if finding.get("payload"):
            req_raw   = (f"GET {path}?q={finding.get('payload','')} HTTP/1.1\r\n"
                         f"Host: {host}\r\nUser-Agent: OXHUNTER/1.0\r\n\r\n")
            resp_raw  = finding.get("evidence","HTTP/1.1 200 OK\r\n\r\n")
            req_resp  = ET.SubElement(issue, "requestresponse")
            req_el    = ET.SubElement(req_resp, "request")
            req_el.set("base64", "true")
            req_el.text = base64.b64encode(req_raw.encode()).decode()
            resp_el   = ET.SubElement(req_resp, "response")
            resp_el.set("base64", "true")
            resp_el.text = base64.b64encode(resp_raw.encode()).decode()

        return issue

    def export(self, findings: List[Dict], output_path: str = "") -> str:
        """Export findings to Burp XML file."""
        root = ET.Element("issues")
        root.set("burpVersion", "2023.12.0")
        root.set("exportTime",  datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y"))

        for f in findings:
            root.append(self._issue_element(f))

        xml_str  = ET.tostring(root, encoding="unicode")
        pretty   = minidom.parseString(xml_str).toprettyxml(indent="  ")
        # Remove extra XML declaration added by minidom
        lines    = pretty.split("\n")[1:]
        final    = "\n".join(lines)

        path = output_path or f"reports/burp_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(final, encoding="utf-8")
        print(f"[+] Burp XML exported → {path}")
        return path

    def export_json(self, findings: List[Dict], output_path: str = "") -> str:
        """Export as Burp-compatible JSON (for newer Burp versions)."""
        burp_findings = []
        for f in findings:
            burp_findings.append({
                "issue_type"    : _vuln_to_burp_type(f.get("vuln_type","")),
                "issue_name"    : f.get("vuln_type","").replace("_"," ").title(),
                "url"           : f.get("url",""),
                "severity"      : OX_TO_BURP.get(f.get("severity","INFO"), "Information"),
                "confidence"    : "Certain" if f.get("cvss_score",0) >= 7 else "Firm",
                "issue_detail"  : f.get("detail",""),
                "remediation"   : f.get("remediation",""),
                "payload"       : f.get("payload",""),
                "cvss_score"    : f.get("cvss_score",""),
                "cwe"           : _vuln_to_cwe(f.get("vuln_type","")),
                "owasp"         : f.get("owasp",""),
                "evidence"      : f.get("evidence",""),
                "tool"          : "OXHUNTER",
            })

        data = {
            "type"       : "burp_findings_export",
            "version"    : "1.0",
            "exported_at": datetime.now().isoformat(),
            "findings"   : burp_findings,
        }
        path = output_path or f"reports/burp_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"[+] Burp JSON exported → {path}")
        return path


# ─────────────────────────────────────────────
#  BURP XML IMPORTER
# ─────────────────────────────────────────────
class BurpImporter:
    """Import Burp Suite scan results into OXHUNTER format."""

    @staticmethod
    def parse_xml(xml_path: str) -> List[Dict]:
        """Parse Burp XML export and convert to OXHUNTER findings."""
        findings = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for issue in root.findall("issue"):
                def get(tag, _issue=issue):  # BUG-006 FIX: capture loop var by default arg
                    el = _issue.find(tag)
                    return el.text.strip() if el is not None and el.text else ""

                severity_raw = get("severity")
                severity     = BURP_TO_OX.get(severity_raw, "INFO")
                vuln_type    = _burp_name_to_type(get("name"))

                # Decode request if base64
                request = ""
                req_el  = issue.find(".//request")
                if req_el is not None and req_el.text:
                    try:
                        request = base64.b64decode(req_el.text).decode("utf-8","ignore")
                    except Exception:
                        request = req_el.text

                findings.append({
                    "vuln_type"  : vuln_type,
                    "url"        : get("location") or (get("host") + get("path")),
                    "severity"   : severity,
                    "detail"     : get("issueDetail") or get("issueBackground"),
                    "remediation": get("remediationDetail") or get("remediationBackground"),
                    "evidence"   : request[:500] if request else "",
                    "source"     : "burp_import",
                    "confidence" : get("confidence"),
                })

        except Exception as e:
            print(f"[!] Burp XML parse error: {e}")

        return findings

    @staticmethod
    def parse_json(json_path: str) -> List[Dict]:
        """Parse Burp JSON export."""
        try:
            data     = json.loads(Path(json_path).read_text())
            findings = data.get("findings", data.get("issues", []))
            result   = []
            for f in findings:
                severity = BURP_TO_OX.get(f.get("severity",""), "INFO")
                result.append({
                    "vuln_type"  : _burp_name_to_type(f.get("issue_name","")),
                    "url"        : f.get("url",""),
                    "severity"   : severity,
                    "detail"     : f.get("issue_detail",""),
                    "remediation": f.get("remediation",""),
                    "source"     : "burp_import",
                })
            return result
        except Exception as e:
            print(f"[!] Burp JSON parse error: {e}")
            return []

    @staticmethod
    def merge(burp_findings: List[Dict],
              ox_findings: List[Dict]) -> List[Dict]:
        """Merge Burp + OXHUNTER findings, deduplicate by URL+type."""
        seen   = set()
        merged = []
        for f in burp_findings + ox_findings:
            key = (f.get("url",""), f.get("vuln_type",""))
            if key not in seen:
                seen.add(key)
                merged.append(f)
        return merged


# ─────────────────────────────────────────────
#  BURP COLLABORATOR HELPER
# ─────────────────────────────────────────────
class CollaboratorHelper:
    """
    Helper for Burp Collaborator-style OOB detection.
    Use with interactsh or similar open-source alternative.
    """

    def __init__(self, server: str = ""):
        self.server = server or "interact.sh"   # interactsh public server

    def payload(self, prefix: str = "oxhunter") -> str:
        """Generate OOB callback URL for SSRF/XXE/blind testing."""
        return f"http://{prefix}.{self.server}"

    def dns_payload(self, prefix: str = "oxhunter") -> str:
        return f"{prefix}.{self.server}"

    def ssrf_payloads(self, prefix: str = "oxhunter") -> List[str]:
        base = self.payload(prefix)
        return [
            base,
            f"https://{prefix}.{self.server}",
            f"http://{prefix}.{self.server}/path",
            f"//\"{prefix}.{self.server}",
        ]

    def xxe_payload(self, prefix: str = "oxhunter") -> str:
        cb = self.payload(prefix)
        return (f'<?xml version="1.0"?>'
                f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{cb}">]>'
                f'<root>&xxe;</root>')


# ─────────────────────────────────────────────
#  LOOKUP HELPERS
# ─────────────────────────────────────────────
_CWE_MAP = {
    "xss"               : "CWE-79",
    "sqli"              : "CWE-89",
    "command_injection" : "CWE-78",
    "ssrf"              : "CWE-918",
    "xxe"               : "CWE-611",
    "csrf"              : "CWE-352",
    "open_redirect"     : "CWE-601",
    "idor"              : "CWE-639",
    "lfi"               : "CWE-22",
    "ssti"              : "CWE-94",
    "cors"              : "CWE-942",
    "jwt_attacks"       : "CWE-347",
    "session_fixation"  : "CWE-384",
    "prototype_pollution":"CWE-1321",
    "http_smuggling"    : "CWE-444",
    "ssl_issues"        : "CWE-326",
    "header_missing"    : "CWE-693",
    "sensitive_files"   : "CWE-538",
    "git_exposure"      : "CWE-538",
    "race_condition"    : "CWE-362",
}

_BURP_TYPE_MAP = {
    "0x00100200": "sqli",
    "0x00200000": "xss",
    "0x00400000": "ssrf",
    "0x00500200": "xxe",
}

def _vuln_to_cwe(vuln_type: str) -> str:
    return _CWE_MAP.get(vuln_type.lower(), "CWE-0")

def _vuln_to_burp_type(vuln_type: str) -> str:
    reverse = {v: k for k, v in _BURP_TYPE_MAP.items()}
    return reverse.get(vuln_type.lower(), "0x00000000")

def _burp_name_to_type(name: str) -> str:
    name = name.lower()
    mapping = {
        "sql injection"         : "sqli",
        "cross-site scripting"  : "xss",
        "xss"                   : "xss",
        "ssrf"                  : "ssrf",
        "xxe"                   : "xxe",
        "csrf"                  : "csrf",
        "open redirect"         : "open_redirect",
        "cors"                  : "cors",
        "clickjacking"          : "header_missing",
        "path traversal"        : "lfi",
        "command injection"     : "command_injection",
        "jwt"                   : "jwt_attacks",
    }
    for k, v in mapping.items():
        if k in name:
            return v
    return name.replace(" ","_")


# ─────────────────────────────────────────────
#  UNIFIED INTERFACE
# ─────────────────────────────────────────────
class BurpIntegration:
    """One-stop Burp Suite integration class."""

    def __init__(self):
        self.exporter   = BurpExporter()
        self.importer   = BurpImporter()
        self.collaborator = CollaboratorHelper()

    def export_xml(self, findings: List[Dict], path: str = "") -> str:
        return self.exporter.export(findings, path)

    def export_json(self, findings: List[Dict], path: str = "") -> str:
        return self.exporter.export_json(findings, path)

    def import_xml(self, path: str) -> List[Dict]:
        return self.importer.parse_xml(path)

    def import_json(self, path: str) -> List[Dict]:
        return self.importer.parse_json(path)

    def sync(self, burp_xml: str, ox_findings: List[Dict]) -> List[Dict]:
        """Import Burp findings + merge with OXHUNTER findings."""
        burp = self.importer.parse_xml(burp_xml)
        return self.importer.merge(burp, ox_findings)

    def oob_payload(self, prefix: str = "oxhunter") -> str:
        return self.collaborator.payload(prefix)

    def summary(self, findings: List[Dict]) -> Dict:
        counts = {}
        for f in findings:
            s = f.get("severity","INFO")
            counts[s] = counts.get(s, 0) + 1
        return {
            "total"        : len(findings),
            "by_severity"  : counts,
            "burp_imported": sum(1 for f in findings if f.get("source")=="burp_import"),
            "oxhunter"     : sum(1 for f in findings if f.get("source")!="burp_import"),
        }
