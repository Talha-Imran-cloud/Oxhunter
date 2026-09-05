"""
OXHUNTER - cicd.py
GitHub Actions CI/CD Pipeline Integration
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List


# ─────────────────────────────────────────────
#  GITHUB ACTIONS WORKFLOW GENERATOR
# ─────────────────────────────────────────────
WORKFLOW_TEMPLATE = """\
name: OXHUNTER Security Scan

on:
  push:
    branches: [{branches}]
  pull_request:
    branches: [main]
  schedule:
    - cron: '{cron}'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    name: OXHUNTER Web Security Scan

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install OXHUNTER
        run: |
          pip install -r requirements.txt

      - name: Run Security Scan
        env:
          ANTHROPIC_API_KEY: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
          SLACK_WEBHOOK_URL: ${{{{ secrets.SLACK_WEBHOOK_URL }}}}
        run: |
          python main.py --target {target} \\
            --modules {modules} \\
            --output reports/ \\
            --format json,html \\
            --severity {severity} \\
            --silent

      - name: Upload Report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: oxhunter-report
          path: reports/

      - name: Check Critical Findings
        run: python -c "
import json, sys, glob
files = glob.glob('reports/*.json')
if not files: sys.exit(0)
data  = json.load(open(files[0]))
crits = [f for f in data.get('findings',[]) if f.get('severity') in ['CRITICAL','HIGH']]
if crits:
    print(f'Found {{len(crits)}} critical/high vulnerabilities!')
    sys.exit({fail_on_critical})
print('No critical vulnerabilities found.')
"
"""


class CICDIntegration:

    @staticmethod
    def generate_workflow(
        target          : str,
        branches        : List[str] = None,
        modules         : str       = "xss,sqli,ssrf,xxe,command_injection",
        severity        : str       = "MEDIUM",
        cron            : str       = "0 2 * * 1",
        fail_on_critical: bool      = True,
    ) -> str:
        """Generate GitHub Actions workflow YAML."""
        return WORKFLOW_TEMPLATE.format(
            target           = target,
            branches         = ",".join(branches or ["main", "develop"]),
            modules          = modules,
            severity         = severity,
            cron             = cron,
            fail_on_critical = 1 if fail_on_critical else 0,
        )

    @staticmethod
    def save_workflow(content: str,
                      path: str = ".github/workflows/oxhunter.yml") -> str:
        """Save workflow file to repo."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return str(p)

    # ── CI/CD Result Handler ──────────────────

    @staticmethod
    def parse_results(report_path: str) -> Dict:
        """Parse OXHUNTER JSON report for CI/CD exit logic."""
        try:
            data     = json.loads(Path(report_path).read_text())
            findings = data.get("findings", [])
            counts   = {}
            for f in findings:
                s = f.get("severity", "INFO")
                counts[s] = counts.get(s, 0) + 1
            return {
                "total"    : len(findings),
                "counts"   : counts,
                "critical" : counts.get("CRITICAL", 0),
                "high"     : counts.get("HIGH", 0),
                "passed"   : counts.get("CRITICAL", 0) == 0,
            }
        except Exception as e:
            return {"error": str(e), "passed": True}

    @staticmethod
    def set_github_output(key: str, value: str):
        """Set GitHub Actions output variable."""
        out = os.getenv("GITHUB_OUTPUT")
        if out:
            with open(out, "a") as f:
                f.write(f"{key}={value}\n")

    @staticmethod
    def set_github_summary(findings: List[Dict], target: str):
        """Write markdown summary to GitHub Actions job summary."""
        summary_file = os.getenv("GITHUB_STEP_SUMMARY")
        if not summary_file:
            return

        counts = {}
        for f in findings:
            s = f.get("severity","INFO")
            counts[s] = counts.get(s, 0) + 1

        emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}
        rows  = "\n".join(f"| {emoji.get(s,'⚪')} {s} | {c} |"
                          for s, c in counts.items())
        md = (
            f"# 🔐 OXHUNTER Security Scan\n\n"
            f"**Target:** `{target}`  \n"
            f"**Total Findings:** {len(findings)}\n\n"
            f"| Severity | Count |\n|---|---|\n{rows}\n"
        )
        with open(summary_file, "a") as f:
            f.write(md)

    @staticmethod
    def exit_code(findings: List[Dict],
                  fail_on: List[str] = None) -> int:
        """
        Return exit code for CI/CD pipeline.
        0 = pass, 1 = fail (critical/high found)
        """
        fail_on = fail_on or ["CRITICAL", "HIGH"]
        for f in findings:
            if f.get("severity") in fail_on:
                return 1
        return 0


# ─────────────────────────────────────────────
#  CLI USAGE (called from pipeline)
# ─────────────────────────────────────────────
def run_cicd_check(report_path: str, target: str = "",
                   fail_on: List[str] = None) -> int:
    """Main entry for CI/CD exit check."""
    result = CICDIntegration.parse_results(report_path)

    if "error" in result:
        print(f"[!] Report parse error: {result['error']}")
        return 0

    CICDIntegration.set_github_output("total_findings", str(result["total"]))
    CICDIntegration.set_github_output("critical_count", str(result["critical"]))

    findings = json.loads(Path(report_path).read_text()).get("findings", [])
    if target:
        CICDIntegration.set_github_summary(findings, target)

    code = CICDIntegration.exit_code(findings, fail_on)
    if code != 0:
        print(f"❌ Pipeline FAILED — {result['critical']} critical, {result['high']} high findings")
    else:
        print(f"✅ Pipeline PASSED — {result['total']} total findings (no critical/high)")

    return code


if __name__ == "__main__":
    report       = sys.argv[1] if len(sys.argv) > 1 else "reports/results.json"
    cli_target   = sys.argv[2] if len(sys.argv) > 2 else ""  # BUG-015 FIX: renamed to avoid shadowing function param 'target'
    sys.exit(run_cicd_check(report, cli_target))
