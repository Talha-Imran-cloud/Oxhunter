"""
PDF & HTML Report Generation Module
Generates professional security reports with charts and findings
"""

import os
import json
import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class ReportConfig:
    """Report generation configuration"""
    title: str = "0xHunter Security Assessment Report"
    company: str = "Target Organization"
    assessor: str = "0xHunter Security Scanner"
    logo_path: Optional[str] = None
    include_executive_summary: bool = True
    include_technical_detail: bool = True
    include_remediation: bool = True
    include_cvss: bool = True
    language: str = "en"  # 'en' or 'ur'


class ReportGenerator:
    """
    Professional PDF & HTML Report Generator
    Features:
    - Executive Summary (management-level)
    - Technical Detail (developer-level)
    - Interactive HTML Dashboard with charts
    - CVSS Score calculation
    - OWASP Top 10 mapping
    - Remediation code snippets
    - Severity breakdown charts
    - Finding timeline
    """

    SEVERITY_COLORS = {
        'critical': '#dc2626',
        'high':     '#ea580c',
        'medium':   '#d97706',
        'low':      '#2563eb',
        'info':     '#6b7280',
    }

    CVSS_BASE_SCORES = {
        'critical': '9.0 - 10.0',
        'high':     '7.0 - 8.9',
        'medium':   '4.0 - 6.9',
        'low':      '0.1 - 3.9',
        'info':     '0.0',
    }

    OWASP_MAPPING = {
        'xss':                  'A03:2021 - Injection',
        'sqli':                 'A03:2021 - Injection',
        'cmd_injection':        'A03:2021 - Injection',
        'xxe':                  'A05:2021 - Security Misconfiguration',
        'ssrf':                 'A10:2021 - Server-Side Request Forgery',
        'idor':                 'A01:2021 - Broken Access Control',
        'lfi':                  'A05:2021 - Security Misconfiguration',
        'cors':                 'A05:2021 - Security Misconfiguration',
        'csrf':                 'A01:2021 - Broken Access Control',
        'jwt_attacks':          'A07:2021 - Identification & Authentication Failures',
        'session_fixation':     'A07:2021 - Identification & Authentication Failures',
        'password_policy':      'A07:2021 - Identification & Authentication Failures',
        'open_redirect':        'A01:2021 - Broken Access Control',
        'prototype_pollution':  'A08:2021 - Software & Data Integrity Failures',
        'git_exposure':         'A05:2021 - Security Misconfiguration',
        'ssl_tls':              'A02:2021 - Cryptographic Failures',
        'headers':              'A05:2021 - Security Misconfiguration',
        'graphql':              'A05:2021 - Security Misconfiguration',
        'waf_bypass':           'A05:2021 - Security Misconfiguration',
        'race_condition':       'A04:2021 - Insecure Design',
        'http_smuggling':       'A05:2021 - Security Misconfiguration',
        'directory_brute':      'A05:2021 - Security Misconfiguration',
        'subdomain':            'A05:2021 - Security Misconfiguration',
        'js_analysis':          'A02:2021 - Cryptographic Failures',
    }

    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()

    def _severity_badge(self, severity: str) -> str:
        color = self.SEVERITY_COLORS.get(severity.lower(), '#6b7280')
        return f'<span class="badge" style="background:{color}">{severity.upper()}</span>'

    def _get_owasp(self, finding_type: str) -> str:
        for key, val in self.OWASP_MAPPING.items():
            if key in finding_type.lower():
                return val
        return 'A05:2021 - Security Misconfiguration'

    def _calculate_cvss(self, severity: str) -> str:
        return self.CVSS_BASE_SCORES.get(severity.lower(), 'N/A')

    def _count_severities(self, findings: List[Dict]) -> Dict:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info').lower()
            if sev in counts:
                counts[sev] += 1
        counts['total'] = sum(counts.values())
        return counts

    def _risk_rating(self, counts: Dict) -> str:
        if counts['critical'] > 0:
            return 'CRITICAL'
        if counts['high'] > 3:
            return 'HIGH'
        if counts['high'] > 0:
            return 'HIGH'
        if counts['medium'] > 0:
            return 'MEDIUM'
        if counts['low'] > 0:
            return 'LOW'
        return 'INFO'

    def generate_html(self, scan_data: Dict, findings: List[Dict],
                      output_path: str = "reports/report.html") -> str:
        """Generate full interactive HTML report"""

        counts      = self._count_severities(findings)
        risk        = self._risk_rating(counts)
        risk_color  = self.SEVERITY_COLORS.get(risk.lower(), '#6b7280')
        target      = scan_data.get('target', 'Unknown')
        scan_id     = scan_data.get('scan_id', 'N/A')
        started     = scan_data.get('started_at', '')[:16]
        finished    = scan_data.get('finished_at', '')[:16]

        # Group findings by module
        by_module: Dict[str, List] = {}
        for f in findings:
            mod = f.get('module') or f.get('type', 'unknown')  # BUG-008 FIX
            by_module.setdefault(mod, []).append(f)

        # Build finding cards HTML
        finding_cards = ""
        for i, f in enumerate(findings, 1):
            sev       = f.get('severity', 'info').lower()
            color     = self.SEVERITY_COLORS.get(sev, '#6b7280')
            owasp     = self._get_owasp(f.get('type', ''))
            cvss      = self._calculate_cvss(sev)
            extra     = json.loads(f.get('extra', '{}')) if isinstance(f.get('extra'), str) else (f.get('extra') or {})
        # BUG-008 FIX: read top-level fields first, fall back to extra
        

            finding_cards += f"""
            <div class="finding-card" data-severity="{sev}">
                <div class="finding-header" style="border-left: 4px solid {color}">
                    <div class="finding-meta">
                        <span class="finding-num">#{i}</span>
                        {self._severity_badge(sev)}
                        <span class="finding-type">{f.get('type','').replace('_',' ').title()}</span>
                        <span class="module-tag">{f.get('module') or f.get('type','')}</span>  <!-- BUG-008 FIX -->
                    </div>
                    <div class="finding-scores">
                        <span class="cvss">CVSS: {cvss}</span>
                        <span class="owasp">{owasp}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="finding-row">
                        <label>URL:</label>
                        <code class="url-code">{f.get('url','')}</code>
                    </div>
                    <div class="finding-row">
                        <label>Evidence:</label>
                        <p class="evidence-text">{f.get('evidence','')}</p>
                    </div>
                    {'<div class="finding-row"><label>Parameter:</label><code>' + (f.get("parameter") or extra.get("parameter","")) + '</code></div>' if (f.get("parameter") or extra.get("parameter")) else ''}
                    {'<div class="finding-row"><label>Payload:</label><code class="payload">' + str(f.get("payload") or extra.get("payload",""))[:200] + '</code></div>' if (f.get("payload") or extra.get("payload")) else ''}
                    <div class="finding-row">
                        <label>Remediation:</label>
                        <pre class="remediation">{f.get('remediation','')}</pre>
                    </div>
                </div>
            </div>"""

        # Module summary rows
        module_rows = ""
        for mod, mod_findings in sorted(by_module.items()):
            mc = self._count_severities(mod_findings)
            module_rows += f"""
            <tr>
                <td>{mod.replace('_',' ').title()}</td>
                <td>{len(mod_findings)}</td>
                <td><span style="color:#dc2626;font-weight:bold">{mc['critical']}</span></td>
                <td><span style="color:#ea580c;font-weight:bold">{mc['high']}</span></td>
                <td><span style="color:#d97706">{mc['medium']}</span></td>
                <td><span style="color:#2563eb">{mc['low']}</span></td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>0xHunter Security Report — {target}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#0f172a; color:#e2e8f0; }}
        .header {{ background:linear-gradient(135deg,#1e1b4b 0%,#312e81 50%,#4c1d95 100%);
                   padding:40px; text-align:center; border-bottom:3px solid #6d28d9; }}
        .header h1 {{ font-size:2.5rem; color:#a78bfa; margin-bottom:8px; }}
        .header .subtitle {{ color:#94a3b8; font-size:1.1rem; }}
        .header .scan-meta {{ display:flex; justify-content:center; gap:40px; margin-top:20px; flex-wrap:wrap; }}
        .meta-item {{ text-align:center; }}
        .meta-item .label {{ color:#94a3b8; font-size:0.8rem; text-transform:uppercase; }}
        .meta-item .value {{ color:#e2e8f0; font-size:1rem; font-weight:600; margin-top:4px; }}
        .risk-badge {{ display:inline-block; padding:8px 24px; border-radius:50px;
                       font-size:1.2rem; font-weight:bold; color:white;
                       background:{risk_color}; margin-top:16px; }}
        .container {{ max-width:1200px; margin:0 auto; padding:30px 20px; }}
        .section {{ background:#1e293b; border-radius:12px; padding:24px;
                    margin-bottom:24px; border:1px solid #334155; }}
        .section h2 {{ color:#a78bfa; font-size:1.3rem; margin-bottom:20px;
                       padding-bottom:10px; border-bottom:1px solid #334155; }}
        .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:16px; }}
        .stat-card {{ background:#0f172a; border-radius:8px; padding:20px; text-align:center;
                      border:1px solid #334155; }}
        .stat-card .count {{ font-size:2.5rem; font-weight:bold; }}
        .stat-card .label {{ color:#94a3b8; font-size:0.85rem; margin-top:4px; }}
        .stat-card.critical .count {{ color:#dc2626; }}
        .stat-card.high     .count {{ color:#ea580c; }}
        .stat-card.medium   .count {{ color:#d97706; }}
        .stat-card.low      .count {{ color:#2563eb; }}
        .stat-card.total    .count {{ color:#a78bfa; }}
        .charts-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
        @media(max-width:768px) {{ .charts-grid {{ grid-template-columns:1fr; }} }}
        .chart-box {{ background:#0f172a; border-radius:8px; padding:20px; border:1px solid #334155; }}
        .chart-box h3 {{ color:#94a3b8; font-size:0.9rem; margin-bottom:16px; text-align:center; }}
        .filters {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:20px; }}
        .filter-btn {{ padding:8px 16px; border-radius:20px; border:1px solid #334155;
                       background:#0f172a; color:#94a3b8; cursor:pointer; font-size:0.85rem;
                       transition:all 0.2s; }}
        .filter-btn:hover, .filter-btn.active {{ background:#6d28d9; color:white; border-color:#6d28d9; }}
        .finding-card {{ background:#0f172a; border-radius:8px; margin-bottom:16px;
                         border:1px solid #334155; overflow:hidden; }}
        .finding-header {{ padding:16px 20px; background:#1e293b; display:flex;
                           justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; }}
        .finding-meta {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
        .finding-num {{ color:#6b7280; font-size:0.85rem; }}
        .badge {{ padding:4px 10px; border-radius:4px; font-size:0.75rem;
                  font-weight:bold; color:white; }}
        .finding-type {{ font-weight:600; color:#e2e8f0; }}
        .module-tag {{ background:#1e293b; color:#94a3b8; padding:2px 8px;
                       border-radius:4px; font-size:0.75rem; border:1px solid #334155; }}
        .finding-scores {{ display:flex; gap:10px; flex-wrap:wrap; }}
        .cvss {{ background:#0f172a; color:#a78bfa; padding:4px 10px;
                 border-radius:4px; font-size:0.8rem; border:1px solid #334155; }}
        .owasp {{ color:#94a3b8; font-size:0.75rem; padding:4px 8px; }}
        .finding-body {{ padding:16px 20px; }}
        .finding-row {{ margin-bottom:12px; }}
        .finding-row label {{ color:#94a3b8; font-size:0.8rem; text-transform:uppercase;
                              letter-spacing:0.05em; display:block; margin-bottom:4px; }}
        .url-code {{ background:#1e293b; padding:6px 10px; border-radius:4px;
                     font-size:0.85rem; color:#38bdf8; word-break:break-all; display:block; }}
        .evidence-text {{ color:#cbd5e1; font-size:0.9rem; line-height:1.5; }}
        .payload {{ background:#1e293b; padding:6px 10px; border-radius:4px;
                    font-size:0.8rem; color:#f87171; word-break:break-all; display:block; }}
        .remediation {{ background:#1e293b; padding:12px; border-radius:4px;
                        font-size:0.85rem; color:#86efac; white-space:pre-wrap;
                        border-left:3px solid #22c55e; }}
        table {{ width:100%; border-collapse:collapse; }}
        th {{ background:#0f172a; color:#94a3b8; padding:10px 12px; text-align:left;
              font-size:0.8rem; text-transform:uppercase; }}
        td {{ padding:10px 12px; border-bottom:1px solid #1e293b; font-size:0.9rem; }}
        tr:hover td {{ background:#1e293b; }}
        .exec-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
        @media(max-width:600px) {{ .exec-grid {{ grid-template-columns:1fr; }} }}
        .exec-card {{ background:#0f172a; padding:20px; border-radius:8px; border:1px solid #334155; }}
        .exec-card h3 {{ color:#a78bfa; margin-bottom:12px; }}
        .exec-card p {{ color:#94a3b8; line-height:1.6; font-size:0.9rem; }}
        .footer {{ text-align:center; padding:30px; color:#475569; font-size:0.85rem; }}
        .no-findings {{ text-align:center; padding:40px; color:#6b7280; }}
        .search-box {{ width:100%; padding:10px 16px; background:#0f172a; border:1px solid #334155;
                       border-radius:8px; color:#e2e8f0; font-size:0.9rem; margin-bottom:16px; }}
    </style>
</head>
<body>

<div class="header">
    <h1>🔍 0xHunter Security Report</h1>
    <div class="subtitle">{self.config.title}</div>
    <div class="risk-badge">Overall Risk: {risk}</div>
    <div class="scan-meta">
        <div class="meta-item">
            <div class="label">Target</div>
            <div class="value">{target}</div>
        </div>
        <div class="meta-item">
            <div class="label">Scan ID</div>
            <div class="value">{scan_id[:8]}...</div>
        </div>
        <div class="meta-item">
            <div class="label">Started</div>
            <div class="value">{started}</div>
        </div>
        <div class="meta-item">
            <div class="label">Finished</div>
            <div class="value">{finished}</div>
        </div>
        <div class="meta-item">
            <div class="label">Total Findings</div>
            <div class="value">{counts['total']}</div>
        </div>
    </div>
</div>

<div class="container">

    <!-- Executive Summary -->
    <div class="section">
        <h2>📊 Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="count">{counts['critical']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="count">{counts['high']}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="count">{counts['medium']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="count">{counts['low']}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card total">
                <div class="count">{counts['total']}</div>
                <div class="label">Total</div>
            </div>
        </div>
    </div>

    <!-- Charts -->
    <div class="section">
        <h2>📈 Findings Overview</h2>
        <div class="charts-grid">
            <div class="chart-box">
                <h3>Severity Distribution</h3>
                <canvas id="severityChart" height="200"></canvas>
            </div>
            <div class="chart-box">
                <h3>Findings by Module</h3>
                <canvas id="moduleChart" height="200"></canvas>
            </div>
        </div>
    </div>

    <!-- Executive Notes -->
    <div class="section">
        <h2>📝 Assessment Notes</h2>
        <div class="exec-grid">
            <div class="exec-card">
                <h3>Risk Summary</h3>
                <p>The security assessment of <strong>{target}</strong> identified
                <strong>{counts['total']} vulnerabilities</strong> across multiple security domains.
                The overall risk rating is <strong>{risk}</strong>.
                {f"There are {counts['critical']} critical severity issues requiring immediate remediation." if counts['critical'] > 0 else "No critical severity issues were identified."}
                </p>
            </div>
            <div class="exec-card">
                <h3>Recommendations</h3>
                <p>1. Address all Critical and High severity findings immediately.<br>
                2. Schedule remediation for Medium severity within 30 days.<br>
                3. Plan Low severity fixes in next development cycle.<br>
                4. Re-scan after remediation to verify fixes.<br>
                5. Implement a continuous security testing program.</p>
            </div>
        </div>
    </div>

    <!-- Module Summary -->
    <div class="section">
        <h2>🧩 Module Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Module</th><th>Total</th>
                    <th>Critical</th><th>High</th><th>Medium</th><th>Low</th>
                </tr>
            </thead>
            <tbody>{module_rows}</tbody>
        </table>
    </div>

    <!-- Findings -->
    <div class="section">
        <h2>🐛 Detailed Findings ({counts['total']})</h2>
        <input class="search-box" type="text" id="searchBox"
               placeholder="Search findings..." oninput="filterFindings()">
        <div class="filters">
            <button class="filter-btn active" onclick="filterSeverity('all',this)">All</button>
            <button class="filter-btn" onclick="filterSeverity('critical',this)" style="border-color:#dc2626">Critical ({counts['critical']})</button>
            <button class="filter-btn" onclick="filterSeverity('high',this)" style="border-color:#ea580c">High ({counts['high']})</button>
            <button class="filter-btn" onclick="filterSeverity('medium',this)" style="border-color:#d97706">Medium ({counts['medium']})</button>
            <button class="filter-btn" onclick="filterSeverity('low',this)" style="border-color:#2563eb">Low ({counts['low']})</button>
        </div>
        <div id="findingsContainer">
            {finding_cards if finding_cards else '<div class="no-findings">✅ No findings to display</div>'}
        </div>
    </div>

</div>

<div class="footer">
    Generated by 0xHunter Security Scanner &nbsp;|&nbsp;
    {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
    Authorized Security Testing Only
</div>

<script>
// Severity distribution chart
const sevCtx = document.getElementById('severityChart').getContext('2d');
new Chart(sevCtx, {{
    type: 'doughnut',
    data: {{
        labels: ['Critical','High','Medium','Low','Info'],
        datasets: [{{
            data: [{counts['critical']},{counts['high']},{counts['medium']},{counts['low']},{counts['info']}],
            backgroundColor: ['#dc2626','#ea580c','#d97706','#2563eb','#6b7280'],
            borderWidth: 0,
        }}]
    }},
    options: {{
        plugins: {{ legend: {{ labels: {{ color:'#94a3b8' }} }} }},
        cutout: '65%'
    }}
}});

// Module chart
const modLabels = {json.dumps(list(by_module.keys()))};
const modData   = {json.dumps([len(v) for v in by_module.values()])};
const modCtx = document.getElementById('moduleChart').getContext('2d');
new Chart(modCtx, {{
    type: 'bar',
    data: {{
        labels: modLabels.map(l => l.replace(/_/g,' ')),
        datasets: [{{
            label: 'Findings',
            data: modData,
            backgroundColor: '#6d28d9',
            borderRadius: 4,
        }}]
    }},
    options: {{
        plugins: {{ legend: {{ display:false }} }},
        scales: {{
            x: {{ ticks: {{ color:'#94a3b8', maxRotation:45 }}, grid: {{ color:'#1e293b' }} }},
            y: {{ ticks: {{ color:'#94a3b8' }}, grid: {{ color:'#1e293b' }}, beginAtZero:true }}
        }}
    }}
}});

// Filter by severity
function filterSeverity(sev, btn) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.finding-card').forEach(card => {{
        if (sev === 'all' || card.dataset.severity === sev) {{
            card.style.display = '';
        }} else {{
            card.style.display = 'none';
        }}
    }});
}}

// Search filter
function filterFindings() {{
    const q = document.getElementById('searchBox').value.toLowerCase();
    document.querySelectorAll('.finding-card').forEach(card => {{
        card.style.display = card.innerText.toLowerCase().includes(q) ? '' : 'none';
    }});
}}
</script>
</body>
</html>"""

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_path

    def generate_pdf(self, scan_data: Dict, findings: List[Dict],
                     output_path: str = "reports/report.pdf") -> str:
        """
        Generate PDF — tries reportlab first (pure Python, no wkhtmltopdf needed),
        then weasyprint, then pdfkit, then falls back to HTML.
        """
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        # ── Method 1: reportlab (pure Python, no external binary) ──────────
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (SimpleDocTemplate, Paragraph,
                                            Spacer, Table, TableStyle,
                                            HRFlowable, PageBreak)
            from reportlab.lib.enums import TA_CENTER, TA_LEFT

            doc = SimpleDocTemplate(output_path, pagesize=A4,
                                    leftMargin=1.5*cm, rightMargin=1.5*cm,
                                    topMargin=1.5*cm, bottomMargin=1.5*cm)
            W   = A4[0] - 3*cm
            RED = colors.HexColor("#FF4444")
            SEV_C = {
                "critical": colors.HexColor("#CC0000"),
                "high":     colors.HexColor("#FF4444"),
                "medium":   colors.HexColor("#FF8800"),
                "low":      colors.HexColor("#FFCC00"),
                "info":     colors.HexColor("#4488FF"),
            }

            def P(txt, size=10, bold=False, clr=colors.HexColor("#CCCCCC"), align=TA_LEFT):
                return Paragraph(str(txt), ParagraphStyle("s",
                    fontSize=size,
                    fontName="Helvetica-Bold" if bold else "Helvetica",
                    textColor=clr, alignment=align, leading=size*1.4))

            story = []

            # ── Cover ──
            story.append(Spacer(1, 0.8*cm))
            story.append(Table([[P("OXHUNTER — Security Scan Report", 16, True, colors.white, TA_CENTER)]],
                colWidths=[W], style=TableStyle([
                    ("BACKGROUND",(0,0),(-1,-1), colors.HexColor("#1A0000")),
                    ("ROWPADDING",(0,0),(-1,-1), 14),
                    ("BOX",(0,0),(-1,-1), 2, RED),
                ])))
            story.append(Spacer(1, 0.3*cm))
            target = scan_data.get("target", "Unknown")
            ts     = str(scan_data.get("started_at",""))[:16]
            story.append(P(f"Target: {target}  |  Date: {ts}  |  OXHUNTER v2.x",
                           9, False, colors.HexColor("#888888"), TA_CENTER))
            story.append(Spacer(1, 0.5*cm))
            story.append(HRFlowable(width=W, color=RED, thickness=2))
            story.append(Spacer(1, 0.4*cm))

            # ── Summary ──
            story.append(P("Vulnerability Summary", 13, True, RED))
            story.append(Spacer(1, 0.2*cm))
            sev_map = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
            for f in findings:
                s = str(f.get("severity","info")).lower()
                sev_map[s] = sev_map.get(s,0) + 1

            rows = []
            for s, c in sev_map.items():
                rows.append([
                    P(s.upper(), 10, True, colors.white, TA_CENTER),
                    P(str(c), 18, True, colors.white, TA_CENTER),
                ])
            sev_table = Table([[r[0], r[1]] for r in rows],
                               colWidths=[W*0.7, W*0.3])
            sev_ts = TableStyle([("ROWPADDING",(0,0),(-1,-1),8),
                                  ("INNERGRID",(0,0),(-1,-1),0.5,colors.HexColor("#333"))])
            for i, s in enumerate(sev_map.keys()):
                sev_ts.add("BACKGROUND",(0,i),(-1,i), SEV_C.get(s, colors.grey))
            sev_table.setStyle(sev_ts)
            story.append(sev_table)
            story.append(PageBreak())

            # ── Findings ──
            story.append(P("Detailed Findings", 13, True, RED))
            story.append(Spacer(1, 0.3*cm))
            for i, f in enumerate(findings, 1):
                sev   = str(f.get("severity","info")).lower()
                sc    = SEV_C.get(sev, colors.grey)
                ftype = f.get("type","Unknown")
                url   = str(f.get("url",""))[:90]
                evid  = str(f.get("evidence",""))[:250]
                rem   = str(f.get("remediation",""))[:300]

                story.append(Table(
                    [[P(f"#{i}  {ftype}  [{sev.upper()}]", 10, True, colors.white, TA_CENTER)]],
                    colWidths=[W],
                    style=TableStyle([("BACKGROUND",(0,0),(-1,-1), sc),
                                      ("ROWPADDING",(0,0),(-1,-1), 7)])))
                story.append(Table(
                    [["URL", url], ["Evidence", evid], ["Fix", rem]],
                    colWidths=[W*0.13, W*0.87],
                    style=TableStyle([
                        ("FONTSIZE",(0,0),(-1,-1), 8),
                        ("TEXTCOLOR",(0,0),(-1,-1), colors.HexColor("#CCCCCC")),
                        ("BACKGROUND",(0,0),(0,-1), colors.HexColor("#1A0000")),
                        ("BACKGROUND",(1,0),(1,-1), colors.HexColor("#0D0D0D")),
                        ("FONTNAME",(0,0),(0,-1), "Helvetica-Bold"),
                        ("ROWPADDING",(0,0),(-1,-1), 5),
                        ("GRID",(0,0),(-1,-1), 0.5, colors.HexColor("#333")),
                    ])))
                story.append(Spacer(1, 0.2*cm))

            # ── Footer ──
            story.append(HRFlowable(width=W, color=RED, thickness=1))
            story.append(P("Generated by OXHUNTER | For Authorized Security Testing Only",
                           8, False, colors.HexColor("#666"), TA_CENTER))
            doc.build(story)
            return output_path

        except ImportError:
            pass  # reportlab not installed, try next

        # ── Method 2: weasyprint ──
        html_path = output_path.replace('.pdf', '_temp.html')
        self.generate_html(scan_data, findings, html_path)
        try:
            import weasyprint
            weasyprint.HTML(filename=html_path).write_pdf(output_path)
            try: os.remove(html_path)
            except Exception: pass
            return output_path
        except (ImportError, Exception):
            pass

        # ── Method 3: pdfkit (needs wkhtmltopdf) ──
        try:
            import pdfkit
            pdfkit.from_file(html_path, output_path)
            try: os.remove(html_path)
            except Exception: pass
            return output_path
        except (ImportError, OSError, Exception):
            pass

        # ── Fallback: HTML ──
        final = output_path.replace('.pdf', '.html')
        if os.path.exists(html_path):
            try: os.rename(html_path, final)
            except Exception: pass
        return final

    def generate_executive_summary(self, scan_data: Dict,
                                    findings: List[Dict]) -> str:
        """Generate plain-text executive summary"""
        counts  = self._count_severities(findings)
        risk    = self._risk_rating(counts)
        target  = scan_data.get('target', 'Unknown')
        started = scan_data.get('started_at', '')[:16]

        lines = [
            "=" * 60,
            "       0xHUNTER SECURITY ASSESSMENT — EXECUTIVE SUMMARY",
            "=" * 60,
            f"Target:          {target}",
            f"Assessment Date: {started}",
            f"Overall Risk:    {risk}",
            f"Total Findings:  {counts['total']}",
            "-" * 60,
            f"  Critical:  {counts['critical']}",
            f"  High:      {counts['high']}",
            f"  Medium:    {counts['medium']}",
            f"  Low:       {counts['low']}",
            f"  Info:      {counts['info']}",
            "-" * 60,
            "TOP CRITICAL / HIGH FINDINGS:",
        ]

        top = [f for f in findings if f.get('severity', '') in ['critical', 'high']][:5]
        for i, f in enumerate(top, 1):
            lines.append(f"  {i}. [{f['severity'].upper()}] {f.get('type','').replace('_',' ').title()}")
            lines.append(f"     URL: {f.get('url','')[:60]}")
            lines.append(f"     {f.get('evidence','')[:80]}")

        lines += [
            "-" * 60,
            "RECOMMENDATIONS:",
            "  1. Remediate Critical findings within 24 hours",
            "  2. Remediate High findings within 7 days",
            "  3. Remediate Medium findings within 30 days",
            "  4. Re-scan after remediation",
            "=" * 60,
            "Generated by 0xHunter Security Scanner",
        ]

        return "\n".join(lines)
