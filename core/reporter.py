"""
HTML Report Generator for 0xHunter
Creates beautiful, interactive vulnerability reports
"""

import os
import html as _html
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from utils.logger import setup_logger
from core.paths import REPORTS_DIR


class HTMLReporter:
    """
    Generates professional HTML vulnerability reports
    """
    
    def __init__(self, template_dir: str = None, output_dir: str = None):
        self.template_dir = str(template_dir or REPORTS_DIR)
        self.output_dir = str(output_dir or REPORTS_DIR)
        self.logger = setup_logger("Reporter")
        
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate(self, report_data: Dict[str, Any], output_file: str = None) -> str:
        """
        Generate HTML report from scan data
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"0xHunter_Report_{timestamp}.html"
        
        output_path = os.path.join(self.output_dir, output_file)
        
        html_content = self._build_html(report_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {output_path}")
        return output_path
    
    def _build_html(self, data: Dict[str, Any]) -> str:
        """Build complete HTML report"""
        
        findings = data.get('findings', [])
        summary = data.get('summary', {})
        target = data.get('target', 'Unknown')
        start_time = data.get('start_time', 'N/A')
        end_time = data.get('end_time', 'N/A')
        urls_crawled = data.get('urls_crawled', 0)
        forms_found = data.get('forms_found', 0)
        
        severity_colors = {
            'Critical': '#dc2626',
            'High': '#ea580c',
            'Medium': '#ca8a04',
            'Low': '#16a34a',
            'Info': '#2563eb'
        }
        
        findings_html = ""
        for i, finding in enumerate(findings, 1):
            sev = finding.get('severity', 'Info')
            color = severity_colors.get(sev, '#6b7280')
            
            # BUG-011 FIX: escape all attacker-controlled values
            _esc = _html.escape
            findings_html += """
            <div class="finding-card" data-severity=""" + _esc(sev.lower()) + """>
                <div class="finding-header">
                    <span class="finding-number">#""" + str(i) + """</span>
                    <span class="finding-type">""" + _esc(finding.get('type', 'Unknown')) + """</span>
                    <span class="severity-badge" style="background: """ + color + """">""" + _esc(sev) + """</span>
                </div>
                <div class="finding-body">
                    <div class="finding-row">
                        <span class="label">URL:</span>
                        <span class="value url-value">""" + _esc(finding.get('url', 'N/A')) + """</span>
                    </div>
                    <div class="finding-row">
                        <span class="label">Parameter:</span>
                        <span class="value">""" + _esc(finding.get('parameter', 'N/A')) + """</span>
                    </div>
                    <div class="finding-row">
                        <span class="label">Payload:</span>
                        <code class="payload">""" + _esc(str(finding.get('payload', 'N/A'))) + """</code>
                    </div>
                    <div class="finding-row">
                        <span class="label">Confidence:</span>
                        <span class="value">""" + finding.get('confidence', 'N/A') + """</span>
                    </div>
                    <div class="finding-row">
                        <span class="label">Evidence:</span>
                        <span class="value evidence">""" + _esc(finding.get('evidence', 'N/A')) + """</span>
                    </div>
                    <div class="finding-row remediation">
                        <span class="label">Remediation:</span>
                        <span class="value">""" + _esc(finding.get('remediation', 'N/A')) + """</span>
                    </div>
                </div>
            </div>
            """
        
        if not findings:
            findings_html = """
            <div class="no-findings">
                <div class="no-findings-icon">✅</div>
                <h3>No Vulnerabilities Found</h3>
                <p>The target appears to be secure against the tested vectors.</p>
            </div>
            """
        
        chart_items = []
        for sev, count in summary.items():
            if count > 0:
                color = severity_colors.get(sev, '#6b7280')
                chart_items.append('{ label: "' + sev + '", value: ' + str(count) + ', color: "' + color + '" }')
        
        chart_data_js = ",\n                ".join(chart_items) if chart_items else ""
        
        html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>0xHunter Security Report - """ + _esc(target) + """</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 40px;
            margin-bottom: 30px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 4px;
            background: linear-gradient(90deg, #06b6d4, #8b5cf6, #ec4899);
        }
        
        .header h1 {
            font-size: 2.5rem;
            background: linear-gradient(90deg, #06b6d4, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            color: #94a3b8;
            font-size: 1.1rem;
        }
        
        .target-info {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
        }
        
        .target-info h2 {
            color: #06b6d4;
            margin-bottom: 15px;
            font-size: 1.3rem;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .info-item {
            background: #0f172a;
            padding: 15px;
            border-radius: 8px;
            border-left: 3px solid #06b6d4;
        }
        
        .info-item .label {
            color: #64748b;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .info-item .value {
            color: #e2e8f0;
            font-size: 1rem;
            font-weight: 600;
            margin-top: 5px;
            word-break: break-all;
        }
        
        .summary-section {
            margin-bottom: 30px;
        }
        
        .summary-section h2 {
            color: #06b6d4;
            margin-bottom: 20px;
            font-size: 1.3rem;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .summary-card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .summary-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        
        .summary-card .count {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .summary-card .label {
            color: #94a3b8;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .summary-card.critical { border-top: 3px solid #dc2626; }
        .summary-card.critical .count { color: #dc2626; }
        
        .summary-card.high { border-top: 3px solid #ea580c; }
        .summary-card.high .count { color: #ea580c; }
        
        .summary-card.medium { border-top: 3px solid #ca8a04; }
        .summary-card.medium .count { color: #ca8a04; }
        
        .summary-card.low { border-top: 3px solid #16a34a; }
        .summary-card.low .count { color: #16a34a; }
        
        .summary-card.info { border-top: 3px solid #2563eb; }
        .summary-card.info .count { color: #2563eb; }
        
        .chart-container {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
        }
        
        .chart-container h3 {
            color: #94a3b8;
            margin-bottom: 20px;
            font-size: 1rem;
        }
        
        .chart-bars {
            display: flex;
            align-items: flex-end;
            gap: 15px;
            height: 200px;
            padding-bottom: 30px;
            border-bottom: 1px solid #334155;
        }
        
        .chart-bar-wrapper {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            min-width: 60px;
        }
        
        .chart-bar {
            width: 100%;
            max-width: 80px;
            border-radius: 6px 6px 0 0;
            transition: all 0.3s ease;
            position: relative;
        }
        
        .chart-bar:hover {
            opacity: 0.8;
        }
        
        .chart-bar .bar-value {
            position: absolute;
            top: -25px;
            left: 50%;
            transform: translateX(-50%);
            font-weight: 700;
            font-size: 1.1rem;
        }
        
        .chart-label {
            margin-top: 10px;
            font-size: 0.85rem;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .findings-section h2 {
            color: #06b6d4;
            margin-bottom: 20px;
            font-size: 1.3rem;
        }
        
        .finding-card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .finding-card:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
        }
        
        .finding-header {
            background: #0f172a;
            padding: 15px 20px;
            display: flex;
            align-items: center;
            gap: 15px;
            border-bottom: 1px solid #334155;
        }
        
        .finding-number {
            background: #06b6d4;
            color: #0f172a;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 0.9rem;
        }
        
        .finding-type {
            flex: 1;
            font-weight: 600;
            font-size: 1.1rem;
            color: #e2e8f0;
        }
        
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: white;
        }
        
        .finding-body {
            padding: 20px;
        }
        
        .finding-row {
            display: flex;
            margin-bottom: 12px;
            align-items: flex-start;
        }
        
        .finding-row .label {
            min-width: 120px;
            color: #64748b;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }
        
        .finding-row .value {
            flex: 1;
            color: #e2e8f0;
            word-break: break-all;
        }
        
        .finding-row .url-value {
            color: #06b6d4;
            font-family: monospace;
        }
        
        .finding-row .payload {
            background: #0f172a;
            padding: 8px 12px;
            border-radius: 6px;
            border: 1px solid #334155;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            color: #ec4899;
        }
        
        .finding-row .evidence {
            color: #ca8a04;
            font-style: italic;
        }
        
        .finding-row.remediation {
            background: #0f172a;
            padding: 15px;
            border-radius: 8px;
            margin-top: 10px;
            border-left: 3px solid #16a34a;
        }
        
        .finding-row.remediation .value {
            color: #86efac;
        }
        
        .no-findings {
            text-align: center;
            padding: 60px 20px;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
        }
        
        .no-findings-icon {
            font-size: 4rem;
            margin-bottom: 20px;
        }
        
        .no-findings h3 {
            color: #16a34a;
            font-size: 1.5rem;
            margin-bottom: 10px;
        }
        
        .no-findings p {
            color: #94a3b8;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #64748b;
            border-top: 1px solid #334155;
            margin-top: 40px;
        }
        
        .footer .disclaimer {
            color: #dc2626;
            font-weight: 600;
            margin-top: 10px;
        }
        
        @media (max-width: 768px) {
            .header h1 { font-size: 1.8rem; }
            .info-grid { grid-template-columns: 1fr; }
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .finding-header { flex-wrap: wrap; }
            .finding-row { flex-direction: column; }
            .finding-row .label { margin-bottom: 5px; }
        }
        
        @media print {
            body { background: white; color: black; }
            .header { background: #f1f5f9; border: 1px solid #cbd5e1; }
            .finding-card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>0xHunter Security Report</h1>
            <p class="subtitle">Web Application Vulnerability Assessment</p>
        </div>
        
        <div class="target-info">
            <h2>📋 Scan Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="label">Target URL</div>
                    <div class="value">""" + _esc(target) + """</div>
                </div>
                <div class="info-item">
                    <div class="label">Scan Start</div>
                    <div class="value">""" + start_time + """</div>
                </div>
                <div class="info-item">
                    <div class="label">Scan End</div>
                    <div class="value">""" + end_time + """</div>
                </div>
                <div class="info-item">
                    <div class="label">URLs Crawled</div>
                    <div class="value">""" + str(urls_crawled) + """</div>
                </div>
                <div class="info-item">
                    <div class="label">Forms Found</div>
                    <div class="value">""" + str(forms_found) + """</div>
                </div>
                <div class="info-item">
                    <div class="label">Total Findings</div>
                    <div class="value">""" + str(len(findings)) + """</div>
                </div>
            </div>
        </div>
        
        <div class="summary-section">
            <h2>📊 Vulnerability Summary</h2>
            <div class="summary-grid">
                <div class="summary-card critical">
                    <div class="count">""" + str(summary.get('Critical', 0)) + """</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-card high">
                    <div class="count">""" + str(summary.get('High', 0)) + """</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-card medium">
                    <div class="count">""" + str(summary.get('Medium', 0)) + """</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-card low">
                    <div class="count">""" + str(summary.get('Low', 0)) + """</div>
                    <div class="label">Low</div>
                </div>
                <div class="summary-card info">
                    <div class="count">""" + str(summary.get('Info', 0)) + """</div>
                    <div class="label">Info</div>
                </div>
            </div>
            
            <div class="chart-container">
                <h3>Severity Distribution</h3>
                <div class="chart-bars" id="chartBars"></div>
            </div>
        </div>
        
        <div class="findings-section">
            <h2>🔍 Detailed Findings</h2>
            """ + findings_html + """
        </div>
        
        <div class="footer">
            <p>Generated by 0xHunter Web Vulnerability Scanner</p>
            <p class="disclaimer">⚠️ This report is for authorized security testing only. Do not share without permission.</p>
        </div>
    </div>
    
    <script>
        const chartData = [""" + chart_data_js + """];
        
        const chartBars = document.getElementById('chartBars');
        if (chartData.length > 0) {
            const maxValue = Math.max(...chartData.map(d => d.value));
            chartData.forEach(item => {
                const percentage = (item.value / maxValue) * 100;
                const bar = document.createElement('div');
                bar.className = 'chart-bar-wrapper';
                bar.innerHTML = `
                    <div class="chart-bar" style="height: ${percentage}%; background: ${item.color}">
                        <span class="bar-value">${item.value}</span>
                    </div>
                    <span class="chart-label">${item.label}</span>
                `;
                chartBars.appendChild(bar);
            });
        } else {
            chartBars.innerHTML = '<div style="width:100%;text-align:center;color:#64748b;padding:20px;">No vulnerabilities detected</div>';
        }
    </script>
</body>
</html>"""
        
        return html