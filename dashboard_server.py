"""Local-only live dashboard for authorized OXHUNTER scans.

Run: python dashboard_server.py --host 127.0.0.1 --port 8787
"""
from __future__ import annotations

import json
import threading
import uuid
import sys
import asyncio
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from core.scanner import ScannerEngine


class JobStore:
    MAX_JOBS = 100  # BUG-6 FIX: limit stored jobs to prevent memory leak

    def __init__(self):
        self._jobs = {}
        self._order = []   # track insertion order for cleanup
        self._lock = threading.Lock()

    def create(self, target: str, full: bool) -> dict:
        job = {
            "id":         uuid.uuid4().hex,
            "target":     target,
            "full":       full,
            "status":     "queued",
            "phase":      "queued",
            "progress":   0,
            "findings":   0,
            "error":      None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            # BUG-6 FIX: evict oldest job if over limit
            if len(self._order) >= self.MAX_JOBS:
                oldest = self._order.pop(0)
                self._jobs.pop(oldest, None)
            self._jobs[job["id"]] = job
            self._order.append(job["id"])
        threading.Thread(target=self._run, args=(job["id"],), daemon=True).start()
        return self._public(job)

    def _update(self, job_id: str, **values):
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.update(values)
            job["updated_at"] = datetime.now(timezone.utc).isoformat()

    # BUG-4 FIX: Windows asyncio compatibility — use explicit SelectorEventLoop in thread
    def _run(self, job_id: str):
        with self._lock:
            job = dict(self._jobs[job_id])
        try:
            self._update(job_id, status="running", phase="starting", progress=1)

            def progress(event):
                self._update(
                    job_id,
                    phase=event.get("phase", "running"),
                    progress=int(event.get("progress", 0)),
                )

            engine = ScannerEngine(
                job["target"], threads=5, timeout=10, delay=0.1,
                verbose=False, progress_callback=progress,
            )

            # BUG-4 FIX: On Windows the default ProactorEventLoop can cause issues
            # inside daemon threads. Explicitly use SelectorEventLoop.
            if sys.platform == "win32":
                loop = asyncio.SelectorEventLoop()
                asyncio.set_event_loop(loop)
                try:
                    report = loop.run_until_complete(engine.run(full_scan=job["full"]))
                finally:
                    loop.close()
            else:
                report = asyncio.run(engine.run(full_scan=job["full"]))

            # BUG-3 FIX: Store result separately; list view only gets counts
            self._update(
                job_id,
                status="completed",
                phase="complete",
                progress=100,
                findings=len(report.findings),
                result=report.__dict__,   # full data — only served by /api/scans/<id>
            )
        except Exception as exc:
            self._update(job_id, status="failed", phase="error", error=str(exc))

    # BUG-3 FIX: strip heavy 'result' field so list refreshes stay small
    @staticmethod
    def _public(job: dict) -> dict:
        return {k: v for k, v in job.items() if k != "result"}

    def get(self, job_id: str):
        with self._lock:
            return dict(self._jobs[job_id]) if job_id in self._jobs else None

    def all(self) -> list:
        with self._lock:
            # BUG-3 FIX: never send full scan result in the list endpoint
            return [self._public(j) for j in self._jobs.values()]


STORE = JobStore()

HTML = """<!doctype html><meta charset='utf-8'>
<title>OXHUNTER Live Dashboard</title>
<style>
*{box-sizing:border-box}
body{font:15px system-ui;max-width:1100px;margin:30px auto;padding:0 18px;background:#0f172a;color:#e2e8f0}
input,select{padding:8px;border-radius:6px;border:1px solid #475569;background:#1e293b;color:#e2e8f0}
button{padding:8px 16px;border-radius:6px;border:none;cursor:pointer;font-weight:bold;transition:opacity .2s}
button:disabled{opacity:.5;cursor:not-allowed}
.btn-scan{background:#dc2626;color:#fff}.btn-view{background:#1e40af;color:#fff;font-size:12px;padding:4px 10px}
.btn-close{background:#475569;color:#fff}
table{width:100%;border-collapse:collapse;margin-top:16px}
td,th{padding:9px 12px;border-bottom:1px solid #334155;text-align:left}
th{background:#1e293b;color:#94a3b8;font-size:12px}
.bar{height:8px;background:#334155;border-radius:4px}.fill{height:8px;background:#22c55e;border-radius:4px;transition:width .5s}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;color:#fff}
.fc{border:1px solid #334155;border-radius:6px;margin:6px 0;padding:12px}
.fm{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
.ft{width:100%;font-size:12px;border-collapse:collapse}
.ft td{padding:3px 0;vertical-align:top}
.lc{color:#94a3b8;width:90px;min-width:90px}
code{background:#1e293b;padding:2px 6px;border-radius:3px;font-size:11px;word-break:break-all}
#toast{position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:8px;font-weight:bold;
       display:none;z-index:999;max-width:360px;word-break:break-word}
.toast-err{background:#dc2626;color:#fff}
.toast-ok{background:#16a34a;color:#fff}
#scanBtn{min-width:110px}
</style>
<h1 style="margin-bottom:4px">OXHUNTER Live Dashboard</h1>
<p style="color:#64748b;margin-top:4px">Authorized security testing only. Localhost only.</p>
<div id="toast"></div>
<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:16px">
  <input id="target" placeholder="https://testphp.vulnweb.com" size="45">
  <label style="display:flex;align-items:center;gap:6px;color:#94a3b8">
    <input id="full" type="checkbox" style="width:16px;height:16px"> Full scan
  </label>
  <button id="scanBtn" class="btn-scan" onclick="startScan()">Start Scan</button>
</div>
<div id="out"></div>
<div id="panel"></div>

<script>
var out = document.getElementById('out');

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function sevColor(s) {
  return {Critical:'#dc2626',High:'#ea580c',Medium:'#ca8a04',Low:'#16a34a',Info:'#2563eb'}[s]||'#6b7280';
}
function toast(msg, isErr) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.className = isErr ? 'toast-err' : 'toast-ok';
  t.style.display = 'block';
  clearTimeout(t._tid);
  t._tid = setTimeout(function(){ t.style.display='none'; }, 4000);
}
function closePanel() {
  document.getElementById('panel').innerHTML = '';
}
function renderFindings(findings) {
  if (!findings||!findings.length) return '<p style="color:#64748b;padding:12px">No findings recorded.</p>';
  var sevFilter = document.getElementById('sevFilter');
  var searchEl = document.getElementById('findingSearch');
  var sev = sevFilter ? sevFilter.value : '';
  var q = searchEl ? searchEl.value.toLowerCase() : '';
  var rows = findings.filter(function(item){
    return (!sev||item.severity===sev) &&
           (!q||(item.url+' '+item.parameter+' '+item.type+' '+(item.evidence||'')).toLowerCase().indexOf(q)>=0);
  });
  if (!rows.length) return '<p style="color:#64748b;padding:12px">No findings match filter.</p>';
  return rows.map(function(item){
    return '<div class="fc" style="border-left:4px solid '+sevColor(item.severity)+'">'
      +'<div class="fm"><span class="badge" style="background:'+sevColor(item.severity)+'">'+esc(item.severity)+'</span>'
      +'<strong>'+esc(item.type)+'</strong>'
      +(item.subtype?'<span style="color:#94a3b8;font-size:12px">'+esc(item.subtype)+'</span>':'')
      +'<span style="color:#94a3b8;font-size:12px;margin-left:auto">Confidence: '+esc(item.confidence)+'</span></div>'
      +'<table class="ft">'
      +'<tr><td class="lc">URL</td><td style="color:#60a5fa;word-break:break-all">'+esc(item.url)+'</td></tr>'
      +(item.parameter&&item.parameter!='N/A'?'<tr><td class="lc">Parameter</td><td><code>'+esc(item.parameter)+'</code></td></tr>':'')
      +(item.payload&&item.payload!='N/A'?'<tr><td class="lc">Payload</td><td><code style="color:#fbbf24">'+esc(String(item.payload).substring(0,400))+'</code></td></tr>':'')
      +(item.evidence?'<tr><td class="lc">Evidence</td><td style="color:#e2e8f0;font-size:11px">'+esc(item.evidence)+'</td></tr>':'')
      +(item.remediation?'<tr><td class="lc" style="vertical-align:top">Fix</td><td style="color:#86efac;font-size:11px">'+esc(item.remediation)+'</td></tr>':'')
      +'</table></div>';
  }).join('');
}
function showFindings(jobId) {
  fetch('/api/scans/'+jobId)
    .then(function(r){ return r.json(); })
    .then(function(job){
      var panel = document.getElementById('panel');
      var findings = (job.result&&job.result.findings)||[];
      var sum = {Critical:0,High:0,Medium:0,Low:0,Info:0};
      findings.forEach(function(item){ if(sum[item.severity]!==undefined) sum[item.severity]++; });
      panel.innerHTML = '<div style="border:1px solid #334155;border-radius:8px;padding:16px">'
        +'<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px">'
        +'<strong>'+findings.length+' Findings - '+esc(job.target)+'</strong>'
        +Object.keys(sum).filter(function(k){ return sum[k]>0; })
          .map(function(k){ return '<span class="badge" style="background:'+sevColor(k)+'">'+k+': '+sum[k]+'</span>'; }).join('')
        +'</div>'
        +'<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">'
        +'<select id="sevFilter" onchange="filterPanel()"><option value="">All Severity</option>'
        +'<option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select>'
        +'<input id="findingSearch" oninput="filterPanel()" placeholder="Search URL, parameter..." style="flex:1;min-width:160px">'
        +'<button class="btn-close" onclick="closePanel()">Close</button>'
        +'</div><div id="findingsList">'+renderFindings(findings)+'</div></div>';
      panel._findings = findings;
      panel.scrollIntoView({behavior:'smooth'});
    })
    .catch(function(e){ toast('Failed to load findings: '+e.message, true); });
}
function filterPanel() {
  var p = document.getElementById('panel');
  if (p&&p._findings) document.getElementById('findingsList').innerHTML = renderFindings(p._findings);
}

var _prevStatuses = {};
async function refresh() {
  try {
    var r = await fetch('/api/scans');
    var jobs = await r.json();
    if (!jobs.length) {
      out.innerHTML = '<p style="color:#64748b;margin-top:16px">No scans yet. Enter a URL and click Start Scan.</p>';
      return;
    }
    var statusColors = {queued:'#94a3b8',running:'#fbbf24',completed:'#22c55e',failed:'#dc2626'};
    jobs.forEach(function(j){
      var prev = _prevStatuses[j.id];
      if (prev==='running'&&j.status==='failed') toast('Scan failed: '+(j.error||'unknown error'), true);
      if (prev==='running'&&j.status==='completed') toast('Scan complete - '+j.findings+' findings found!', false);
      _prevStatuses[j.id] = j.status;
    });
    var html = '<table><tr><th>#</th><th>Target</th><th>Status</th><th>Phase</th><th>Progress</th><th>Findings</th><th>Action</th></tr>';
    var rev = jobs.slice().reverse();
    for (var i=0; i<rev.length; i++) {
      var j = rev[i];
      var action;
      if (j.status==='completed') {
        action = '<button class="btn-view" data-id="'+j.id+'" onclick="showFindings(this.dataset.id)">View Findings</button>';
      } else if (j.status==='failed') {
        action = '<span style="color:#dc2626;font-size:12px" title="'+esc(j.error||'')+'">'+esc((j.error||'error').substring(0,60))+'</span>';
      } else {
        action = '-';
      }
      html += '<tr>'
        +'<td style="color:#64748b">'+(i+1)+'</td>'
        +'<td style="word-break:break-all;max-width:280px">'+esc(j.target)+'</td>'
        +'<td><span style="color:'+(statusColors[j.status]||'#94a3b8')+';font-weight:bold">'+esc(j.status)+'</span></td>'
        +'<td style="color:#94a3b8;font-size:12px">'+esc(j.phase)+'</td>'
        +'<td style="min-width:120px"><div class="bar"><div class="fill" style="width:'+(j.progress||0)+'%"></div></div>'
        +'<span style="font-size:11px;color:#64748b">'+(j.progress||0)+'%</span></td>'
        +'<td><strong style="color:'+(j.findings>0?'#f97316':'#94a3b8')+'">'+(j.findings||0)+'</strong></td>'
        +'<td>'+action+'</td>'
        +'</tr>';
    }
    out.innerHTML = html + '</table>';
  } catch(err) {
    out.innerHTML = '<p style="color:#dc2626">Dashboard error: '+esc(err.message)+'</p>';
  }
}

async function startScan() {
  var target = document.getElementById('target').value.trim();
  var full = document.getElementById('full').checked;
  var btn = document.getElementById('scanBtn');
  if (!target) { toast('Please enter a target URL', true); document.getElementById('target').focus(); return; }
  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    toast('URL must start with http:// or https://', true);
    document.getElementById('target').focus();
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Starting...';
  try {
    var r = await fetch('/api/scans', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({target:target, full:full, authorized:true})
    });
    var data = await r.json();
    if (r.ok) {
      toast('Scan queued for '+target, false);
      refresh();
    } else {
      toast('Error '+r.status+': '+(data.error||'Unknown error'), true);
    }
  } catch(err) {
    toast('Could not reach server: '+err.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Start Scan';
  }
}

document.getElementById('target').addEventListener('keydown', function(e){
  if (e.key==='Enter') startScan();
});
setInterval(refresh, 1500);
refresh();
</script>
"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, data, content_type: str = "application/json"):
        body = data if isinstance(data, bytes) else data.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # BUG-7 FIX: add basic security headers
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            return self._send(200, HTML, "text/html; charset=utf-8")
        if path == "/api/scans":
            return self._send(200, json.dumps(STORE.all()))
        if path.startswith("/api/scans/"):
            job = STORE.get(path.rsplit("/", 1)[-1])
            return self._send(
                200 if job else 404,
                json.dumps(job or {"error": "not found"}),
            )
        self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if urlparse(self.path).path != "/api/scans":
            return self._send(404, json.dumps({"error": "not found"}))

        # BUG-1 FIX: robust body reading — handle missing/zero Content-Length
        try:
            raw_len = self.headers.get("Content-Length", "").strip()
            if raw_len and int(raw_len) > 0:
                body = self.rfile.read(int(raw_len))
            else:
                # Fallback: read whatever is available (handles chunked / missing CL)
                body = self.rfile.read(65536)
            payload = json.loads(body)
        except Exception as exc:
            return self._send(400, json.dumps({"error": f"invalid JSON body: {exc}"}))

        target = str(payload.get("target", "")).strip()

        if not payload.get("authorized"):
            return self._send(
                403,
                json.dumps({"error": "explicit authorization confirmation is required"}),
            )

        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return self._send(
                400,
                json.dumps({"error": "target must be an absolute HTTP(S) URL"}),
            )

        return self._send(202, json.dumps(STORE.create(target, bool(payload.get("full")))))

    def log_message(self, *_):
        pass  # suppress default per-request logging


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    a = p.parse_args()

    print(f"[OXHUNTER] Dashboard: http://{a.host}:{a.port}")
    print("[OXHUNTER] Authorized testing only. Press Ctrl+C to stop.")
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()
