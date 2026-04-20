"""HTML report generator — professional 3-tab layout with print support."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{case_name}} — Investigation Report</title>
<style>
/* ── Theme System ── */
:root {
  --bg:#fff; --surface:#f6f8fa; --surface2:#eef1f5; --border:#d0d7de; --border-light:#e8ecf0;
  --text:#1f2328; --text-dim:#656d76; --text-light:#8b949e;
  --accent:#0969da; --accent-light:#ddf4ff;
  --critical:#cf222e; --critical-bg:#ffebe9; --high:#bf8700; --high-bg:#fff8c5;
  --medium:#0969da; --medium-bg:#ddf4ff; --low:#1a7f37; --low-bg:#dafbe1;
  --font: 'Segoe UI', -apple-system, system-ui, sans-serif;
  --mono: 'Cascadia Code', 'Consolas', monospace;
}
[data-theme="dark"] {
  --bg:#0d1117; --surface:#161b22; --surface2:#1c2129; --border:#30363d; --border-light:#21262d;
  --text:#e6edf3; --text-dim:#8b949e; --text-light:#484f58;
  --accent:#58a6ff; --accent-light:rgba(56,139,253,0.15);
  --critical:#f85149; --critical-bg:rgba(248,81,73,0.1); --high:#d29922; --high-bg:rgba(210,153,34,0.1);
  --medium:#58a6ff; --medium-bg:rgba(56,139,253,0.1); --low:#3fb950; --low-bg:rgba(63,185,80,0.1);
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:var(--font); background:var(--bg); color:var(--text); font-size:14px; line-height:1.6; }

/* ── Cover Page ── */
.cover { min-height:100vh; display:flex; flex-direction:column; justify-content:center; align-items:center;
         padding:60px 40px; text-align:center; border-bottom:1px solid var(--border); position:relative; }
.cover-badge { background:var(--critical-bg); color:var(--critical); padding:6px 20px; border-radius:20px;
               font-size:12px; font-weight:700; letter-spacing:1px; text-transform:uppercase; margin-bottom:32px; }
.cover h1 { font-size:32px; font-weight:300; margin-bottom:8px; }
.cover h1 strong { font-weight:700; }
.cover .cover-case { font-size:20px; color:var(--accent); font-weight:600; margin:16px 0; }
.cover-meta { display:grid; grid-template-columns:repeat(3, auto); gap:32px; margin-top:40px;
              padding:24px 40px; background:var(--surface); border-radius:12px; border:1px solid var(--border); }
.cover-meta dt { font-size:10px; text-transform:uppercase; letter-spacing:1px; color:var(--text-dim); }
.cover-meta dd { font-size:14px; font-weight:600; margin-top:2px; }
.cover-controls { position:absolute; top:20px; right:24px; display:flex; gap:8px; }
.btn { padding:6px 14px; border-radius:6px; border:1px solid var(--border); background:var(--surface);
       color:var(--text); cursor:pointer; font-size:12px; font-family:var(--font); transition:all 0.15s; }
.btn:hover { background:var(--surface2); }
.btn-accent { background:var(--accent); color:#fff; border-color:var(--accent); }
.btn-accent:hover { opacity:0.9; }

/* ── Navigation ── */
.nav { position:sticky; top:0; z-index:100; background:var(--bg); border-bottom:1px solid var(--border);
       display:flex; align-items:center; padding:0 32px; gap:0; }
.nav-brand { font-weight:700; font-size:13px; color:var(--text-dim); padding:12px 16px 12px 0;
             border-right:1px solid var(--border); margin-right:8px; }
.nav-tab { padding:12px 20px; cursor:pointer; font-size:13px; font-weight:500; color:var(--text-dim);
           border-bottom:2px solid transparent; transition:all 0.15s; }
.nav-tab:hover { color:var(--text); }
.nav-tab.active { color:var(--accent); border-bottom-color:var(--accent); }
.nav-right { margin-left:auto; display:flex; align-items:center; gap:8px; }

/* ── Content ── */
.page { display:none; padding:32px; max-width:1200px; margin:0 auto; }
.page.active { display:block; }
h2 { font-size:15px; font-weight:600; margin:32px 0 16px; padding-bottom:10px;
     border-bottom:1px solid var(--border-light); display:flex; align-items:center; gap:8px; }
h2 .h2-icon { font-size:16px; }
h3 { font-size:13px; font-weight:600; margin:20px 0 10px; color:var(--text-dim); text-transform:uppercase;
     letter-spacing:0.5px; }

/* ── Risk Banner ── */
.risk { border-radius:12px; padding:24px 28px; margin-bottom:28px; display:flex; align-items:center; gap:20px;
        border:1px solid; }
.risk.critical { background:var(--critical-bg); border-color:var(--critical); }
.risk.high { background:var(--high-bg); border-color:var(--high); }
.risk.medium { background:var(--medium-bg); border-color:var(--medium); }
.risk.low { background:var(--low-bg); border-color:var(--low); }
.risk-icon { font-size:40px; }
.risk-level { font-size:28px; font-weight:800; min-width:120px; }
.risk-body { font-size:13px; color:var(--text-dim); line-height:1.6; }
.risk-body strong { color:var(--text); }

/* ── Cards ── */
.cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(160px,1fr)); gap:12px; margin-bottom:28px; }
.card { background:var(--surface); border:1px solid var(--border-light); border-radius:10px; padding:16px; }
.card-label { font-size:10px; text-transform:uppercase; letter-spacing:0.8px; color:var(--text-dim); font-weight:600; }
.card-value { font-size:26px; font-weight:700; margin-top:4px; }
.card-sub { font-size:11px; color:var(--text-light); margin-top:2px; }

/* ── Kill Chain ── */
.kc { display:flex; gap:2px; margin-bottom:28px; overflow-x:auto; padding-bottom:4px; }
.kc-step { flex:1; min-width:90px; background:var(--surface); border:1px solid var(--border-light);
           border-radius:8px; padding:10px 8px; text-align:center; position:relative; transition:all 0.2s; }
.kc-step.hit { background:var(--high-bg); border-color:var(--high); }
.kc-step .kc-num { font-size:9px; color:var(--text-light); }
.kc-step .kc-name { font-size:9px; font-weight:700; text-transform:uppercase; margin:4px 0;
                    color:var(--text-dim); letter-spacing:0.3px; line-height:1.3; }
.kc-step.hit .kc-name { color:var(--high); }
.kc-step .kc-count { font-size:16px; font-weight:800; }
.kc-step.hit .kc-count { color:var(--critical); }
.kc-arrow { display:flex; align-items:center; color:var(--border); font-size:10px; }

/* ── Findings ── */
.finding { background:var(--surface); border:1px solid var(--border-light); border-radius:10px;
           margin-bottom:12px; overflow:hidden; }
.finding-header { padding:16px 20px; display:flex; align-items:flex-start; gap:16px; cursor:pointer; }
.finding-header:hover { background:var(--surface2); }
.finding-sev { min-width:72px; }
.finding-body { flex:1; }
.finding-body h4 { font-size:14px; font-weight:600; margin-bottom:4px; }
.finding-body p { font-size:12px; color:var(--text-dim); }
.finding-count { font-size:22px; font-weight:700; color:var(--text-dim); min-width:50px; text-align:right; }
.finding-evidence { padding:0 20px 16px; display:none; }
.finding.open .finding-evidence { display:block; }
.finding-patterns { display:flex; flex-wrap:wrap; gap:4px; margin-bottom:12px; }
.pattern-tag { background:var(--surface2); border:1px solid var(--border-light); border-radius:4px;
               padding:2px 8px; font-size:11px; font-family:var(--mono); }
.pattern-count { color:var(--text-light); font-size:10px; margin-left:3px; }
.evidence-item { background:var(--surface2); border:1px solid var(--border-light); border-radius:8px;
                 padding:12px; margin-top:8px; font-size:12px; }
.ev-header { display:flex; gap:8px; align-items:center; margin-bottom:6px; flex-wrap:wrap; }
.ev-type { font-weight:600; color:var(--accent); font-size:11px; }
.ev-time { font-family:var(--mono); font-size:10px; color:var(--text-dim); }
.ev-match { font-family:var(--mono); font-size:11px; padding:6px 8px; background:var(--critical-bg);
            border-radius:4px; margin-top:4px; word-break:break-all; line-height:1.5; }
.ev-match em { color:var(--critical); font-style:normal; font-weight:700; }
.ev-ctx { font-size:11px; color:var(--text-dim); margin-top:6px; }

/* ── IOC ── */
.ioc-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(260px,1fr)); gap:12px; margin-bottom:24px; }
.ioc-card { background:var(--surface); border:1px solid var(--border-light); border-radius:10px; padding:16px; }
.ioc-card-title { font-size:10px; font-weight:700; text-transform:uppercase; color:var(--text-dim);
                  letter-spacing:0.5px; margin-bottom:8px; display:flex; justify-content:space-between; }
.ioc-card-title span { color:var(--text-light); font-weight:400; }
.ioc-item { font-family:var(--mono); font-size:12px; padding:4px 0; border-bottom:1px solid var(--border-light);
            word-break:break-all; }
.ioc-item:last-child { border-bottom:none; }
.ioc-more { font-size:11px; color:var(--accent); margin-top:6px; cursor:pointer; }

/* ── Timeline (Summary) ── */
.stl { margin-bottom:24px; }
.stl-item { display:grid; grid-template-columns:130px 90px 1fr; gap:12px; padding:10px 0;
            border-bottom:1px solid var(--border-light); font-size:13px; align-items:start; }
.stl-item:last-child { border-bottom:none; }
.stl-time { font-family:var(--mono); font-size:11px; color:var(--text-dim); }
.stl-type { font-size:11px; }
.stl-desc { color:var(--text-dim); }

/* ── Recommendations ── */
.rec { background:var(--surface); border:1px solid var(--border-light); border-radius:10px; padding:20px; }
.rec-item { padding:8px 0; border-bottom:1px solid var(--border-light); font-size:13px;
            display:flex; gap:10px; line-height:1.5; }
.rec-item:last-child { border-bottom:none; }
.rec-num { color:var(--accent); font-weight:700; min-width:20px; }

/* ── Detail Tables ── */
table { width:100%; border-collapse:collapse; margin:8px 0 24px; font-size:12px; }
th { background:var(--surface); text-align:left; padding:8px 12px; font-weight:600; font-size:11px;
     text-transform:uppercase; letter-spacing:0.3px; color:var(--text-dim);
     border-bottom:2px solid var(--border); position:sticky; top:48px; cursor:pointer; }
th:hover { color:var(--accent); }
td { padding:8px 12px; border-bottom:1px solid var(--border-light); max-width:350px;
     overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
td:hover { white-space:normal; word-break:break-all; }
tr:hover td { background:var(--accent-light); }

/* ── Detail MITRE ── */
.mitre { display:grid; grid-template-columns:repeat(auto-fill, minmax(160px,1fr)); gap:10px; }
.mitre-col { background:var(--surface); border:1px solid var(--border-light); border-radius:8px; padding:12px; }
.mitre-tactic { font-size:10px; font-weight:700; text-transform:uppercase; color:var(--accent);
                margin-bottom:8px; letter-spacing:0.5px; }
.mitre-item { font-size:11px; padding:3px 0; border-top:1px solid var(--border-light); }
.mitre-item:first-child { border-top:none; }
.mitre-tid { color:var(--high); font-weight:600; font-family:var(--mono); font-size:10px; }

/* ── Detail Timeline ── */
.tl-wrap { max-height:600px; overflow-y:auto; }
.tl-row { display:grid; grid-template-columns:130px 160px 1fr; gap:8px; padding:5px 0;
          border-bottom:1px solid var(--border-light); font-size:12px; }
.tl-row:hover { background:var(--accent-light); }
.tl-ts { font-family:var(--mono); font-size:11px; color:var(--text-dim); }
.tl-at { font-weight:600; color:var(--accent); font-size:11px; }
.tl-desc { color:var(--text-dim); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.tl-desc:hover { white-space:normal; }

/* ── Filter ── */
.filter { display:flex; gap:8px; margin-bottom:12px; }
.filter input, .filter select { background:var(--surface); border:1px solid var(--border); color:var(--text);
     padding:7px 12px; border-radius:6px; font-size:12px; font-family:var(--font); }
.filter input { flex:1; }

/* ── Badges ── */
.badge { display:inline-block; padding:2px 10px; border-radius:12px; font-size:10px; font-weight:700;
         letter-spacing:0.3px; }
.badge-critical { background:var(--critical-bg); color:var(--critical); }
.badge-high { background:var(--high-bg); color:var(--high); }
.badge-medium { background:var(--medium-bg); color:var(--medium); }
.badge-low { background:var(--low-bg); color:var(--low); }
.badge-info { background:var(--surface2); color:var(--text-dim); }
.tag { display:inline-block; padding:1px 6px; font-size:10px; background:var(--accent-light);
       border-radius:3px; font-family:var(--mono); }

/* ── Misc ── */
.masked-bar { background:var(--high-bg); border:1px solid var(--high); border-radius:0;
              padding:8px 32px; font-size:12px; color:var(--high); }
.section { margin-bottom:32px; }
.empty { color:var(--text-dim); font-size:13px; font-style:italic; padding:20px 0; }
footer { padding:20px 32px; border-top:1px solid var(--border); color:var(--text-light);
         font-size:11px; text-align:center; }

/* ── Print ── */
@media print {
  .cover-controls, .nav, .btn, .filter, .ioc-more { display:none !important; }
  .page { display:block !important; page-break-before:always; }
  .page:first-of-type { page-break-before:avoid; }
  .cover { min-height:auto; padding:40px; page-break-after:always; }
  body { font-size:11px; }
  .finding-evidence { display:block !important; }
  .risk { break-inside:avoid; }
  .finding { break-inside:avoid; }
}

@page { margin:15mm; }
</style>
</head>
<body data-theme="light">

<!-- ============= COVER PAGE ============= -->
<div class="cover" id="cover">
  <div class="cover-controls">
    <button class="btn" onclick="toggleTheme()" id="theme-btn">Dark Mode</button>
    <button class="btn btn-accent" onclick="window.print()">Print / PDF</button>
  </div>
  <div class="cover-badge" id="cover-risk-badge">INVESTIGATION REPORT</div>
  <h1><strong>Forensic Orchestra</strong></h1>
  <h1 style="font-size:18px;color:var(--text-dim);font-weight:400">Digital Forensics &amp; Incident Response</h1>
  <div class="cover-case">{{case_name}}</div>
  <dl class="cover-meta">
    <div><dt>Evidence</dt><dd>{{evidence_sources}}</dd></div>
    <div><dt>Analysis Period</dt><dd>{{date_range}}</dd></div>
    <div><dt>Generated</dt><dd>{{generated_at}}</dd></div>
    <div><dt>Total Artifacts</dt><dd>{{total_hits}}</dd></div>
    <div><dt>Findings</dt><dd>{{total_findings}}</dd></div>
    <div><dt>ATT&amp;CK Techniques</dt><dd>{{total_techniques}}</dd></div>
  </dl>
</div>

{{masked_notice_bar}}

<!-- ============= NAVIGATION ============= -->
<div class="nav" id="main-nav">
  <div class="nav-brand">FORENSIC ORCHESTRA</div>
  <div class="nav-tab active" onclick="go('summary')">Executive Summary</div>
  <div class="nav-tab" onclick="go('details')">Detailed Analysis</div>
  <div class="nav-tab" onclick="go('appendix')">IOC &amp; Timeline</div>
  <div class="nav-right">
    <button class="btn" onclick="toggleTheme()" id="theme-btn2">Dark</button>
  </div>
</div>

<!-- ===== TAB 1: EXECUTIVE SUMMARY ===== -->
<div id="pg-summary" class="page active">

  <div id="risk-banner"></div>

  <div class="cards" id="dashboard-cards">
    <div class="card"><div class="card-label">Artifacts</div><div class="card-value">{{total_hits}}</div><div class="card-sub">{{artifact_type_count}} types</div></div>
    <div class="card"><div class="card-label">Findings</div><div class="card-value" style="color:var(--critical)">{{total_findings}}</div></div>
    <div class="card"><div class="card-label">IOCs</div><div class="card-value">{{total_iocs}}</div></div>
    <div class="card"><div class="card-label">ATT&amp;CK</div><div class="card-value" style="color:var(--high)">{{total_techniques}}</div><div class="card-sub">techniques</div></div>
    <div class="card"><div class="card-label">Period</div><div class="card-value" style="font-size:14px">{{date_range}}</div></div>
  </div>

  <h2>Attack Kill Chain</h2>
  <div class="kc" id="killchain"></div>

  <div id="antiforensics-banner"></div>

  <h2>Evidence Strength</h2>
  <div id="strength-rollup" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px"></div>

  <h2>Key Findings</h2>
  <div id="key-findings"></div>

  <h2>IOC Summary</h2>
  <div class="ioc-grid" id="ioc-summary"></div>

  <h2>Key Events</h2>
  <div class="stl" id="key-timeline"></div>

  <h2>Recommendations</h2>
  <div class="rec" id="recommendations"></div>
</div>

<!-- ===== TAB 2: DETAILED ANALYSIS ===== -->
<div id="pg-details" class="page">

  <h2>MITRE ATT&amp;CK Matrix</h2>
  <div class="mitre" id="mitre-matrix"></div>

  <h2>All Findings</h2>
  <table><thead><tr><th>Severity</th><th>Strength</th><th>Rule</th><th>MITRE</th><th>Hits</th><th>Description</th><th>Patterns</th></tr></thead>
  <tbody id="findings-body"></tbody></table>

  <h2>Artifact Types</h2>
  <table><thead><tr><th>Type</th><th>Count</th><th>Distribution</th></tr></thead>
  <tbody id="types-body"></tbody></table>
</div>

<!-- ===== TAB 3: IOC & TIMELINE ===== -->
<div id="pg-appendix" class="page">

  <h2>Indicators of Compromise</h2>
  <div class="filter">
    <input type="text" id="ioc-filter" placeholder="Filter IOCs..." oninput="filterIOCs()">
    <select id="ioc-type-filter" onchange="filterIOCs()"><option value="">All</option></select>
  </div>
  <table><thead><tr><th onclick="sortIOC('type')">Type</th><th onclick="sortIOC('value')">Value</th>
  <th onclick="sortIOC('count')">Count</th><th>Sources</th></tr></thead>
  <tbody id="ioc-body"></tbody></table>

  <h2>Full Timeline</h2>
  <div class="filter">
    <input type="text" id="tl-filter" placeholder="Filter timeline..." oninput="filterTimeline()">
  </div>
  <div class="tl-wrap" id="timeline"></div>
</div>

<footer>Forensic Orchestra MCP | Generated {{generated_at}} | All analysis performed locally | No data transmitted externally</footer>

<script>
const DATA = {{json_data}};

// ── Theme ──
function toggleTheme() {
  const d = document.documentElement;
  const isDark = d.getAttribute('data-theme') === 'dark';
  d.setAttribute('data-theme', isDark ? 'light' : 'dark');
  document.body.setAttribute('data-theme', isDark ? 'light' : 'dark');
  document.getElementById('theme-btn').textContent = isDark ? 'Dark Mode' : 'Light Mode';
  document.getElementById('theme-btn2').textContent = isDark ? 'Dark' : 'Light';
}

// ── Navigation ──
function go(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('pg-'+name).classList.add('active');
  event.target.classList.add('active');
  window.scrollTo(0, document.getElementById('main-nav').offsetTop);
}

// ── Summary Tab ──
function renderRisk() {
  const f = DATA.findings || [];
  const hasCrit = f.some(x => x.severity==='critical');
  const hasHigh = f.some(x => x.severity==='high');
  const lv = hasCrit?'critical':hasHigh?'high':f.length?'medium':'low';
  const icons = {critical:'\u26A0\uFE0F',high:'\u26A0',medium:'\u2139\uFE0F',low:'\u2705'};
  const labels = {critical:'CRITICAL',high:'HIGH',medium:'MEDIUM',low:'LOW'};
  const descs = {
    critical:'Critical threats detected requiring immediate response. Evidence of active compromise found.',
    high:'High severity threats detected. Prompt investigation and containment recommended.',
    medium:'Medium severity findings present. Review and assess potential impact.',
    low:'No significant threats detected in analyzed evidence.'
  };
  const total = f.reduce((s,x)=>s+x.matching_count,0);
  document.getElementById('risk-banner').innerHTML = `<div class="risk ${lv}">
    <div class="risk-icon">${icons[lv]}</div>
    <div class="risk-level" style="color:var(--${lv})">${labels[lv]}</div>
    <div class="risk-body"><strong>Risk Assessment</strong><br>${descs[lv]}<br>
    <span style="font-size:11px">${f.length} detection rules triggered across ${total.toLocaleString()} evidence artifacts.</span></div>
  </div>`;
  document.getElementById('cover-risk-badge').textContent = labels[lv] + ' — INVESTIGATION REPORT';
  document.getElementById('cover-risk-badge').style.background = `var(--${lv}-bg)`;
  document.getElementById('cover-risk-badge').style.color = `var(--${lv})`;
}

function renderKillChain() {
  const el = document.getElementById('killchain');
  const nar = DATA.narrative || [];
  const active = Object.fromEntries(nar.map(n=>[n.tactic, n.techniques.length]));
  const phases = ['Reconnaissance','Resource Dev.','Initial Access','Execution','Persistence',
    'Priv. Escalation','Defense Evasion','Credential Access','Discovery',
    'Lateral Movement','Collection','C2','Exfiltration','Impact'];
  el.innerHTML = phases.map((p,i) => {
    const cnt = active[p] || active[p.replace('Dev.','Development').replace('Priv.','Privilege')] || 0;
    const arrow = i<phases.length-1 ? '<div class="kc-arrow">\u25B6</div>' : '';
    return `<div class="kc-step ${cnt?'hit':''}">
      <div class="kc-num">${i+1}</div>
      <div class="kc-name">${p}</div>
      <div class="kc-count">${cnt||'\u2014'}</div>
    </div>${arrow}`;
  }).join('');
}

function renderKeyFindings() {
  const el = document.getElementById('key-findings');
  const findings = (DATA.findings||[]).filter(f=>f.severity==='critical'||f.severity==='high');
  if (!findings.length) { el.innerHTML='<div class="empty">No critical or high severity findings.</div>'; return; }
  el.innerHTML = findings.map((f,fi) => {
    const patterns = Object.entries(f.matched_patterns||{}).sort((a,b)=>b[1]-a[1]).slice(0,8)
      .map(([p,c])=>`<span class="pattern-tag">${esc(p)}<span class="pattern-count">\u00d7${c}</span></span>`).join('');
    const details = (f.details||[]).filter(d=>d.matched_value).slice(0,3);
    const samples = details.map(d => {
      let val = esc(d.matched_value||'');
      const pat = d.matched_pattern||'';
      if (pat) val = val.replace(new RegExp('('+escRx(pat)+')','gi'),'<em>$1</em>');
      const ctx = ['Event ID','Computer','source_path','Provider Name','ServiceName','ImagePath','Application Name']
        .filter(k=>d[k]).map(k=>k+': '+esc(String(d[k]))).join(' \u2502 ');
      return `<div class="evidence-item"><div class="ev-header">
        <span class="ev-type">${esc(d.artifact_type)}</span>
        <span class="ev-time">${d.timestamp||''}</span></div>
        <div class="ev-match">${val}</div>
        ${ctx?'<div class="ev-ctx">'+ctx+'</div>':''}
      </div>`;
    }).join('');
    const rem = (f.details||[]).length - 3;
    return `<div class="finding" onclick="this.classList.toggle('open')">
      <div class="finding-header">
        <div class="finding-sev"><span class="badge badge-${f.severity}">${f.severity.toUpperCase()}</span></div>
        <div class="finding-body"><h4>${f.rule_name.replace(/_/g,' ').replace(/\b\w/g,l=>l.toUpperCase())}</h4>
          <p>${f.description}</p>
          <div style="margin-top:6px">${(f.mitre_techniques||[]).map(t=>'<span class="tag">'+t+'</span>').join(' ')}</div></div>
        <div class="finding-count">${f.matching_count.toLocaleString()}</div>
      </div>
      <div class="finding-evidence">
        <h3>Detection Evidence</h3>
        <div class="finding-patterns">${patterns}</div>
        ${samples}
        ${rem>0?'<div class="empty" style="font-size:11px">+ '+rem+' more evidence samples in detailed view</div>':''}
      </div>
    </div>`;
  }).join('');
}

function renderIOCSummary() {
  const el = document.getElementById('ioc-summary');
  const iocs = DATA.iocs||[];
  const groups = {};
  iocs.forEach(i => { if (!groups[i.ioc_type]) groups[i.ioc_type]=[]; if (groups[i.ioc_type].length<5) groups[i.ioc_type].push(i); });
  const labels = {ipv4:'IP Addresses',md5:'MD5 Hashes',sha1:'SHA1',sha256:'SHA256',domain:'Domains',url:'URLs',email:'Emails'};
  el.innerHTML = Object.entries(groups).map(([t,items]) => {
    const total = iocs.filter(i=>i.ioc_type===t).length;
    return `<div class="ioc-card"><div class="ioc-card-title">${labels[t]||t} <span>${total} total</span></div>
      ${items.map(i=>'<div class="ioc-item">'+esc(i.value)+'</div>').join('')}
      ${total>5?'<div class="ioc-more" onclick="go(\'appendix\')">View all \u2192</div>':''}
    </div>`;
  }).join('') || '<div class="empty">No IOCs extracted.</div>';
}

function renderKeyTimeline() {
  const el = document.getElementById('key-timeline');
  const tl = DATA.timeline||[];
  if (!tl.length) { el.innerHTML='<div class="empty">No timeline data.</div>'; return; }
  const step = Math.max(1, Math.floor(tl.length/8));
  const picks = [tl[0]];
  for (let i=step; i<tl.length-1; i+=step) picks.push(tl[i]);
  if (tl.length>1) picks.push(tl[tl.length-1]);
  const seen = new Set();
  const uniq = picks.filter(e => { const k=e.timestamp; if(seen.has(k)) return false; seen.add(k); return true; }).slice(0,10);
  el.innerHTML = uniq.map(e => `<div class="stl-item">
    <div class="stl-time">${(e.timestamp||'').substring(0,19)}</div>
    <div class="stl-type"><span class="badge badge-medium">${esc(e.artifact_type||'')}</span></div>
    <div class="stl-desc">${esc(e.description||'')}</div>
  </div>`).join('');
}

function renderRecs() {
  const el = document.getElementById('recommendations');
  const f = DATA.findings||[];
  const map = {
    lsass_access:'Investigate LSASS access. Check for credential dumping tools. Force password reset for all accounts on affected systems.',
    suspicious_process_creation:'Review flagged process executions. Block encoded PowerShell via Group Policy. Enable enhanced Script Block Logging.',
    service_installation:'Audit all newly installed services. Remove unauthorized services. Check service binary paths and signatures.',
    scheduled_task_creation:'Review all scheduled tasks for unauthorized entries. Disable suspicious tasks and investigate their origin.',
    log_clearing:'Security logs were cleared. Recover logs from backup or SIEM. Investigate who cleared the logs and when.',
    rdp_lateral_movement:'Isolate systems with RDP lateral movement. Reset credentials. Review RDP access policies and enable NLA.',
    explicit_credential_use:'Audit explicit credential usage. Check for pass-the-hash indicators. Review account permissions.',
    suspicious_prefetch:'Quarantine systems where attack tools were executed. Image affected systems for further analysis.',
    suspicious_service_paths:'Remove services with binaries in suspicious paths. Scan binaries with AV/YARA. Check for persistence.',
    powershell_scriptblock:'Review suspicious PowerShell scripts. Block unauthorized script execution. Audit PowerShell logs.',
  };
  const recs = [];
  f.forEach(x => { if (map[x.rule_name]) recs.push(map[x.rule_name]); });
  recs.push('Preserve all digital evidence with documented chain of custody for potential legal proceedings.');
  recs.push('Conduct a comprehensive review of all endpoint security controls and update detection signatures.');
  el.innerHTML = recs.map((r,i) => `<div class="rec-item"><span class="rec-num">${i+1}.</span><span>${r}</span></div>`).join('');
}

// ── Details Tab ──
function renderMitre() {
  const el = document.getElementById('mitre-matrix');
  el.innerHTML = (DATA.narrative||[]).map(p => `<div class="mitre-col">
    <div class="mitre-tactic">${p.tactic}</div>
    ${p.techniques.map(t=>`<div class="mitre-item"><span class="mitre-tid">${t.id}</span> ${t.name}
      <span style="color:var(--text-light);font-size:10px">(${t.evidence_count})</span></div>`).join('')}
  </div>`).join('');
}

function renderAllFindings() {
  const tbody = document.getElementById('findings-body');
  const strengthBadge = (s) => {
    if (!s) return '';
    const colors = {
      confirmed: ['#16a34a','rgba(74,222,128,0.16)'],
      strong:    ['#2563eb','rgba(56,139,253,0.16)'],
      moderate:  ['#b45309','rgba(245,158,11,0.15)'],
      weak:      ['#475569','rgba(148,163,184,0.22)'],
    };
    const [fg,bg] = colors[s] || colors.moderate;
    return `<span style="padding:1px 8px;border-radius:10px;font-size:10px;font-weight:700;
      text-transform:uppercase;letter-spacing:0.04em;background:${bg};color:${fg}">${s}</span>`;
  };
  tbody.innerHTML = (DATA.findings||[]).map(f => {
    const pats = Object.entries(f.matched_patterns||{}).sort((a,b)=>b[1]-a[1]).slice(0,5)
      .map(([p,c])=>`<span class="pattern-tag">${esc(p)}<span class="pattern-count">\u00d7${c}</span></span>`).join('');
    return `<tr><td><span class="badge badge-${f.severity}">${f.severity.toUpperCase()}</span></td>
    <td>${strengthBadge(f.overall_strength)}</td>
    <td>${f.rule_name}</td><td>${(f.mitre_techniques||[]).map(t=>'<span class="tag">'+t+'</span>').join(' ')}</td>
    <td>${f.matching_count.toLocaleString()}</td><td>${f.description}</td><td>${pats}</td></tr>`;
  }).join('');
}

function renderTypes() {
  const types = DATA.artifact_types||[];
  const max = types.length ? types[0].count : 1;
  document.getElementById('types-body').innerHTML = types.slice(0,30).map(t => `<tr>
    <td>${t.artifact_type}</td><td>${t.count.toLocaleString()}</td>
    <td><div style="background:var(--accent);height:12px;border-radius:3px;width:${Math.max(2,t.count/max*100)}%"></div></td>
  </tr>`).join('');
}

// ── Appendix Tab ──
function renderIOCs() {
  const iocs = DATA.iocs||[];
  window._iocData = iocs;
  const types = new Set(); iocs.forEach(i=>types.add(i.ioc_type));
  const sel = document.getElementById('ioc-type-filter');
  types.forEach(t => { const o=document.createElement('option'); o.value=t; o.textContent=t; sel.appendChild(o); });
  _renderIOCRows(iocs);
}
function _renderIOCRows(iocs) {
  document.getElementById('ioc-body').innerHTML = iocs.slice(0,500).map(i => `<tr>
    <td><span class="badge badge-info">${i.ioc_type}</span></td><td style="font-family:var(--mono)">${esc(i.value)}</td>
    <td>${i.count}</td><td>${(i.source_artifact_types||[]).join(', ')}</td></tr>`).join('');
}
function filterIOCs() {
  const t=document.getElementById('ioc-filter').value.toLowerCase();
  const tp=document.getElementById('ioc-type-filter').value;
  let f=window._iocData||[];
  if(t) f=f.filter(i=>i.value.toLowerCase().includes(t));
  if(tp) f=f.filter(i=>i.ioc_type===tp);
  _renderIOCRows(f);
}
let _sd={};
function sortIOC(k) {
  _sd[k]=!_sd[k]; const d=_sd[k]?1:-1;
  const m={type:'ioc_type',value:'value',count:'count'};
  window._iocData.sort((a,b)=>typeof a[m[k]]==='number'?(a[m[k]]-b[m[k]])*d:String(a[m[k]]).localeCompare(String(b[m[k]]))*d);
  filterIOCs();
}
function renderTimeline() {
  window._tlData = DATA.timeline||[];
  _renderTL(window._tlData);
}
function _renderTL(entries) {
  document.getElementById('timeline').innerHTML = entries.slice(0,500).map(e => `<div class="tl-row">
    <div class="tl-ts">${(e.timestamp||'').substring(0,19)}</div>
    <div class="tl-at">${esc(e.artifact_type||'')}</div>
    <div class="tl-desc">${esc(e.description||'')}</div>
  </div>`).join('');
}
function filterTimeline() {
  const t=document.getElementById('tl-filter').value.toLowerCase();
  let f=window._tlData||[];
  if(t) f=f.filter(e=>(e.description||'').toLowerCase().includes(t)||(e.artifact_type||'').toLowerCase().includes(t));
  _renderTL(f);
}

// ── Helpers ──
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function escRx(s){return s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');}

function renderStrengthRollup() {
  const el = document.getElementById('strength-rollup');
  if (!el) return;
  const r = DATA.strength_rollup || {};
  const tiers = [
    ['confirmed', 'Confirmed', '#16a34a', 'rgba(74,222,128,0.16)'],
    ['strong',    'Strong',    '#2563eb', 'rgba(56,139,253,0.16)'],
    ['moderate',  'Moderate',  '#b45309', 'rgba(245,158,11,0.15)'],
    ['weak',      'Weak',      '#475569', 'rgba(148,163,184,0.22)'],
  ];
  el.innerHTML = tiers.map(([k,label,color,bg]) =>
    `<div style="padding:6px 14px;border-radius:8px;background:${bg};border:1px solid ${color}33;font-size:12px">
      <div style="font-weight:700;color:${color};font-size:16px">${r[k]||0}</div>
      <div style="color:var(--text-dim)">${label}</div>
    </div>`
  ).join('');
}

function renderAntiForensicsBanner() {
  const el = document.getElementById('antiforensics-banner');
  if (!el) return;
  const af = DATA.anti_forensics || {};
  if (!af.rules_fired) { el.innerHTML = ''; return; }
  const fired = (af.rules||[]).filter(r => r.ok && r.count);
  el.innerHTML = `<div style="padding:14px 18px;border-radius:10px;margin:16px 0;
    background:var(--critical-bg);border:1px solid var(--critical)">
    <div style="font-weight:700;color:var(--critical);margin-bottom:6px">
      \u26A0 Anti-forensic activity detected
      \u2014 ${af.rules_fired} rule${af.rules_fired>1?'s':''} fired, ${af.total_hits} hit${af.total_hits===1?'':'s'}
    </div>
    ${fired.map(r => `<div style="font-size:12px;padding:2px 0">
      <strong>${esc(r.rule_name)}</strong>
      <span style="font-family:var(--mono);color:var(--critical);margin-left:6px">${esc(r.mitre_technique)}</span>
      <span style="margin-left:6px">\u00b7 ${r.count} hit${r.count===1?'':'s'}</span>
      <span style="margin-left:8px;color:var(--text-dim)">${esc(r.description||'')}</span>
    </div>`).join('')}
  </div>`;
}

// ── Init ──
renderRisk(); renderKillChain(); renderStrengthRollup(); renderAntiForensicsBanner();
renderKeyFindings(); renderIOCSummary();
renderKeyTimeline(); renderRecs(); renderMitre(); renderAllFindings();
renderTypes(); renderIOCs(); renderTimeline();
</script>
</body>
</html>"""


def generate_report(
    connectors: dict[str, Any],
    masker: Any = None,
    output_path: str = "",
) -> dict:
    """Generate a professional HTML investigation report."""

    axiom = connectors.get("axiom")
    if not axiom or not axiom.is_connected():
        return {"error": "AXIOM 케이스가 열려있지 않습니다."}

    from analysis.suspicious import find_suspicious
    from analysis.ioc_extractor import extract_iocs
    from analysis.mitre_mapper import get_attack_narrative
    from analysis.evidence_strength import score_findings
    from analysis.anti_forensics import detect_anti_forensics as _anti_forensics
    from analysis.coverage import build_coverage_report

    metadata = axiom.get_metadata()
    types = axiom.get_artifact_type_counts()
    sus = find_suspicious(axiom.artifact_queries)
    # Annotate findings with CLAUDE.md strength tiers so the report carries the
    # same confirmed/strong/moderate/weak classification as the live UI.
    score_findings(sus)
    iocs = extract_iocs(axiom)
    narrative = get_attack_narrative(sus.get("findings", []))
    timeline = axiom.get_timeline(limit=500)
    # Anti-forensics and coverage are cheap to include and often the first
    # sections an incident reviewer wants.
    try:
        anti = _anti_forensics(axiom.artifact_queries)
    except Exception:
        anti = {"ok": False, "rules_fired": 0, "total_hits": 0, "rules": []}
    try:
        coverage = build_coverage_report(connectors)
    except Exception:
        coverage = {"ok": False, "coverage": [], "summary": {}, "case_context": {}}

    json_data = {
        "findings": sus.get("findings", []),
        "strength_rollup": sus.get("strength_rollup", {}),
        "iocs": iocs.get("iocs", []),
        "narrative": narrative.get("narrative", []),
        "timeline": timeline.get("entries", []),
        "artifact_types": types,
        "anti_forensics": anti,
        "coverage": coverage,
    }

    if masker and masker.enabled:
        json_data = masker.mask(json_data)
        metadata = masker.mask(metadata)

    case_name = metadata.get("case_name", "Unknown")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sources = ", ".join(metadata.get("evidence_sources", []))
    date_start = (metadata.get("date_range_start") or "?")[:10]
    date_end = (metadata.get("date_range_end") or "?")[:10]

    masked_notice_bar = ""
    if masker and masker.enabled:
        masked_notice_bar = (
            '<div class="masked-bar">'
            "\u26A0 This report contains masked data. Sensitive values are replaced with tokens. "
            "Restore originals: <code>python demask.py report.html output.html</code></div>"
        )

    html = REPORT_TEMPLATE
    html = html.replace("{{case_name}}", _esc(case_name))
    html = html.replace("{{generated_at}}", now)
    html = html.replace("{{evidence_sources}}", _esc(sources))
    html = html.replace("{{total_hits}}", f"{metadata.get('total_hits', 0):,}")
    html = html.replace("{{artifact_type_count}}", str(metadata.get("artifact_type_count", 0)))
    html = html.replace("{{date_range}}", f"{date_start} ~ {date_end}")
    html = html.replace("{{total_findings}}", str(sus.get("total_findings", 0)))
    html = html.replace("{{total_iocs}}", str(iocs.get("total_iocs", 0)))
    html = html.replace("{{total_techniques}}", str(narrative.get("total_techniques", 0)))
    html = html.replace("{{masked_notice_bar}}", masked_notice_bar)
    html = html.replace("{{json_data}}", json.dumps(json_data, ensure_ascii=False, default=str))

    if not output_path:
        safe_name = case_name.replace(" ", "_").replace("\\", "_").replace("/", "_")[:30]
        output_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            f"report_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
        )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return {
        "status": "success",
        "path": output_path,
        "size_kb": round(os.path.getsize(output_path) / 1024, 1),
        "tabs": ["Executive Summary", "Detailed Analysis", "IOC & Timeline"],
    }


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
