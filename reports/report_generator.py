"""
reports/report_generator.py
============================
Phase 2 — Security Report Generator

Produces two output formats from a ``SecurityReport``:
- ``security_report.json``  — Machine-readable full report
- ``security_report.html``  — Professional HTML security assessment

The HTML report includes:
- Executive summary with risk posture banner
- CVSS score cards per finding
- Collapsible proof-of-concept sections
- Prioritised remediation roadmap
- OWASP API Top 10 coverage table
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from models.vulnerability import CVSSScore, SecurityReport, Severity, VulnerabilityFinding
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Colour mapping for severity levels
# ---------------------------------------------------------------------------

_SEVERITY_COLOURS = {
    Severity.CRITICAL: ("#dc2626", "#fef2f2"),   # (border/text, background)
    Severity.HIGH:     ("#ea580c", "#fff7ed"),
    Severity.MEDIUM:   ("#d97706", "#fffbeb"),
    Severity.LOW:      ("#16a34a", "#f0fdf4"),
    Severity.INFO:     ("#6b7280", "#f9fafb"),
}

_SEVERITY_BADGE_BG = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH:     "#ea580c",
    Severity.MEDIUM:   "#d97706",
    Severity.LOW:      "#16a34a",
    Severity.INFO:     "#6b7280",
}

_RISK_POSTURE_GRADIENT = {
    "CRITICAL": "linear-gradient(135deg, #7f1d1d 0%, #dc2626 100%)",
    "HIGH":     "linear-gradient(135deg, #7c2d12 0%, #ea580c 100%)",
    "MEDIUM":   "linear-gradient(135deg, #78350f 0%, #d97706 100%)",
    "LOW":      "linear-gradient(135deg, #14532d 0%, #16a34a 100%)",
    "SECURE":   "linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%)",
    "Unknown":  "linear-gradient(135deg, #374151 0%, #6b7280 100%)",
}


class ReportGenerator:
    """
    Generates JSON and HTML security reports from a ``SecurityReport``.

    Parameters
    ----------
    report:
        The completed ``SecurityReport`` from Phase 2.
    output_dir:
        Directory where report files will be written.
    """

    def __init__(self, report: SecurityReport, output_dir: str = "reports") -> None:
        self._report = report
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    # ── Public interface ────────────────────────────────────────────────────

    def generate_json(self) -> Path:
        """Write the security report as JSON. Returns the output path."""
        output_path = self._output_dir / "security_report.json"
        data = self._report.model_dump(mode="json")

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)

        logger.info("JSON security report written", path=str(output_path))
        return output_path

    def generate_html(self) -> Path:
        """Generate a professional HTML security report. Returns the output path."""
        output_path = self._output_dir / "security_report.html"
        html_content = self._build_html()

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info("HTML security report written", path=str(output_path))
        return output_path

    def generate_all(self) -> tuple[Path, Path]:
        """Generate both JSON and HTML reports."""
        json_path = self.generate_json()
        html_path = self.generate_html()
        return json_path, html_path

    # ── HTML Builder ────────────────────────────────────────────────────────

    def _build_html(self) -> str:
        r = self._report
        s = r.statistics
        posture = s.risk_posture
        gradient = _RISK_POSTURE_GRADIENT.get(posture, _RISK_POSTURE_GRADIENT["Unknown"])

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Build finding cards
        findings_html = ""
        for i, finding in enumerate(
            sorted(r.findings, key=lambda f: -f.cvss_score), start=1
        ):
            findings_html += self._render_finding_card(i, finding)

        # Build OWASP coverage table
        owasp_rows = ""
        for cat, count in sorted(s.by_owasp_category.items()):
            owasp_rows += f"""
            <tr>
                <td>{cat}</td>
                <td><span class="badge badge-vuln">{count} finding{'s' if count != 1 else ''}</span></td>
            </tr>"""

        # Build remediation roadmap
        roadmap_items = ""
        for item in r.remediation_roadmap[:20]:  # Limit to 20
            roadmap_items += f"<li>{self._esc(item)}</li>\n"

        # Severity summary cards
        crit  = s.by_severity.get("CRITICAL", 0)
        high  = s.by_severity.get("HIGH", 0)
        med   = s.by_severity.get("MEDIUM", 0)
        low   = s.by_severity.get("LOW", 0)
        info  = s.by_severity.get("INFO", 0)

        # Scan duration
        duration = "N/A"
        if r.scan_started_at and r.scan_completed_at:
            delta = r.scan_completed_at - r.scan_started_at
            minutes = int(delta.total_seconds() // 60)
            seconds = int(delta.total_seconds() % 60)
            duration = f"{minutes}m {seconds}s"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Security Assessment Report — {self._esc(r.target_url)}</title>
<style>
  :root {{
    --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
    --bg: #0f172a;
    --surface: #1e293b;
    --surface2: #273548;
    --border: #334155;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --accent: #3b82f6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: var(--font); background: var(--bg); color: var(--text); line-height: 1.6; }}
  a {{ color: var(--accent); }}

  /* ── Header ── */
  .header {{
    background: {gradient};
    padding: 2.5rem 2rem;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute; inset: 0;
    background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
  }}
  .header h1 {{ font-size: 2rem; font-weight: 700; color: #fff; position: relative; }}
  .header .subtitle {{ color: rgba(255,255,255,0.8); margin-top: 0.5rem; position: relative; }}
  .risk-banner {{
    display: inline-block;
    background: rgba(0,0,0,0.35);
    border: 2px solid rgba(255,255,255,0.3);
    border-radius: 2rem;
    padding: 0.4rem 1.5rem;
    font-size: 1.1rem;
    font-weight: 700;
    color: #fff;
    margin-top: 1rem;
    position: relative;
  }}

  /* ── Layout ── */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
  section {{ margin-bottom: 2.5rem; }}
  h2 {{
    font-size: 1.3rem; font-weight: 600; margin-bottom: 1rem;
    padding-bottom: 0.5rem; border-bottom: 2px solid var(--border);
    color: var(--accent);
  }}
  h3 {{ font-size: 1rem; font-weight: 600; color: var(--text); margin-bottom: 0.5rem; }}

  /* ── Meta grid ── */
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
  }}
  .meta-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    padding: 1rem 1.25rem;
  }}
  .meta-card .label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }}
  .meta-card .value {{ font-size: 1.1rem; font-weight: 600; margin-top: 0.25rem; }}

  /* ── Severity summary ── */
  .sev-grid {{
    display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem;
  }}
  .sev-card {{
    flex: 1; min-width: 100px;
    border-radius: 0.75rem;
    padding: 1rem;
    text-align: center;
    border-left: 4px solid;
  }}
  .sev-card.CRITICAL {{ border-color: #dc2626; background: rgba(220,38,38,0.12); }}
  .sev-card.HIGH     {{ border-color: #ea580c; background: rgba(234,88,12,0.12); }}
  .sev-card.MEDIUM   {{ border-color: #d97706; background: rgba(217,119,6,0.12); }}
  .sev-card.LOW      {{ border-color: #16a34a; background: rgba(22,163,74,0.12); }}
  .sev-card.INFO     {{ border-color: #6b7280; background: rgba(107,114,128,0.12); }}
  .sev-card .sev-count {{ font-size: 2rem; font-weight: 700; }}
  .sev-card .sev-label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--muted); }}

  /* ── Executive summary ── */
  .exec-summary {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    padding: 1.25rem 1.5rem;
    line-height: 1.8;
  }}

  /* ── Finding card ── */
  .finding-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    margin-bottom: 1.25rem;
    overflow: hidden;
  }}
  .finding-header {{
    display: flex; align-items: center; gap: 1rem;
    padding: 1rem 1.25rem;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
  }}
  .finding-header:hover {{ background: var(--surface2); }}
  .badge {{
    display: inline-block;
    padding: 0.2rem 0.7rem;
    border-radius: 999px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #fff;
  }}
  .badge-vuln {{ background: #3b82f6; }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .cvss-score {{
    font-size: 1.2rem; font-weight: 700;
    min-width: 3rem; text-align: right;
  }}
  .finding-body {{ padding: 1.25rem 1.5rem; display: none; }}
  .finding-body.open {{ display: block; }}

  .detail-row {{ display: grid; grid-template-columns: 140px 1fr; gap: 0.5rem; margin-bottom: 0.5rem; }}
  .detail-label {{ font-size: 0.8rem; color: var(--muted); font-weight: 600; padding-top: 0.1rem; }}
  .detail-value {{ font-size: 0.9rem; }}

  pre {{
    background: #0d1117;
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    padding: 1rem;
    overflow-x: auto;
    font-family: var(--mono);
    font-size: 0.8rem;
    color: #a5f3fc;
    white-space: pre-wrap;
    word-break: break-all;
  }}

  ul.remediation-list {{ padding-left: 1.25rem; }}
  ul.remediation-list li {{ margin-bottom: 0.3rem; font-size: 0.9rem; }}

  /* ── Tables ── */
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 0.65rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
  th {{ background: var(--surface2); font-weight: 600; color: var(--muted); text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.06em; }}
  tr:hover td {{ background: var(--surface2); }}

  /* ── Roadmap ── */
  .roadmap-list {{ list-style: none; padding: 0; }}
  .roadmap-list li {{
    padding: 0.7rem 1rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    margin-bottom: 0.5rem;
    font-size: 0.875rem;
  }}

  /* ── Footer ── */
  .footer {{
    text-align: center;
    padding: 2rem;
    color: var(--muted);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    margin-top: 3rem;
  }}
</style>
</head>
<body>

<!-- ═══ HEADER ═══ -->
<div class="header">
  <h1>🛡 API Security Assessment Report</h1>
  <div class="subtitle">{self._esc(r.target_url)} &nbsp;·&nbsp; {now_str}</div>
  <div class="risk-banner">Overall Risk Posture: {posture}</div>
</div>

<div class="container">

<!-- ═══ SCAN METADATA ═══ -->
<section>
  <h2>Scan Metadata</h2>
  <div class="meta-grid">
    <div class="meta-card">
      <div class="label">Report ID</div>
      <div class="value" style="font-size:0.85rem;">{self._esc(r.report_id)}</div>
    </div>
    <div class="meta-card">
      <div class="label">Target</div>
      <div class="value">{self._esc(r.target_url)}</div>
    </div>
    <div class="meta-card">
      <div class="label">Scan Duration</div>
      <div class="value">{duration}</div>
    </div>
    <div class="meta-card">
      <div class="label">Total Findings</div>
      <div class="value">{s.total_findings}</div>
    </div>
    <div class="meta-card">
      <div class="label">Confirmed Vulns</div>
      <div class="value">{s.confirmed_vulnerabilities}</div>
    </div>
    <div class="meta-card">
      <div class="label">Highest CVSS</div>
      <div class="value">{s.highest_cvss:.1f}</div>
    </div>
    <div class="meta-card">
      <div class="label">Endpoints Tested</div>
      <div class="value">{s.total_endpoints_tested}</div>
    </div>
    <div class="meta-card">
      <div class="label">Phase 1 Catalog</div>
      <div class="value" style="font-size:0.8rem;">{self._esc(r.catalog_source)}</div>
    </div>
  </div>
</section>

<!-- ═══ SEVERITY SUMMARY ═══ -->
<section>
  <h2>Vulnerability Summary</h2>
  <div class="sev-grid">
    <div class="sev-card CRITICAL">
      <div class="sev-count" style="color:#dc2626;">{crit}</div>
      <div class="sev-label">Critical</div>
    </div>
    <div class="sev-card HIGH">
      <div class="sev-count" style="color:#ea580c;">{high}</div>
      <div class="sev-label">High</div>
    </div>
    <div class="sev-card MEDIUM">
      <div class="sev-count" style="color:#d97706;">{med}</div>
      <div class="sev-label">Medium</div>
    </div>
    <div class="sev-card LOW">
      <div class="sev-count" style="color:#16a34a;">{low}</div>
      <div class="sev-label">Low</div>
    </div>
    <div class="sev-card INFO">
      <div class="sev-count" style="color:#6b7280;">{info}</div>
      <div class="sev-label">Info</div>
    </div>
  </div>
</section>

<!-- ═══ EXECUTIVE SUMMARY ═══ -->
<section>
  <h2>Executive Summary</h2>
  <div class="exec-summary">
    <p>{self._esc(r.executive_summary)}</p>
  </div>
</section>

<!-- ═══ FINDINGS ═══ -->
<section>
  <h2>Vulnerability Findings ({len(r.findings)})</h2>
  {findings_html if r.findings else '<p style="color:var(--muted)">No vulnerabilities detected.</p>'}
</section>

<!-- ═══ OWASP COVERAGE ═══ -->
<section>
  <h2>OWASP API Top 10 Coverage</h2>
  <table>
    <thead><tr><th>OWASP Category</th><th>Findings</th></tr></thead>
    <tbody>{owasp_rows if owasp_rows else '<tr><td colspan="2" style="color:var(--muted)">No OWASP findings mapped.</td></tr>'}</tbody>
  </table>
</section>

<!-- ═══ REMEDIATION ROADMAP ═══ -->
<section>
  <h2>Remediation Roadmap</h2>
  {'<ul class="roadmap-list">' + roadmap_items + '</ul>' if roadmap_items else '<p style="color:var(--muted)">No remediation items.</p>'}
</section>

</div><!-- /container -->

<div class="footer">
  Generated by Phase 2 — Security Testing Specialist &nbsp;·&nbsp;
  Multi-Agent AI Security Testing Platform &nbsp;·&nbsp;
  {now_str}
</div>

<script>
// Toggle finding body on header click
document.querySelectorAll('.finding-header').forEach(header => {{
  header.addEventListener('click', () => {{
    const body = header.nextElementSibling;
    body.classList.toggle('open');
    const indicator = header.querySelector('.toggle-indicator');
    if (indicator) indicator.textContent = body.classList.contains('open') ? '▲' : '▼';
  }});
}});
</script>
</body>
</html>"""

        return html

    def _render_finding_card(self, index: int, finding: VulnerabilityFinding) -> str:
        sev = finding.severity
        colour = _SEVERITY_BADGE_BG.get(sev, "#6b7280")
        border_col, bg_col = _SEVERITY_COLOURS.get(sev, ("#6b7280", "#f9fafb"))

        confirmed_badge = (
            '<span class="badge" style="background:#16a34a;">CONFIRMED</span>'
            if finding.confirmed
            else '<span class="badge" style="background:#6b7280;">SUSPECTED</span>'
        )

        # Evidence table
        evidence_rows = ""
        for ev in finding.evidence[:3]:
            ev_body = (
                json.dumps(ev.response_body, indent=2)[:300]
                if ev.response_body
                else ""
            )
            evidence_rows += f"""
            <tr>
              <td><code>{self._esc(ev.method)}</code></td>
              <td style="font-size:0.8rem;">{self._esc(ev.url)}</td>
              <td><code>{ev.response_status}</code></td>
            </tr>"""

        evidence_section = ""
        if evidence_rows:
            evidence_section = f"""
            <div style="margin-top:1rem;">
              <h3>HTTP Evidence</h3>
              <table>
                <thead><tr><th>Method</th><th>URL</th><th>Status</th></tr></thead>
                <tbody>{evidence_rows}</tbody>
              </table>
            </div>"""

        # PoC
        poc_section = ""
        if finding.proof_of_concept:
            poc_section = f"""
            <div style="margin-top:1rem;">
              <h3>Proof of Concept</h3>
              <pre>{self._esc(finding.proof_of_concept)}</pre>
            </div>"""

        # Remediation
        remediation_items = "".join(
            f"<li>{self._esc(r)}</li>" for r in finding.remediation
        )
        remediation_section = f"""
        <div style="margin-top:1rem;">
          <h3>Remediation</h3>
          <ul class="remediation-list">{remediation_items}</ul>
        </div>""" if remediation_items else ""

        return f"""
<div class="finding-card" id="finding-{index}" style="border-left: 4px solid {colour};">
  <div class="finding-header">
    <span class="badge" style="background:{colour};">{sev.value}</span>
    {confirmed_badge}
    <span class="finding-title">{self._esc(finding.vuln_id)} — {self._esc(finding.title)}</span>
    <span class="cvss-score" style="color:{colour};">{finding.cvss_score:.1f}</span>
    <span class="toggle-indicator" style="color:var(--muted);margin-left:0.5rem;">▼</span>
  </div>
  <div class="finding-body">
    <div class="detail-row">
      <div class="detail-label">OWASP Category</div>
      <div class="detail-value">{self._esc(finding.owasp_category.value)}</div>
    </div>
    <div class="detail-row">
      <div class="detail-label">Endpoint</div>
      <div class="detail-value"><code>{self._esc(finding.method)} {self._esc(finding.endpoint)}</code></div>
    </div>
    <div class="detail-row">
      <div class="detail-label">CVSS v3.1</div>
      <div class="detail-value">
        <strong>{finding.cvss_score:.1f}</strong>
        {f'<code style="font-size:0.75rem;color:var(--muted);margin-left:0.5rem;">{self._esc(finding.cvss.vector)}</code>' if finding.cvss.vector else ''}
      </div>
    </div>
    <div class="detail-row">
      <div class="detail-label">Description</div>
      <div class="detail-value">{self._esc(finding.description)}</div>
    </div>
    <div class="detail-row">
      <div class="detail-label">Impact</div>
      <div class="detail-value">{self._esc(finding.impact)}</div>
    </div>
    {evidence_section}
    {poc_section}
    {remediation_section}
  </div>
</div>"""

    @staticmethod
    def _esc(text: str) -> str:
        """HTML-escape a string."""
        if not isinstance(text, str):
            text = str(text) if text is not None else ""
        return (
            text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
