"""
dashboard_generator.py
-----------------------
Builds a single static HTML file (dashboard.html) summarizing every
alert report ever generated in reports/, styled as a terminal-style
SOC dashboard. Open the file in any browser -- no server needed.
"""

import glob
import json
import os
import time

CSS = """
:root {
  --bg: #0a0e0a;
  --panel: #10160f;
  --panel-border: #1f2b1e;
  --text: #c9d6c9;
  --text-dim: #6f7d6f;
  --green: #6bff8f;
  --amber: #ffb454;
  --red: #ff5c5c;
  --mono: 'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, Consolas, monospace;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--mono);
  padding: 32px 16px 64px;
  line-height: 1.5;
}

.window {
  max-width: 960px;
  margin: 0 auto;
  border: 1px solid var(--panel-border);
  border-radius: 8px;
  overflow: hidden;
  background: var(--panel);
}

.titlebar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  background: #0d130c;
  border-bottom: 1px solid var(--panel-border);
}

.dot { width: 11px; height: 11px; border-radius: 50%; }
.dot.red { background: #ff5f56; }
.dot.amber { background: #ffbd2e; }
.dot.green { background: #27c93f; }

.titlebar-label {
  margin-left: 8px;
  color: var(--text-dim);
  font-size: 13px;
}

.content { padding: 28px 32px 36px; }

.prompt { color: var(--green); }
.prompt::before { content: "$ "; color: var(--text-dim); }

h1 {
  font-size: 20px;
  margin: 0 0 4px;
  color: var(--green);
  letter-spacing: 0.5px;
}

.subtitle {
  color: var(--text-dim);
  font-size: 13px;
  margin-bottom: 28px;
}

.cursor {
  display: inline-block;
  width: 8px;
  height: 15px;
  background: var(--green);
  margin-left: 6px;
  animation: blink 1.1s steps(1) infinite;
  vertical-align: -2px;
}

@keyframes blink { 50% { opacity: 0; } }

.stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
  margin-bottom: 30px;
}

.stat {
  border: 1px solid var(--panel-border);
  border-radius: 6px;
  padding: 14px 16px;
  background: #0c110b;
}

.stat .label {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-dim);
  margin-bottom: 6px;
}

.stat .value { font-size: 26px; font-weight: 600; }
.stat .value.red { color: var(--red); }
.stat .value.green { color: var(--green); }
.stat .value.amber { color: var(--amber); }
.stat .value.dim { color: var(--text); }

.divider {
  border: none;
  border-top: 1px dashed var(--panel-border);
  margin: 26px 0;
}

.section-label {
  color: var(--text-dim);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-bottom: 12px;
}

table { width: 100%; border-collapse: collapse; font-size: 13px; }

th {
  text-align: left;
  color: var(--text-dim);
  font-weight: 500;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  padding: 8px 10px;
  border-bottom: 1px solid var(--panel-border);
}

td {
  padding: 10px;
  border-bottom: 1px solid #161f15;
  vertical-align: top;
  word-break: break-all;
}

tr:hover td { background: #0d130c; }

.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.5px;
}

.badge.local { background: rgba(255, 92, 92, 0.15); color: var(--red); }
.badge.vt { background: rgba(255, 180, 84, 0.15); color: var(--amber); }

.hash { color: var(--text-dim); font-size: 12px; }

.empty {
  color: var(--text-dim);
  padding: 30px 10px;
  text-align: center;
  border: 1px dashed var(--panel-border);
  border-radius: 6px;
}

.footer {
  margin-top: 30px;
  color: var(--text-dim);
  font-size: 11px;
  text-align: center;
}
"""


def _load_all_reports(reports_dir):
    """Read every alert_report_*.json file and merge their alerts."""
    all_alerts = []
    report_files = sorted(glob.glob(os.path.join(reports_dir, "alert_report_*.json")))

    for path in report_files:
        try:
            with open(path, "r") as f:
                data = json.load(f)
            for alert in data.get("alerts", []):
                alert = dict(alert)
                alert["report_time"] = data.get("generated_at", "")
                all_alerts.append(alert)
        except (json.JSONDecodeError, IOError):
            continue

    return all_alerts, len(report_files)


def generate_dashboard(reports_dir, output_path):
    """
    Build dashboard.html from every report in reports_dir.
    Returns the output path.
    """
    alerts, report_count = _load_all_reports(reports_dir)

    local_count = sum(1 for a in alerts if a.get("source") == "local_signature_db")
    vt_count = sum(1 for a in alerts if a.get("source") == "virustotal")

    rows_html = ""
    if alerts:
        # Most recent first
        for a in reversed(alerts):
            badge_class = "local" if a.get("source") == "local_signature_db" else "vt"
            badge_label = "LOCAL DB" if a.get("source") == "local_signature_db" else "VIRUSTOTAL"
            rows_html += f"""
            <tr>
              <td>{a.get('report_time', '')}</td>
              <td>{a.get('file', '')}</td>
              <td class="hash">{a.get('hash', '')}</td>
              <td><span class="badge {badge_class}">{badge_label}</span></td>
              <td>{a.get('label', '')}</td>
            </tr>"""
        table_html = f"""
        <table>
          <thead>
            <tr>
              <th>Detected At</th>
              <th>File</th>
              <th>SHA-256</th>
              <th>Source</th>
              <th>Label</th>
            </tr>
          </thead>
          <tbody>{rows_html}
          </tbody>
        </table>"""
    else:
        table_html = '<div class="empty">No detections recorded yet. Run a scan to populate this dashboard.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AV Simulation :: Dashboard</title>
<style>{CSS}</style>
</head>
<body>
  <div class="window">
    <div class="titlebar">
      <span class="dot red"></span>
      <span class="dot amber"></span>
      <span class="dot green"></span>
      <span class="titlebar-label">av-simulation — dashboard.html</span>
    </div>
    <div class="content">
      <h1><span class="prompt">basic-av-sim --dashboard</span><span class="cursor"></span></h1>
      <div class="subtitle">Generated {time.strftime("%Y-%m-%d %H:%M:%S")} · {report_count} scan report(s) loaded</div>

      <div class="stats">
        <div class="stat">
          <div class="label">Total Detections</div>
          <div class="value {'red' if alerts else 'dim'}">{len(alerts)}</div>
        </div>
        <div class="stat">
          <div class="label">Local Signature Hits</div>
          <div class="value red">{local_count}</div>
        </div>
        <div class="stat">
          <div class="label">VirusTotal Hits</div>
          <div class="value amber">{vt_count}</div>
        </div>
        <div class="stat">
          <div class="label">Scan Reports</div>
          <div class="value green">{report_count}</div>
        </div>
      </div>

      <hr class="divider">
      <div class="section-label">// detection history</div>
      {table_html}

      <div class="footer">Basic Antivirus Simulation — educational project. Not a substitute for real endpoint protection.</div>
    </div>
  </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
