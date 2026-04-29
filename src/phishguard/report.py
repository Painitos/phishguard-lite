from __future__ import annotations

from html import escape

from .analyzer import AnalysisResult


def render_html_report(results: list[AnalysisResult]) -> str:
    rows = "\n".join(_render_row(result) for result in results)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PhishGuard Lite Report</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #15202b;
      --muted: #5f6b76;
      --line: #d6dde5;
      --surface: #f6f8fb;
      --low: #1f8a4c;
      --medium: #ad6b00;
      --high: #be2f37;
    }}
    body {{
      margin: 0;
      font-family: Arial, sans-serif;
      color: var(--ink);
      background: #ffffff;
    }}
    main {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 32px 20px;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 28px;
    }}
    p {{
      color: var(--muted);
      margin: 0 0 24px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
      border: 1px solid var(--line);
    }}
    th, td {{
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      overflow-wrap: anywhere;
    }}
    th {{
      background: var(--surface);
      font-size: 13px;
      text-transform: uppercase;
      color: var(--muted);
    }}
    .score {{
      font-weight: 700;
      white-space: nowrap;
    }}
    .risk-low {{ color: var(--low); }}
    .risk-medium {{ color: var(--medium); }}
    .risk-high {{ color: var(--high); }}
    ul {{
      margin: 0;
      padding-left: 18px;
    }}
  </style>
</head>
<body>
  <main>
    <h1>PhishGuard Lite Report</h1>
    <p>Heuristic URL analysis for defensive review. Scores are indicators, not proof.</p>
    <table>
      <thead>
        <tr>
          <th style="width: 36%">URL</th>
          <th style="width: 12%">Score</th>
          <th style="width: 12%">Risk</th>
          <th>Findings</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </main>
</body>
</html>
"""


def _render_row(result: AnalysisResult) -> str:
    findings = "".join(
        f"<li><strong>{escape(finding.severity)}</strong>: {escape(finding.message)}</li>"
        for finding in result.findings
    )
    if not findings:
        findings = "<li>No phishing-like indicators found.</li>"

    risk_class = f"risk-{result.risk_level}"
    return f"""<tr>
  <td>{escape(result.normalized_url)}</td>
  <td class="score">{result.score}/100</td>
  <td class="{risk_class}">{escape(result.risk_level)}</td>
  <td><ul>{findings}</ul></td>
</tr>"""
