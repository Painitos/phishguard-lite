from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from .analyzer import analyze_url


PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PhishGuard Lite</title>
  <style>
    :root {{
      --ink: #17212b;
      --muted: #607080;
      --line: #d9e0e8;
      --surface: #f5f7fa;
      --accent: #126b6f;
      --high: #bd2d3a;
      --medium: #9b650d;
      --low: #167046;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: Arial, sans-serif;
      color: var(--ink);
      background: linear-gradient(180deg, #ffffff 0%, #f5f7fa 100%);
    }}
    main {{
      max-width: 880px;
      margin: 0 auto;
      padding: 48px 20px;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 32px;
    }}
    .subtitle {{
      margin: 0 0 28px;
      color: var(--muted);
      line-height: 1.5;
    }}
    form {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      margin-bottom: 24px;
    }}
    input {{
      width: 100%;
      padding: 13px 14px;
      border: 1px solid var(--line);
      border-radius: 6px;
      font-size: 16px;
    }}
    button {{
      border: 0;
      border-radius: 6px;
      padding: 0 18px;
      background: var(--accent);
      color: #ffffff;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
    }}
    section {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      padding: 20px;
    }}
    .score {{
      font-size: 40px;
      font-weight: 700;
      margin: 0;
    }}
    .risk-high {{ color: var(--high); }}
    .risk-medium {{ color: var(--medium); }}
    .risk-low {{ color: var(--low); }}
    ul {{
      margin: 18px 0 0;
      padding-left: 20px;
      line-height: 1.55;
    }}
    code {{
      overflow-wrap: anywhere;
      color: var(--muted);
    }}
    @media (max-width: 640px) {{
      form {{ grid-template-columns: 1fr; }}
      button {{ min-height: 44px; }}
    }}
  </style>
</head>
<body>
  <main>
    <h1>PhishGuard Lite</h1>
    <p class="subtitle">Defensive URL risk scoring for phishing awareness and triage.</p>
    <form method="post">
      <input name="url" placeholder="https://example.com/login" value="{url}" autofocus>
      <button type="submit">Analyze</button>
    </form>
    {result}
  </main>
</body>
</html>
"""


def run_server(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), PhishGuardHandler)
    print(f"PhishGuard Lite running at http://{host}:{port}")
    server.serve_forever()


class PhishGuardHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._send_page("", "")

    def do_POST(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size).decode("utf-8")
        url = parse_qs(body).get("url", [""])[0]

        try:
            analysis = analyze_url(url)
            findings = "".join(
                f"<li><strong>{item.severity}</strong>: {item.message}</li>"
                for item in analysis.findings
            )
            if not findings:
                findings = "<li>No phishing-like indicators found.</li>"
            normalized_url = _html_escape(analysis.normalized_url)
            result = f"""
            <section>
              <code>{normalized_url}</code>
              <p class="score risk-{analysis.risk_level}">{analysis.score}/100</p>
              <strong class="risk-{analysis.risk_level}">{analysis.risk_level.upper()} risk</strong>
              <ul>{findings}</ul>
            </section>
            """
        except ValueError as exc:
            result = f"<section><strong>{exc}</strong></section>"

        self._send_page(url, result)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_page(self, url: str, result: str) -> None:
        content = PAGE.format(url=_html_escape(url), result=result).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def _html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
