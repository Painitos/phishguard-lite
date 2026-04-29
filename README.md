# PhishGuard Lite

PhishGuard Lite is a small defensive cybersecurity tool that scores URLs for phishing-like signals. It is built as a portfolio-friendly project: readable Python, a CLI, HTML reports, tests, and a tiny local web interface.

> For education and defensive analysis only. Only analyze URLs you are allowed to inspect.

## Features

- URL risk scoring from 0 to 100
- Human-readable findings with severity levels
- JSON and HTML report output
- Batch mode for URL lists
- Local web UI powered by Python's standard library
- No external dependencies

## Detection Signals

PhishGuard Lite checks for indicators such as:

- Missing HTTPS
- IP address hostnames
- suspicious keywords like `login`, `verify`, `wallet`, `update`
- punycode / IDN domains
- long URLs and deep paths
- too many subdomains
- misleading brand words in subdomains
- risky top-level domains
- excessive digits or hyphens
- embedded credentials in URLs
- URL shorteners

The score is heuristic, not a verdict. A low score does not prove a URL is safe, and a high score should be investigated with proper tooling.

## Quick Start

```powershell
python -m pip install -e .
phishguard analyze "https://example.com/login"
```

Or without installing the console command:

```powershell
$env:PYTHONPATH = "src"
python -m phishguard.cli analyze "https://example.com/login"
```

## CLI Usage

Analyze one URL:

```powershell
phishguard analyze "http://paypal-login.example.com/verify"
```

Return JSON:

```powershell
phishguard analyze "http://paypal-login.example.com/verify" --json
```

Analyze a file:

```powershell
phishguard batch examples/urls.txt --json
```

Create an HTML report:

```powershell
phishguard report examples/urls.txt --output report.html
```

Start the local web UI:

```powershell
phishguard serve --port 8080
```

On Windows from a local checkout, you can also run:

```powershell
.\scripts\run_server.ps1 -Port 8080
```

## Example Output

```text
URL: http://paypal-login.example.com/verify
Risk score: 65/100
Risk level: high

[high] Brand word appears outside the registered domain
[medium] URL does not use HTTPS
[medium] Suspicious keyword found: login
[medium] Suspicious keyword found: verify
```

## Project Structure

```text
src/phishguard/
  analyzer.py   URL parsing, feature extraction, scoring
  cli.py        Command-line interface
  report.py     HTML report rendering
  server.py     Local web interface
tests/
  test_analyzer.py
examples/
  urls.txt
```

## Run Tests

```powershell
python -m pip install -e .
python -m unittest discover -s tests
```

## Roadmap

- Add CSV export
- Add allowlist support
- Add DNS age enrichment when network access is available
- Add screenshot capture for internal lab URLs
- Add YARA-like rule definitions for URL patterns

## Legal Notice

This project is intended for defensive security, awareness training, and portfolio demonstration. Do not use it to scan, test, or profile systems without authorization.
