from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from re import search
from typing import Iterable
from urllib.parse import ParseResult, urlparse


SUSPICIOUS_KEYWORDS = {
    "account",
    "auth",
    "bank",
    "billing",
    "confirm",
    "crypto",
    "kyc",
    "login",
    "password",
    "recover",
    "reset",
    "secure",
    "support",
    "update",
    "verify",
    "wallet",
}

BRAND_WORDS = {
    "amazon",
    "apple",
    "binance",
    "coinbase",
    "facebook",
    "google",
    "instagram",
    "microsoft",
    "netflix",
    "paypal",
    "steam",
    "whatsapp",
}

SHORTENER_HOSTS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "s.id",
    "t.co",
    "tinyurl.com",
}

RISKY_TLDS = {
    "biz",
    "click",
    "country",
    "download",
    "gq",
    "info",
    "loan",
    "mom",
    "party",
    "rest",
    "ru",
    "tk",
    "top",
    "work",
    "xyz",
    "zip",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    message: str
    points: int


@dataclass(frozen=True)
class AnalysisResult:
    original_url: str
    normalized_url: str
    host: str
    score: int
    risk_level: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "original_url": self.original_url,
            "normalized_url": self.normalized_url,
            "host": self.host,
            "score": self.score,
            "risk_level": self.risk_level,
            "findings": [
                {"severity": item.severity, "message": item.message, "points": item.points}
                for item in self.findings
            ],
        }


def analyze_url(raw_url: str) -> AnalysisResult:
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    findings = list(_collect_findings(parsed))
    score = min(sum(finding.points for finding in findings), 100)

    return AnalysisResult(
        original_url=raw_url,
        normalized_url=normalized,
        host=host,
        score=score,
        risk_level=risk_level(score),
        findings=tuple(sorted(findings, key=lambda item: _severity_rank(item.severity))),
    )


def analyze_many(urls: Iterable[str]) -> list[AnalysisResult]:
    return [analyze_url(url.strip()) for url in urls if url.strip() and not url.startswith("#")]


def normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise ValueError("URL cannot be empty")
    if "://" not in value:
        value = f"https://{value}"
    return value


def risk_level(score: int) -> str:
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _collect_findings(parsed: ParseResult) -> Iterable[Finding]:
    host = parsed.hostname or ""
    host_parts = host.split(".") if host else []
    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    full_url = parsed.geturl().lower()

    if parsed.scheme != "https":
        yield Finding("medium", "URL does not use HTTPS", 15)

    if parsed.username or parsed.password:
        yield Finding("high", "URL contains embedded credentials", 30)

    if _is_ip_address(host):
        yield Finding("high", "Host is an IP address instead of a domain name", 25)

    if host.startswith("xn--") or ".xn--" in host:
        yield Finding("high", "Domain contains punycode / IDN encoding", 25)

    if len(parsed.geturl()) > 90:
        yield Finding("medium", "URL is unusually long", 10)

    if parsed.path.count("/") >= 4:
        yield Finding("low", "URL has a deep path structure", 6)

    if len(host_parts) >= 4:
        yield Finding("medium", "Domain has many subdomains", 12)

    if host in SHORTENER_HOSTS:
        yield Finding("medium", "URL uses a public URL shortener", 18)

    tld = host_parts[-1] if host_parts else ""
    if tld in RISKY_TLDS:
        yield Finding("medium", f"Top-level domain is commonly abused: .{tld}", 12)

    for keyword in sorted(SUSPICIOUS_KEYWORDS):
        if keyword in full_url:
            yield Finding("medium", f"Suspicious keyword found: {keyword}", 8)

    if search(r"\d{4,}", host):
        yield Finding("low", "Domain contains a long digit sequence", 6)

    if host.count("-") >= 2:
        yield Finding("low", "Domain contains multiple hyphens", 5)

    registered_domain = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else host
    subdomain = ".".join(host_parts[:-2]) if len(host_parts) > 2 else ""
    for brand in sorted(BRAND_WORDS):
        if brand in subdomain and brand not in registered_domain:
            yield Finding("high", "Brand word appears outside the registered domain", 34)
            break

    if "%2f" in path_and_query or "%40" in path_and_query:
        yield Finding("low", "URL contains encoded separators", 6)


def _is_ip_address(host: str) -> bool:
    try:
        ip_address(host)
    except ValueError:
        return False
    return True


def _severity_rank(severity: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(severity, 3)
