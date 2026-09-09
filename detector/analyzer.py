"""Transparent, educational URL risk analysis.

The checks in this module inspect URL structure only. They do not connect to a
website, download content, or claim that a URL is definitely safe or malicious.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import SplitResult, urlsplit

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "banking",
    "password",
    "confirmation",
}

SHORTENING_SERVICES = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
}


def _check(name: str, status: str, detail: str, points: int = 0) -> dict:
    return {"name": name, "status": status, "detail": detail, "points": points}


def _host_is_ip(hostname: str | None) -> bool:
    if not hostname:
        return False
    candidate = hostname.strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def _subdomain_count(hostname: str | None) -> int:
    if not hostname or _host_is_ip(hostname):
        return 0
    labels = [part for part in hostname.split(".") if part]
    return max(0, len(labels) - 2)


def _looks_unusual(parsed: SplitResult, hostname: str | None) -> bool:
    if not hostname:
        return True
    if parsed.port is not None and parsed.port not in {80, 443}:
        return True
    if parsed.username or parsed.password:
        return True
    if "//" in parsed.path or "\\" in parsed.path:
        return True
    return False


def _validate_input(raw_url: str) -> tuple[str, SplitResult]:
    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("Please enter a URL to analyze.")
    if len(cleaned) > 2048:
        raise ValueError("The URL is too long to analyze (maximum 2,048 characters).")
    if not re.match(r"^https?://", cleaned, re.IGNORECASE):
        raise ValueError("Include a web scheme such as https:// or http://.")
    parsed = urlsplit(cleaned)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a complete HTTP or HTTPS URL with a domain name.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port number.") from exc
    return cleaned, parsed


def analyze_url(raw_url: str) -> dict:
    """Analyze a URL and return a presentation-ready risk report."""
    cleaned, parsed = _validate_input(raw_url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    lowered_url = cleaned.lower()
    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    labels = [part for part in hostname.split(".") if part]
    keyword_hits = sorted(
        keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered_url
    )
    hyphen_count = lowered_url.count("-")
    digit_count = sum(character.isdigit() for character in hostname)
    subdomains = _subdomain_count(hostname)
    ip_address = _host_is_ip(hostname)
    unusual_structure = _looks_unusual(parsed, hostname)
    shortening_service = hostname in SHORTENING_SERVICES

    checks = [
        _check(
            "HTTPS encryption",
            "pass" if parsed.scheme.lower() == "https" else "warning",
            "HTTPS is used for the connection." if parsed.scheme.lower() == "https" else "HTTP does not encrypt the connection in transit.",
            0 if parsed.scheme.lower() == "https" else 15,
        ),
        _check(
            "IP address host",
            "warning" if ip_address else "pass",
            "The host is a numeric IP address rather than a named domain." if ip_address else "The host uses a named domain.",
            25 if ip_address else 0,
        ),
        _check(
            "URL length",
            "warning" if len(cleaned) > 120 else "pass",
            f"The URL contains {len(cleaned)} characters." + (" Long URLs can hide important details." if len(cleaned) > 120 else ""),
            10 if len(cleaned) > 120 else 0,
        ),
        _check(
            "Subdomain count",
            "warning" if subdomains >= 3 else "pass",
            f"The hostname contains {subdomains} subdomain(s)." + (" Multiple subdomains can make the real domain harder to spot." if subdomains >= 3 else ""),
            10 if subdomains >= 3 else 0,
        ),
        _check(
            "At-symbol or embedded credentials",
            "warning" if parsed.username or parsed.password or "@" in cleaned else "pass",
            "An @ symbol or embedded user information can obscure the actual destination." if parsed.username or parsed.password or "@" in cleaned else "No @ symbol or embedded credentials were found.",
            20 if parsed.username or parsed.password or "@" in cleaned else 0,
        ),
        _check(
            "Hyphen usage",
            "warning" if hyphen_count >= 3 else "pass",
            f"The URL contains {hyphen_count} hyphen(s)." + (" Many hyphens may indicate a look-alike domain." if hyphen_count >= 3 else ""),
            10 if hyphen_count >= 3 else 0,
        ),
        _check(
            "Numeric host characters",
            "warning" if digit_count >= 4 else "pass",
            f"The hostname contains {digit_count} number(s)." + (" Unusual number patterns deserve extra review." if digit_count >= 4 else ""),
            5 if digit_count >= 4 else 0,
        ),
        _check(
            "Suspicious keywords",
            "warning" if keyword_hits else "pass",
            "Found: " + ", ".join(keyword_hits) if keyword_hits else "No common urgency or credential-related keywords were found.",
            min(15, len(keyword_hits) * 5),
        ),
        _check(
            "URL structure",
            "warning" if unusual_structure else "pass",
            "The URL contains an unusual port, credentials, or path separators." if unusual_structure else "The URL structure is conventional.",
            10 if unusual_structure else 0,
        ),
        _check(
            "Known URL shortener",
            "warning" if shortening_service else "pass",
            "A shortening service hides the final destination until the link is opened." if shortening_service else "The host is not a commonly recognized URL shortener.",
            10 if shortening_service else 0,
        ),
    ]

    score = min(100, sum(item["points"] for item in checks))
    if score <= 30:
        classification = "Likely Safe"
        tone = "safe"
    elif score <= 60:
        classification = "Suspicious"
        tone = "suspicious"
    else:
        classification = "Potential Phishing"
        tone = "danger"

    return {
        "url": cleaned,
        "score": score,
        "classification": classification,
        "tone": tone,
        "checks": checks,
        "summary": _summary(classification, score, keyword_hits, ip_address, parsed.scheme.lower()),
        "keyword_hits": keyword_hits,
        "subdomains": subdomains,
        "path_preview": path_and_query[:120],
    }


def _summary(classification: str, score: int, keywords: list[str], ip_address: bool, scheme: str) -> str:
    reasons = []
    if scheme != "https":
        reasons.append("HTTP is used")
    if ip_address:
        reasons.append("the host is an IP address")
    if keywords:
        reasons.append("credential or urgency-related words appear")
    if not reasons:
        reasons.append("the inspected URL structure contains few warning signals")
    return f"{classification} based on a transparent score of {score}/100: " + "; ".join(reasons) + "."
