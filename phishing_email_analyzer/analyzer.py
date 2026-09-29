from __future__ import annotations

import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SUSPICIOUS_KEYWORDS = [
    "verify",
    "urgent",
    "security",
    "alert",
    "confirm",
    "reset",
    "login",
    "bank",
    "suspended",
    "password",
    "suspicious",
    "account",
    "invoice",
    "immediate",
    "update",
    "action required",
    "click here",
]

DEFAULT_MALICIOUS_DOMAINS = [
    "example-security-check",
    "banking-update",
    "verify-bank",
    "secure-login",
    "account-verify",
]


def _extract_text_parts(message: Any) -> list[str]:
    parts: list[str] = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() in {"text/plain", "text/html"}:
            payload = part.get_payload(decode=True)
            if payload is None:
                payload = part.get_payload() or ""
            if isinstance(payload, bytes):
                text = payload.decode("utf-8", errors="replace")
            else:
                text = str(payload)
            parts.append(text)
    return parts


def _extract_urls(text: str) -> list[str]:
    pattern = r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+"
    matches = re.findall(pattern, text, flags=re.IGNORECASE)
    return [match.rstrip(").,;:") for match in matches]


def _safe_domain(url: str) -> str:
    try:
        parsed = urlsplit(url if "//" in url else f"http://{url}")
        return parsed.netloc.lower().split(":")[0].strip()
    except Exception:
        return ""


def _list_domains(urls: list[str]) -> list[str]:
    domains: list[str] = []
    for url in urls:
        domain = _safe_domain(url)
        if domain:
            domains.append(domain)
    return sorted(set(domains))


def _detect_url_obfuscation(urls: list[str]) -> list[str]:
    findings: list[str] = []
    for url in urls:
        domain = _safe_domain(url)
        if not domain:
            continue
        lowered = domain.lower()
        suspicious = False
        reasons: list[str] = []

        if "@" in url:
            suspicious = True
            reasons.append("embedded userinfo")
        if "%" in url or "//" in url:
            suspicious = True
            reasons.append("encoded or double-slash path")
        if len(lowered.split(".")) >= 4:
            suspicious = True
            reasons.append("many subdomains")
        if any(keyword in lowered for keyword in ["verify", "secure", "login", "bank", "update"]):
            suspicious = True
            reasons.append("brand-mimicking keywords")

        if suspicious:
            findings.append({"url": url, "domain": domain, "reasons": reasons})

    return findings


def _authentication_summary(headers: dict[str, str]) -> dict[str, Any]:
    auth = headers.get("Authentication-Results", "")
    result = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "raw": auth,
    }

    if auth:
        patterns = {
            "spf": r"spf=(pass|fail|neutral|softfail|temperror|permerror)",
            "dkim": r"dkim=(pass|fail|neutral|temperror|permerror)",
            "dmarc": r"dmarc=(pass|fail|none|temperror|permerror)",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, auth, flags=re.IGNORECASE)
            if match:
                result[key] = match.group(1).lower()

    for header_name in ("Received-SPF", "X-Received-SPF"):
        value = headers.get(header_name, "")
        if value:
            match = re.search(r"spf=(pass|fail|neutral|softfail|temperror|permerror)", value, flags=re.IGNORECASE)
            if match:
                result["spf"] = match.group(1).lower()

    return result


def _attachment_hashes(message: Any) -> list[dict[str, str]]:
    attachments: list[dict[str, str]] = []
    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = b""
        digest = hashlib.sha256(payload).hexdigest()
        attachments.append({"filename": filename, "sha256": digest})
    return attachments


def _score_keywords(text: str) -> list[str]:
    lowered = text.lower()
    matches = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered]
    return sorted(set(matches))


def _domain_reputation(domain: str) -> str:
    lowered = domain.lower()
    if any(token in lowered for token in DEFAULT_MALICIOUS_DOMAINS):
        return "malicious"
    if any(token in lowered for token in ["verify", "secure", "bank", "login", "update"]):
        return "suspicious"
    return "unknown"


def analyze_email(email_path: str | Path) -> dict[str, Any]:
    path = Path(email_path)
    raw = path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)

    sender = message.get("From", "")
    subject = message.get("Subject", "")
    headers = {key: value for key, value in message.items()}
    body_text = "\n".join(_extract_text_parts(message))
    urls = _extract_urls(body_text)
    domains = _list_domains(urls)
    obfuscation_hits = _detect_url_obfuscation(urls)
    auth_results = _authentication_summary(headers)
    suspicious_keywords = _score_keywords(f"{subject}\n{body_text}")

    score = 0
    if sender:
        score += 5
    if "urgent" in subject.lower() or "verify" in subject.lower():
        score += 15
    if auth_results.get("spf") == "fail":
        score += 20
    if auth_results.get("dkim") == "fail":
        score += 15
    if auth_results.get("dmarc") == "fail":
        score += 25
    if urls:
        score += min(25, len(urls) * 8)
    if domains:
        for domain in domains:
            reputation = _domain_reputation(domain)
            if reputation == "malicious":
                score += 25
            elif reputation == "suspicious":
                score += 12
    if obfuscation_hits:
        score += min(20, len(obfuscation_hits) * 10)
    if suspicious_keywords:
        score += min(30, len(suspicious_keywords) * 6)

    attachments = _attachment_hashes(message)
    if attachments:
        score += 10

    score = min(score, 100)
    is_suspicious = score >= 50

    return {
        "file": str(path),
        "sender": sender,
        "subject": subject,
        "headers": headers,
        "authentication_results": auth_results,
        "urls": urls,
        "domains": domains,
        "url_obfuscation": obfuscation_hits,
        "suspicious_keywords": suspicious_keywords,
        "attachments": attachments,
        "risk_score": score,
        "is_suspicious": is_suspicious,
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m phishing_email_analyzer.analyzer <path-to-email.eml>")
        raise SystemExit(1)

    print(json.dumps(analyze_email(sys.argv[1]), indent=2, ensure_ascii=False))
