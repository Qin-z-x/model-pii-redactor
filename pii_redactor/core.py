"""pii_redactor core: detect and redact PII and secrets in text.

Detectors are independent regexes plus small validators (Luhn for cards, octet
range checks for IPs). ``scan`` returns spans; ``redact`` applies one of three
modes (report / redact / hash) and never leaks raw values in the report output.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

VERSION = "0.1.0"

SEVERITIES = ("low", "medium", "high")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES, start=1)}

EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w.-])")
US_PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[ -]?)?\(?\d{3}\)?[ -]\d{3}[ -]\d{4}(?!\d)")
E164_PHONE_RE = re.compile(r"(?<![\w+])\+[1-9]\d{6,14}(?!\d)")
CN_MOBILE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
CN_LANDLINE_RE = re.compile(r"(?<!\d)0\d{2,3}-\d{7,8}(?!\d)")
CARD_CANDIDATE_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
JWT_RE = re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![\w-])")
BEARER_RE = re.compile(r"(?i)\b(?:bearer|authorization:\s*bearer)\s+([A-Za-z0-9._~+/=-]{20,})")
KEY_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key)\b"
    r"\s*[=:]\s*[\"']?([A-Za-z0-9_\-./+=]{12,})"
)
API_KEY_PATTERNS = [
    ("API_KEY", "openai-style sk- key", re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}")),
    ("API_KEY", "GitHub ghp_ token", re.compile(r"(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9_])")),
    ("API_KEY", "GitHub fine-grained PAT", re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,}(?![A-Za-z0-9_])")),
    ("API_KEY", "AWS access key id", re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![0-9A-Z])")),
    ("API_KEY", "Google API key", re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])")),
    ("API_KEY", "Slack token", re.compile(r"(?<![A-Za-z0-9_-])xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("API_KEY", "GitLab PAT", re.compile(r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}")),
]

KIND_SEVERITY = {
    "EMAIL": "medium",
    "PHONE": "medium",
    "CREDIT_CARD": "high",
    "PRIVATE_IP": "low",
    "API_KEY": "high",
    "JWT": "high",
    "SECRET": "high",
}

DESCRIPTIONS = {
    "EMAIL": "email address",
    "PHONE": "phone number",
    "CREDIT_CARD": "credit card number with a valid Luhn checksum",
    "PRIVATE_IP": "private/loopback IPv4 address",
    "API_KEY": "API key or access token",
    "JWT": "JSON Web Token",
    "SECRET": "secret assignment (password/token/key)",
}


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: str
    start: int
    end: int
    value: str = field(repr=False, default="")
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "start": self.start,
            "end": self.end,
            "length": self.end - self.start,
            "preview": mask_value(self.kind, self.value),
            "detail": self.detail or DESCRIPTIONS.get(self.kind, ""),
        }


def mask_value(kind: str, value: str) -> str:
    """Return a masked preview that is safe to print in logs."""
    if not value:
        return ""
    if kind == "EMAIL":
        local, _, domain = value.partition("@")
        return (local[:1] + "***@" + domain) if domain else "***"
    if kind == "PHONE":
        digits = re.sub(r"\D", "", value)
        return "***" + digits[-2:]
    if kind == "CREDIT_CARD":
        digits = re.sub(r"\D", "", value)
        return "**** **** **** " + digits[-4:]
    if kind == "PRIVATE_IP":
        return ".".join(value.split(".")[:2]) + ".***.***"
    return value[:4] + "***" + value[-2:]


def luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        if not char.isdigit():
            return False
        number = int(char)
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0 and len(digits) >= 13


def _is_private_ip(octets: list) -> bool:
    first, second = octets[0], octets[1]
    if first == 10 or first == 127:
        return True
    if first == 169 and second == 254:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 100 and 64 <= second <= 127:
        return True
    return False


def _iter_matches(pattern, text: str):
    for match in pattern.finditer(text):
        yield match.start(), match.end(), match.group(0), match


def detect(text: str) -> list:
    """Return all candidate findings (overlaps unresolved)."""
    findings = []
    for start, end, value, _match in _iter_matches(EMAIL_RE, text):
        findings.append(Finding("EMAIL", "medium", start, end, value))
    for pattern in (US_PHONE_RE, E164_PHONE_RE, CN_MOBILE_RE, CN_LANDLINE_RE):
        for start, end, value, _match in _iter_matches(pattern, text):
            findings.append(Finding("PHONE", "medium", start, end, value))
    for start, end, value, _match in _iter_matches(CARD_CANDIDATE_RE, text):
        digits = re.sub(r"\D", "", value)
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            findings.append(Finding("CREDIT_CARD", "high", start, end, value, detail="credit card number with a valid Luhn checksum"))
    for match in IPV4_RE.finditer(text):
        octets = [int(part) for part in match.groups()]
        if any(octet > 255 for octet in octets):
            continue
        if _is_private_ip(octets):
            findings.append(Finding("PRIVATE_IP", "low", match.start(), match.end(), match.group(0)))
    for kind, detail, pattern in API_KEY_PATTERNS:
        for start, end, value, _match in _iter_matches(pattern, text):
            findings.append(Finding(kind, "high", start, end, value, detail))
    for start, end, value, _match in _iter_matches(JWT_RE, text):
        findings.append(Finding("JWT", "high", start, end, value))
    for match in BEARER_RE.finditer(text):
        findings.append(Finding("SECRET", "high", match.start(), match.end(), match.group(0), detail="bearer token"))
    for match in KEY_ASSIGNMENT_RE.finditer(text):
        findings.append(Finding("SECRET", "high", match.start(1), match.end(1), match.group(1), detail="secret assignment"))
    return findings


def _resolve_overlaps(findings) -> list:
    ordered = sorted(findings, key=lambda finding: (finding.start, -SEVERITY_RANK[finding.severity], -(finding.end - finding.start)))
    kept = []
    for finding in ordered:
        if kept and finding.start < kept[-1].end:
            continue
        kept.append(finding)
    return kept


def scan(text: str) -> list:
    """Return non-overlapping findings sorted by position."""
    return _resolve_overlaps(detect(text))


def summarize(findings) -> dict:
    counts = {kind: 0 for kind in KIND_SEVERITY}
    by_severity = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.kind] = counts.get(finding.kind, 0) + 1
        by_severity[finding.severity] += 1
    max_severity = "none"
    for severity in SEVERITIES:
        if by_severity[severity]:
            max_severity = severity
    return {"total": len(findings), "counts": counts, "by_severity": by_severity, "max_severity": max_severity}


def _hash_label(kind: str, value: str, salt: str) -> str:
    digest = hashlib.sha256((salt + value).encode("utf-8")).hexdigest()[:16]
    return "%s:sha256:%s" % (kind, digest)


def redact(text: str, mode: str = "redact", salt: str = "") -> dict:
    """Apply one of the modes and return the result, findings and counts."""
    if mode not in ("report", "redact", "hash"):
        raise ValueError("mode must be 'report', 'redact' or 'hash'")
    findings = scan(text)
    if mode == "report" or not findings:
        output = text
    else:
        pieces = []
        position = 0
        for finding in findings:
            pieces.append(text[position:finding.start])
            if mode == "redact":
                pieces.append("[REDACTED:%s]" % finding.kind)
            else:
                pieces.append(_hash_label(finding.kind, finding.value, salt))
            position = finding.end
        pieces.append(text[position:])
        output = "".join(pieces)
    summary = summarize(findings)
    return {
        "tool": "model-pii-redactor",
        "version": VERSION,
        "mode": mode,
        "summary": summary,
        "clean": not findings,
        "findings": [finding.to_dict() for finding in findings],
        "text": output,
    }
