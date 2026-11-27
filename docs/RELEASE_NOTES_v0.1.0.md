## model-pii-redactor v0.1.0

Detect and redact PII and secrets in model output (and in prompts you log),
stdlib-only.

### Included

- `python -m pii_redactor scan|redact|report` with `--json`, `--fail-on` and
  three redaction modes: `report` (no change), `redact` (typed placeholders) and
  `hash` (deterministic salted SHA-256 labels). Exit codes 0/1/2.
- Detectors: emails, phone numbers (E.164 / US / CN mobile / CN landline),
  credit cards with a real Luhn check, private/loopback IPv4, API-key patterns
  (`sk-`, `ghp_`, `github_pat_`, `AKIA`, `AIza`, `xox[baprs]-`, `glpat-`),
  JWTs, Bearer tokens and `api_key=...`/`password=...` style assignments.
- Human-readable output shows **masked** previews only (no raw PII in logs).
- 40 unit tests, GitHub Actions CI on Python 3.10/3.12, real captured evidence.

### Honest notes

- Pattern-based detection is heuristic: formatted/unusual PII can be missed and
  benign strings can be flagged (that is why `report` mode exists before
  redaction). It does not disclose a new vulnerability and does not claim a new
  CVE.
- A Luhn pass is a strong signal but not proof that a number is a real card.
- JSON report previews are masked; do not paste raw model output into issue
  trackers when reporting a false positive.
