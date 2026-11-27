# Threat model: PII and secrets leaking through model output

## Honesty statement

This project is a **defensive redaction tool**. It does not disclose a new
vulnerability, does not claim a new CVE, and does not make an application
compliant with any privacy regulation. The PII in the examples is synthetic.
Detection is pattern-based and therefore incomplete in both directions (misses
and false positives); `report` mode exists so an operator can review before
redaction.

## 1. How PII gets into model output

* The model was fine-tuned or prompted on records and reproduces identifiers.
* Retrieval/tool results contain customer data that the model paraphrases or
  copies verbatim into the answer.
* Users paste sensitive data into the chat, and the answer echoes it back.
* Credentials appear in stack traces, config snippets or documentation that the
  model summarises.

Once the text is in application logs, APM traces, error trackers or support
tickets, the exposure outlives the chat session. Redaction at the boundary is
cheaper than deleting data from many sinks later.

## 2. What is detected and why the severities

| Kind | Severity | Rationale |
| --- | --- | --- |
| `CREDIT_CARD` | high | financial data; Luhn check keeps precision |
| `API_KEY` | high | direct credential compromise |
| `JWT` | high | bearer credential with a validity window |
| `SECRET` | high | explicit password/token assignment or bearer header |
| `EMAIL` | medium | direct identifier; commonly personal data |
| `PHONE` | medium | direct identifier; culturally specific formats |
| `PRIVATE_IP` | low | internal topology leak; not personal data by itself |

Overlapping spans are resolved deterministically (higher severity and longer
match win) so a JWT inside a `Bearer` header yields one finding, not two.

## 3. Detection method

* Regex with boundaries to avoid matching inside identifiers.
* Credit cards: candidate digit runs are normalized and validated with the Luhn
  checksum and a 13-19 digit length range.
* IPv4: octets are range-checked and only private/loopback/link-local/CGNAT
  ranges are reported; a public IP is not PII here.
* Secrets: key-shape patterns plus a conservative assignment regex; short or
  malformed prefixes are not reported (tested).
* Human-readable output and the JSON report show **masked previews** only.

## 4. What this does not claim

* Not a privacy compliance solution (GDPR/CCPA/HIPAA/PIPL). It is one control.
* Names, addresses, national IDs, medical data and free-form identifiers are
  out of scope.
* Hash mode is pseudonymisation; a determined attacker with the salt can test
  candidate values.
* Redaction only applies where called; vendor logs and prompt stores need their
  own ingestion/egress controls.
* No new CVE, no vulnerability disclosure.

## 5. Limitations, explicitly

* Formatted or locale-specific numbers can be missed; extend the regex list for
  your own data (and add tests).
* `SECRET` assignment detection is intentionally conservative; it misses
  secrets pasted without a label.
* False positives are possible (e.g. a 13-19 digit Luhn-valid test fixture in a
  document). Use `report` mode and tune.
* Masked previews keep the last 2-4 characters; do not treat them as
  non-personal data in very sensitive contexts.
* Hashing is deterministic per salt: cross-deployment correlation is possible
  if the salt is reused.
* The tool processes text; it cannot stop a model from emitting data it was
  given. Data minimisation in the prompt and access control on the sinks remain
  the primary controls.

## 6. Prior art

* OWASP privacy and logging guidance.
* Secret-scanning rules from gitleaks and trufflehog (public rule sets).
* The Luhn checksum for payment card numbers.
* General PII/redaction research and the OpenAI/Anthropic privacy guidance on
  logging model interactions.
