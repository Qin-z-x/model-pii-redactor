# Video assets: pii-redactor

Every command and output below was captured from the real CLI on the build machine.

## Beat sheet (outputs are captured from real runs)

| time | beat | command | captured output (first line) |
| --- | --- | --- | --- |
| 0:00-0:30 | Hook: the model output contains a card, keys and a JWT | `python -m pii_redactor scan examples/poisoned_output.txt` | model-pii-redactor 0.1.0  scan  examples/poisoned_output.txt  (13 lines, 507 chars) |
| 0:30-1:05 | Gate the log pipeline on high-severity leaks | `python -m pii_redactor scan examples/poisoned_output.txt --fail-on high` | model-pii-redactor 0.1.0  scan  examples/poisoned_output.txt  (13 lines, 507 chars) |
| 1:05-1:45 | Redact with typed placeholders | `python -m pii_redactor redact examples/poisoned_output.txt -o evidence/raw/redacted_output.txt` | wrote evidence/raw/redacted_output.txt (mode=redact, findings=10: 6 high, 3 medium, 1 low) |
| 1:45-2:15 | Hash mode for stable correlation | `python -m pii_redactor redact examples/poisoned_output.txt --mode hash --json` | { |
| 2:15-2:40 | Tests and honest limits | python -m unittest discover -s tests -t . | Ran 40 tests in ... OK |

## Real command transcripts for the recording

### 0:00-0:30 -- Hook: the model output contains a card, keys and a JWT

Point at the masked previews: the human-readable log never prints the raw values.

```console
$ python -m pii_redactor scan examples/poisoned_output.txt
model-pii-redactor 0.1.0  scan  examples/poisoned_output.txt  (13 lines, 507 chars)
MEDIUM EMAIL        line 4    col 8    j***@acme-corp.example (email address)
MEDIUM PHONE        line 5    col 8    ***32 (phone number)
MEDIUM PHONE        line 6    col 15   ***78 (phone number)
HIGH   CREDIT_CARD  line 7    col 15   **** **** **** 1111 (credit card number with a valid Luhn checksum)
LOW    PRIVATE_IP   line 8    col 19   10.12.***.*** (private/loopback IPv4 address)
HIGH   API_KEY      line 9    col 10   sk-p***45 (openai-style sk- key)
HIGH   API_KEY      line 10   col 13   ghp_***yz (GitHub ghp_ token)
HIGH   API_KEY      line 11   col 17   AKIA***LE (AWS access key id)
HIGH   JWT          line 12   col 16   eyJh***8U (JSON Web Token)
HIGH   SECRET       line 13   col 22   hunt***et (secret assignment)
summary: 10 finding(s): 6 high, 3 medium, 1 low
[exit code: 0]
```

### 0:30-1:05 -- Gate the log pipeline on high-severity leaks

`--fail-on high` returns exit code 1.

```console
$ python -m pii_redactor scan examples/poisoned_output.txt --fail-on high
model-pii-redactor 0.1.0  scan  examples/poisoned_output.txt  (13 lines, 507 chars)
MEDIUM EMAIL        line 4    col 8    j***@acme-corp.example (email address)
MEDIUM PHONE        line 5    col 8    ***32 (phone number)
MEDIUM PHONE        line 6    col 15   ***78 (phone number)
HIGH   CREDIT_CARD  line 7    col 15   **** **** **** 1111 (credit card number with a valid Luhn checksum)
LOW    PRIVATE_IP   line 8    col 19   10.12.***.*** (private/loopback IPv4 address)
HIGH   API_KEY      line 9    col 10   sk-p***45 (openai-style sk- key)
HIGH   API_KEY      line 10   col 13   ghp_***yz (GitHub ghp_ token)
HIGH   API_KEY      line 11   col 17   AKIA***LE (AWS access key id)
HIGH   JWT          line 12   col 16   eyJh***8U (JSON Web Token)
HIGH   SECRET       line 13   col 22   hunt***et (secret assignment)
summary: 10 finding(s): 6 high, 3 medium, 1 low
FAIL: 6 finding(s) at or above severity 'high'
[exit code: 1]
```

### 1:05-1:45 -- Redact with typed placeholders

Then rescan: zero findings at the strictest gate, the surrounding text is preserved.

```console
$ python -m pii_redactor redact examples/poisoned_output.txt -o evidence/raw/redacted_output.txt
wrote evidence/raw/redacted_output.txt (mode=redact, findings=10: 6 high, 3 medium, 1 low)
[exit code: 0]
```

### 1:45-2:15 -- Hash mode for stable correlation

Same value -> same deterministic label; useful for joining logs without storing PII.

```console
$ python -m pii_redactor redact examples/poisoned_output.txt --mode hash --json
{
  "tool": "model-pii-redactor",
  "version": "0.1.0",
  "mode": "hash",
  "summary": {
    "total": 10,
    "counts": {
      "EMAIL": 1,
      "PHONE": 2,
      "CREDIT_CARD": 1,
      "PRIVATE_IP": 1,
      "API_KEY": 3,
      "JWT": 1,
      "SECRET": 1
    },
    "by_severity": {
      "low": 1,
      "medium": 3,
      "high": 6
    },
    "max_severity": "high"
  },
  "clean": false,
  "findings": [
    {
      "kind": "EMAIL",
      "severity": "medium",
      "start": 66,
      "end": 92,
      "length": 26,
      "preview": "j***@acme-corp.example",
      "detail": "email address"
    },
    {
      "kind": "PHONE",
      "severity": "medium",
      "start": 100,
      "end": 115,
      "length": 15,
      "preview": "***32",
      "detail": "phone number"
    },
    {
      "kind": "PHONE",
      "severity": "medium",
      "start": 130,
      "end": 141,
      "length": 11,
      "preview": "***78",
      "detail": "phone number"
    },
    {
      "kind": "CREDIT_CARD",
      "severity": "high",
      "start": 156,
      "end": 175,
      "length": 19,
      "preview": "**** **** **** 1111",
      "detail": "credit card number with a valid Luhn checksum"
    },
    {
      "kind": "PRIVATE_IP",
      "severity": "low",
      "start": 194,
      "end": 205,
      "length": 11,
      "preview": "10.12.***.***",
      "detail": "private/loopback IPv4 address"
    },
    {
      "kind": "API_KEY",
      "severity": "high",
      "start": 225,
      "end": 265,
     
... (truncated; full output in docs/EVIDENCE.md)
[exit code: 0]
```

### 2:15-2:40 -- Tests and honest limits

```console
$ python -m unittest discover -s tests -t .
Ran 40 tests
OK
```

## Ready files for the edit

- `docs/screenshots/terminal_clean.txt`
- `docs/screenshots/terminal_gate.txt`
- `docs/screenshots/terminal_redact.txt`
- `docs/screenshots/terminal_rescan.txt`
- `docs/screenshots/terminal_scan.txt`
- `docs/screenshots/terminal_tests.txt`
- `docs/EVIDENCE.md`
- `examples/poisoned_output.txt`

## OBS/screen-recording notes

- Record a 1920x1080 terminal at 120x32 characters; the commands above fit without wrapping.
- Run every command from the repository root so the relative paths match.
- The JSON runs are for the evidence log only and are not needed on camera.

## Caveats to state on camera

All PII in the examples is synthetic. Detection is pattern-based: unusual formats can be missed and benign strings can be flagged, which is why report mode exists. Luhn is a strong signal, not proof.
