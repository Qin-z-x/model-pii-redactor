# model-pii-redactor

[![CI](https://github.com/Qin-z-x/model-pii-redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/Qin-z-x/model-pii-redactor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![stdlib-only core](https://img.shields.io/badge/core-stdlib%20only-brightgreen.svg)](scripts/check_core_deps.py)

**Detect and redact PII and secrets in model output** — emails, phone numbers,
Luhn-checked credit cards, private IPs, API keys (`sk-`, `ghp_`, `AKIA`, ...),
JWTs, Bearer tokens and `password = ...` style assignments — before the text is
logged, stored, indexed or shown to someone who should not see it.

```console
$ python -m pii_redactor scan examples/poisoned_output.txt
pii-redactor 0.1.0  scan  examples/poisoned_output.txt  (13 lines, 507 chars)
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
```

The human-readable output prints **masked previews only** — the raw values never
reach the terminal log. Three modes:

```console
$ python -m pii_redactor redact examples/poisoned_output.txt -o redacted.txt
wrote redacted.txt (mode=redact, findings=10: 5 high, 4 medium, 1 low)
$ python -m pii_redactor scan redacted.txt --fail-on low
PASS: no finding at or above severity 'low'
```

* `-o` never writes the original text; the file contains
  `[REDACTED:EMAIL]`-style typed placeholders.
* `--mode hash` replaces values with deterministic salted hashes
  (`EMAIL:sha256:<16 hex>`) so logs can be correlated without storing PII.
* `--mode report` (or the `report` subcommand) changes nothing and is intended
  for review before redaction.

## Detectors

| Kind | Severity | Detection |
| --- | --- | --- |
| `EMAIL` | medium | RFC-ish email with a real TLD |
| `PHONE` | medium | E.164, US `(415) 555-0132`, CN mobile `1[3-9]xxxxxxxxx`, CN landline |
| `CREDIT_CARD` | high | 13–19 digits **and a valid Luhn checksum** |
| `PRIVATE_IP` | low | RFC1918, loopback, link-local, CGNAT |
| `API_KEY` | high | `sk-`, `ghp_`, `github_pat_`, `AKIA`, `AIza`, `xox[baprs]-`, `glpat-` |
| `JWT` | high | `eyJ... . ... . ...` three-segment token |
| `SECRET` | high | Bearer tokens and `api_key/password/secret/token = ...` assignments |

False-positive guards are tested: dates and long order numbers are not phones,
`8.8.8.8` and `172.32.x.x` are not private, a non-Luhn 16-digit number is not a
card, and short `sk-`/`ghp_`/`AKIA` prefixes are not keys.

## Install

```bash
git clone https://github.com/Qin-z-x/model-pii-redactor.git
cd model-pii-redactor
python -m pip install -e .      # optional: installs the pii-redactor CLI
```

No runtime dependencies. Python 3.10+.

## CLI

```text
python -m pii_redactor scan   <file|-> [--json] [--fail-on {low,medium,high}]
python -m pii_redactor redact <file|-> [--mode {report,redact,hash}] [--salt S] [--json] [-o OUT]
python -m pii_redactor report <file|-> [--json]
```

Exit codes: `0` success / gate not reached, `1` `--fail-on` threshold reached,
`2` usage error, missing file or invalid UTF-8.

Library API:

```python
from pii_redactor import scan, redact, summarize

findings = scan(text)                 # list[Finding] with start/end spans
summary = summarize(findings)         # counts by kind and severity
redact(text, "redact")                # dict with .text / .findings / .summary
redact(text, "hash", salt="pepper")   # deterministic pseudonyms
```

## Where to use it

* redact model output before writing it to application logs or APM traces;
* redact prompts before sending them to a third-party evaluator;
* gate a data pipeline with `--fail-on high` when output must not contain
  credentials;
* produce review-friendly `report` output before enabling `redact` (tune the
  rule set against your own false positives first).

## Honest scope and limits

* **Heuristic.** Regex + checksum detection misses unusual formats and
  context-dependent PII (names, addresses) and can flag benign strings. The
  `report` mode exists so a human can review before redaction.
* Luhn is a strong signal, not proof that the number is a live card.
* Hash mode is a deterministic pseudonym, **not anonymisation**: keep the salt
  secret and rotate it per deployment if needed.
* The report JSON deliberately masks previews; if you need raw spans, use the
  library in-process and handle the result as personal data.
* Redaction happens where you call it. Vendor-side logs and prompt traces are
  not covered unless you redact at ingestion and egress.
* This is not legal advice and not a compliance certification; it does not
  disclose a new vulnerability and does not claim a new CVE.

## Tests and CI

```bash
python scripts/check_core_deps.py            # stdlib-only core check
python -m unittest discover -s tests -t .    # 40 tests
python scripts/capture_evidence.py           # regenerate docs/EVIDENCE.md + captures
```

CI (`.github/workflows/ci.yml`) runs on GitHub Actions for Python 3.10 and 3.12:
stdlib-only check, unit tests, a JSON smoke test, redact-then-rescan, the clean
example gate and both expected outcomes of the `--fail-on high` gate.

## Suggested GitHub topics

`security`, `llm`, `pii`, `redaction`, `privacy`, `secrets`, `regex`, `python`,
`cli`, `ai-safety`

## 中文简介

**model-pii-redactor** 在模型输出（以及需要落库/打日志的提示词）中检测并脱敏 PII 与密钥：
邮箱、电话（E.164/美式/中国手机号/固话）、**通过 Luhn 校验**的信用卡号、私有/回环 IP、
常见 API Key（`sk-`、`ghp_`、`github_pat_`、`AKIA`、`AIza`、`xoxb-`、`glpat-`）、JWT、
Bearer Token 以及 `password = ...` 形式的密钥赋值。核心库**仅使用 Python 标准库**，提供
`scan` / `redact` / `report` 三个 CLI 子命令，支持 `--json`、`--fail-on` 门禁，以及
`report`（不改原文）/ `redact`（类型占位符）/ `hash`（加盐确定性哈希）三种模式。
人类可读输出只显示**脱敏预览**，原始 PII 不会进入终端日志。误报控制有专门测试：
日期和长订单号不会被当电话、`8.8.8.8`/`172.32.x.x` 不会被当私有 IP、非 Luhn 的
16 位数字不会被当卡号、过短的 `sk-`/`ghp_`/`AKIA` 前缀不会命中。示例中的 PII 全部为
合成数据；本项目是防御性工具，不声称发现新漏洞或新 CVE。

## 视频演示

B站：https://www.bilibili.com/video/BV1fE1pztE53（65 秒）

视频使用本仓库自带的合成/无害样例与真实命令输出；本项目是启发式检测工具，边界见上文说明。

## License

MIT -- see [LICENSE](LICENSE). Pattern ideas are public prior art from OWASP
privacy guidance, secret-scanning tools (gitleaks/trufflehog) and the Luhn
checksum specification.

## 系列：LLM 安全防护工具

本项目是「LLM 安全 7 件套」之一：[llm-markdown-xss-guard](https://github.com/Qin-Z-x/llm-markdown-xss-guard)（模型输出 XSS 净化）、[tool-call-arg-guard](https://github.com/Qin-Z-x/tool-call-arg-guard)（工具调用参数注入校验）、[rag-poison-guard](https://github.com/Qin-Z-x/rag-poison-guard)（RAG 语料投毒扫描）、[llm-sql-injection-guard](https://github.com/Qin-Z-x/llm-sql-injection-guard)（模型生成 SQL 注入 lint）、[ai-agent-permission-guard](https://github.com/Qin-Z-x/ai-agent-permission-guard)（Agent 工具权限审计）、[llm-file-path-guard](https://github.com/Qin-Z-x/llm-file-path-guard)（生成代码路径穿越扫描）

- GitHub 主页（全部 14 个项目）：https://github.com/Qin-Z-x
- B站演示合集（7 工具 4 分钟）：https://www.bilibili.com/video/BV1jH1pz4ED7

- 7 件套在线索引：https://github.com/Qin-Z-x/llm-security-toolkit （页面：https://qin-z-x.github.io/llm-security-toolkit/）
