"""Command line interface for model-pii-redactor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import SEVERITY_RANK, VERSION, redact, scan, summarize

TOOL = "model-pii-redactor"


def _read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _print_json(payload) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=True))


def _line_col(text: str, offset: int) -> tuple:
    line = text.count("\n", 0, offset) + 1
    column = offset - (text.rfind("\n", 0, offset) + 1) + 1
    return line, column


def _print_findings(path: str, text: str, findings) -> None:
    summary = summarize(findings)
    print("%s %s  scan  %s  (%d lines, %d chars)" % (TOOL, VERSION, path, len(text.splitlines()), len(text)))
    for finding in findings:
        payload = finding.to_dict()
        preview = payload["preview"]
        line, column = _line_col(text, finding.start)
        print(
            "%-6s %-12s line %-4d col %-4d %s (%s)"
            % (finding.severity.upper(), finding.kind, line, column, preview, payload["detail"])
        )
    print(
        "summary: %d finding(s): %d high, %d medium, %d low"
        % (summary["total"], summary["by_severity"]["high"], summary["by_severity"]["medium"], summary["by_severity"]["low"])
    )


def _gate(findings, fail_on: str) -> int:
    if not fail_on:
        return 0
    threshold = SEVERITY_RANK[fail_on]
    count = sum(1 for finding in findings if SEVERITY_RANK[finding.severity] >= threshold)
    if count:
        print("FAIL: %d finding(s) at or above severity %r" % (count, fail_on), file=sys.stderr)
        return 1
    print("PASS: no finding at or above severity %r" % fail_on)
    return 0


def _cmd_scan(args) -> int:
    text = _read_text(args.path)
    findings = scan(text)
    if args.json:
        payload = redact(text, "report")
        payload.pop("text", None)
        payload["path"] = args.path
        _print_json(payload)
    else:
        _print_findings(args.path, text, findings)
    return _gate(findings, args.fail_on)


def _cmd_redact(args) -> int:
    text = _read_text(args.path)
    result = redact(text, args.mode, salt=args.salt)
    if args.json:
        result["path"] = args.path
        _print_json(result)
        return 0
    output = result["text"]
    if args.output and args.output != "-":
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output if output.endswith("\n") else output + "\n", encoding="utf-8", newline="\n")
        summary = result["summary"]
        print(
            "wrote %s (mode=%s, findings=%d: %d high, %d medium, %d low)"
            % (args.output, args.mode, summary["total"], summary["by_severity"]["high"], summary["by_severity"]["medium"], summary["by_severity"]["low"]),
            file=sys.stderr,
        )
    else:
        sys.stdout.write(output if output.endswith("\n") else output + "\n")
    return 0


def _cmd_report(args) -> int:
    text = _read_text(args.path)
    result = redact(text, "report")
    result["path"] = args.path
    if args.json:
        _print_json(result)
        return 0
    _print_findings(args.path, text, scan(text))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL,
        description="Detect and redact PII and secrets in LLM output (stdlib-only).",
    )
    parser.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="detect PII/secrets and print masked findings")
    scan_parser.add_argument("path", help="text file, or - for stdin")
    scan_parser.add_argument("--json", action="store_true", help="emit JSON (masked previews)")
    scan_parser.add_argument("--fail-on", choices=["low", "medium", "high"], help="exit 1 when a finding at or above this severity exists")
    scan_parser.set_defaults(func=_cmd_scan)

    redact_parser = subparsers.add_parser("redact", help="apply report/redact/hash mode")
    redact_parser.add_argument("path", help="text file, or - for stdin")
    redact_parser.add_argument("--mode", choices=["report", "redact", "hash"], default="redact")
    redact_parser.add_argument("--salt", default="", help="salt for hash mode (keep it secret)")
    redact_parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    redact_parser.add_argument("-o", "--output", help="write the processed text to this file")
    redact_parser.set_defaults(func=_cmd_redact)

    report_parser = subparsers.add_parser("report", help="summary report; the text is not modified")
    report_parser.add_argument("path", help="text file, or - for stdin")
    report_parser.add_argument("--json", action="store_true", help="emit JSON")
    report_parser.set_defaults(func=_cmd_report)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print("error: file not found: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except UnicodeDecodeError as exc:
        print("error: input is not valid UTF-8: %s" % exc, file=sys.stderr)
        return 2
