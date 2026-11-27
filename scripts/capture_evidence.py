#!/usr/bin/env python3
"""Regenerate docs/EVIDENCE.md, docs/screenshots/*.txt and evidence/raw/*.

Every command below is executed for real with this Python interpreter; the
captured stdout/stderr and exit codes are what the evidence file quotes.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

META = {'package': 'pii_redactor', 'title': 'pii-redactor', 'repo': 'model-pii-redactor', 'version': '0.1.0', 'examples': ['examples/poisoned_output.txt', 'examples/clean_output.txt'], 'runs': [{'label': 'scan model output with PII', 'args': ['scan', 'examples/poisoned_output.txt'], 'terminal': 'scan'}, {'label': 'machine-readable scan', 'args': ['scan', 'examples/poisoned_output.txt', '--json'], 'terminal': None}, {'label': 'CI gate at high severity', 'args': ['scan', 'examples/poisoned_output.txt', '--fail-on', 'high'], 'terminal': 'gate', 'expect_exit': 1}, {'label': 'redact the output', 'args': ['redact', 'examples/poisoned_output.txt', '-o', 'evidence/raw/redacted_output.txt'], 'terminal': 'redact'}, {'label': 'rescan the redacted output with the strictest gate', 'args': ['scan', 'evidence/raw/redacted_output.txt', '--fail-on', 'low'], 'terminal': 'rescan', 'expect_exit': 0}, {'label': 'hash mode is deterministic', 'args': ['redact', 'examples/poisoned_output.txt', '--mode', 'hash', '--json'], 'terminal': None}, {'label': 'clean output passes', 'args': ['scan', 'examples/clean_output.txt', '--fail-on', 'low'], 'terminal': 'clean', 'expect_exit': 0}, {'label': 'report mode leaves the text unchanged', 'args': ['report', 'examples/poisoned_output.txt', '--json'], 'terminal': None}], 'extra_files': [], 'honesty': '`model-pii-redactor` is a defensive redaction tool. It does not disclose a new vulnerability, does not claim a new CVE and does not make an output pipeline compliant with any privacy regulation. The PII in the examples is synthetic. Pattern matching can miss formatted or unexpected identifiers and can flag benign strings; the report mode exists so an operator can review before redaction.', 'limits': '- Detection is regex + checksum based: unusual formats, non-Latin identifiers and context-dependent PII\n  can be missed; names and addresses are out of scope.\n- A Luhn-valid number is only a candidate card number, not proof of a live card.\n- The report JSON deliberately masks values; if you need the raw span, use the library API in-process and\n  handle the result as personal data.\n- Hash mode is a deterministic pseudonym, not anonymisation: an attacker who knows the salt can brute\n  force common values. Keep the salt secret and rotate it per deployment if needed.\n- Redaction happens where you call it. Model output stored elsewhere (vendor logs, PI traces) is not\n  covered; apply redaction at ingestion and egress.', 'video': {'intro': 'Every command and output below was captured from the real CLI on the build machine.', 'beats': [{'time': '0:00-0:30', 'beat': 'Hook: the model output contains a card, keys and a JWT', 'run': 0, 'note': 'Point at the masked previews: the human-readable log never prints the raw values.'}, {'time': '0:30-1:05', 'beat': 'Gate the log pipeline on high-severity leaks', 'run': 2, 'note': '`--fail-on high` returns exit code 1.'}, {'time': '1:05-1:45', 'beat': 'Redact with typed placeholders', 'run': 3, 'note': 'Then rescan: zero findings at the strictest gate, the surrounding text is preserved.'}, {'time': '1:45-2:15', 'beat': 'Hash mode for stable correlation', 'run': 5, 'note': 'Same value -> same deterministic label; useful for joining logs without storing PII.'}, {'time': '2:15-2:40', 'beat': 'Tests and honest limits', 'tests': True, 'note': '40 tests, including Luhn and false-positive cases; state that pattern matching is heuristic.'}], 'extra_files': ['docs/EVIDENCE.md', 'examples/poisoned_output.txt'], 'caveats': 'All PII in the examples is synthetic. Detection is pattern-based: unusual formats can be missed and benign strings can be flagged, which is why report mode exists. Luhn is a strong signal, not proof.'}}

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_step(spec, stdin_text=None):
    if spec.get("script"):
        cmd = [sys.executable, spec["script"]]
        command = "python " + spec["script"]
    else:
        cmd = [sys.executable, "-m", META["package"]] + list(spec["args"])
        command = "python -m " + META["package"] + " " + " ".join(spec["args"])
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        input=stdin_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=240,
    )
    return proc, command


def terminal_text(command: str, proc) -> str:
    text = "$ " + command + "\n" + proc.stdout.rstrip() + "\n"
    if proc.stderr.strip():
        text += "[stderr]\n" + proc.stderr.rstrip() + "\n"
    text += "[exit code: %d]\n" % proc.returncode
    return text


def main() -> int:
    raw = ROOT / "evidence" / "raw"
    shots = ROOT / "docs" / "screenshots"
    raw.mkdir(parents=True, exist_ok=True)
    shots.mkdir(parents=True, exist_ok=True)

    records = []
    by_index = {}
    for index, spec in enumerate(META["runs"]):
        stdin_text = None
        if spec.get("stdin_from") is not None:
            stdin_text = by_index[spec["stdin_from"]]["stdout"]
        proc, command = run_step(spec, stdin_text)
        record = {
            "index": index,
            "label": spec["label"],
            "command": command,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "expect_exit": spec.get("expect_exit"),
        }
        records.append(record)
        by_index[index] = record
        if spec.get("terminal"):
            (shots / ("terminal_%s.txt" % spec["terminal"])).write_text(
                terminal_text(command, proc), encoding="utf-8", newline="\n"
            )
        print("run %d/%d: %s -> exit %d" % (index + 1, len(META["runs"]), spec["label"], proc.returncode))

    tests = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    test_output = tests.stdout + tests.stderr
    (raw / "unit_test_output.txt").write_text(test_output, encoding="utf-8", newline="\n")
    match = re.search(r"Ran (\d+) tests?", test_output)
    test_count = int(match.group(1)) if match else 0
    tests_ok = tests.returncode == 0 and "OK" in test_output
    (shots / "terminal_tests.txt").write_text(
        terminal_text("python -m unittest discover -s tests -t .", tests), encoding="utf-8", newline="\n"
    )

    example_hashes = []
    for rel in META["examples"]:
        path = ROOT / rel
        example_hashes.append({"path": rel, "bytes": path.stat().st_size, "sha256": sha256(path)})
    extra_hashes = []
    for rel in META.get("extra_files", []):
        path = ROOT / rel
        if path.is_file():
            extra_hashes.append({"path": rel, "bytes": path.stat().st_size, "sha256": sha256(path)})

    captured_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    env = {
        "os": platform.platform(),
        "python": platform.python_version(),
        "package_version": META["version"],
        "captured_at_utc": captured_at,
        "command_count": len(records),
        "test_count": test_count,
        "tests_ok": tests_ok,
    }
    (raw / "cli_runs.json").write_text(
        json.dumps({"environment": env, "runs": records, "examples": example_hashes, "extra_files": extra_hashes}, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    lines = []
    lines.append("# Evidence log: %s" % META["title"])
    lines.append("")
    lines.append("This file is generated by `python scripts/capture_evidence.py` and only contains real captured output: every command below was executed on the build machine, and the quoted text is the verbatim stdout/stderr, exit code and file hash. Nothing here is estimated. Re-run the script to reproduce it.")
    lines.append("")
    lines.append("## Scope and honesty statement")
    lines.append("")
    lines.append(META["honesty"])
    lines.append("")
    lines.append("## Environment")
    lines.append("")
    lines.append("| item | value |")
    lines.append("| --- | --- |")
    lines.append("| operating system | %s |" % env["os"])
    lines.append("| Python | %s |" % env["python"])
    lines.append("| package version | %s |" % env["package_version"])
    lines.append("| capture time (UTC) | %s |" % env["captured_at_utc"])
    lines.append("")
    lines.append("## Example inputs")
    lines.append("")
    lines.append("| file | bytes | sha256 |")
    lines.append("| --- | --- | --- |")
    for item in example_hashes:
        lines.append("| `%s` | %d | `%s` |" % (item["path"], item["bytes"], item["sha256"]))
    if extra_hashes:
        lines.append("")
        lines.append("Generated artifacts:")
        lines.append("")
        lines.append("| file | bytes | sha256 |")
        lines.append("| --- | --- | --- |")
        for item in extra_hashes:
            lines.append("| `%s` | %d | `%s` |" % (item["path"], item["bytes"], item["sha256"]))
    lines.append("")
    lines.append("## CLI runs (real output)")
    lines.append("")
    for record in records:
        lines.append("### %d. %s" % (record["index"] + 1, record["label"]))
        lines.append("")
        lines.append("```console")
        lines.append(record["command"])
        lines.append("```")
        lines.append("")
        output = record["stdout"].rstrip()
        if record["stderr"].strip():
            output += ("\n[stderr]\n" + record["stderr"].rstrip())
        if len(output) > 4000:
            output = output[:4000] + "\n... (truncated in this summary; full output is in evidence/raw/cli_runs.json)"
        lines.append("```text")
        lines.append(output if output else "(no output)")
        lines.append("```")
        expected = record.get("expect_exit")
        if expected is None:
            lines.append("")
            lines.append("exit code: **%d**" % record["exit_code"])
        elif expected == record["exit_code"]:
            lines.append("")
            lines.append("exit code: **%d** (expected %d, gate behaves as documented)" % (record["exit_code"], expected))
        else:
            lines.append("")
            lines.append("exit code: **%d** (EXPECTED %d -- see warnings below)" % (record["exit_code"], expected))
        lines.append("")
    lines.append("## Test suite")
    lines.append("")
    lines.append("- command: `python -m unittest discover -s tests -t .`")
    lines.append("- tests run: **%d**" % test_count)
    lines.append("- result: **%s** (exit code %d)" % ("OK" if tests_ok else "FAILED", tests.returncode))
    lines.append("- full output: `evidence/raw/unit_test_output.txt`")
    lines.append("")
    lines.append("## Reproduce")
    lines.append("")
    lines.append("```bash")
    lines.append("python scripts/check_core_deps.py")
    for record in records:
        lines.append(record["command"])
    lines.append("python -m unittest discover -s tests -t .")
    lines.append("python scripts/capture_evidence.py")
    lines.append("```")
    lines.append("")
    lines.append("## Console captures")
    lines.append("")
    for path in sorted(shots.glob("terminal_*.txt")):
        lines.append("- `docs/screenshots/%s`" % path.name)
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    lines.append(META["limits"])
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Generated by `scripts/capture_evidence.py` at %s. Raw machine-readable run log: `evidence/raw/cli_runs.json`." % captured_at)
    lines.append("")
    (ROOT / "docs" / "EVIDENCE.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")

    mismatches = [r for r in records if r.get("expect_exit") is not None and r["exit_code"] != r["expect_exit"]]
    for record in mismatches:
        print("WARNING: run %r exited %d, expected %d" % (record["label"], record["exit_code"], record["expect_exit"]))
    write_video_assets(records, test_count, tests_ok, shots)
    print("wrote docs/EVIDENCE.md, docs/video_assets.md, evidence/raw/cli_runs.json, docs/screenshots/ (%d tests, %s)" % (test_count, "OK" if tests_ok else "FAILED"))
    return 0 if tests_ok and not mismatches else 1


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:140]
    return "(no output)"


def write_video_assets(records, test_count, tests_ok, shots) -> None:
    video = META.get("video")
    if not video:
        return
    lines = ["# Video assets: %s" % META["title"], "", video["intro"], ""]
    lines.append("## Beat sheet (outputs are captured from real runs)")
    lines.append("")
    lines.append("| time | beat | command | captured output (first line) |")
    lines.append("| --- | --- | --- | --- |")
    for beat in video["beats"]:
        if beat.get("tests"):
            command = "python -m unittest discover -s tests -t ."
            output_line = "Ran %d tests in ... OK" % test_count
        elif beat.get("doc"):
            command = "see " + beat["doc"]
            output_line = beat.get("expected", "")
        else:
            record = records[beat["run"]]
            command = "`" + record["command"] + "`"
            output_line = _first_line(record["stdout"] + record["stderr"]).replace("|", "\\|")
        lines.append("| %s | %s | %s | %s |" % (beat["time"], beat["beat"], command, output_line))
    lines.append("")
    lines.append("## Real command transcripts for the recording")
    lines.append("")
    for beat in video["beats"]:
        if beat.get("tests"):
            lines.append("### %s -- %s" % (beat["time"], beat["beat"]))
            lines.append("")
            lines.append("```console")
            lines.append("$ python -m unittest discover -s tests -t .")
            lines.append("Ran %d tests" % test_count)
            lines.append("OK" if tests_ok else "FAILED")
            lines.append("```")
            lines.append("")
            continue
        if beat.get("doc"):
            lines.append("### %s -- %s" % (beat["time"], beat["beat"]))
            lines.append("")
            lines.append(beat.get("note", ""))
            lines.append("")
            continue
        record = records[beat["run"]]
        lines.append("### %s -- %s" % (beat["time"], beat["beat"]))
        lines.append("")
        lines.append(beat.get("note", ""))
        lines.append("")
        lines.append("```console")
        lines.append("$ " + record["command"])
        output = (record["stdout"] + record["stderr"]).rstrip()
        if len(output) > 1500:
            output = output[:1500] + "\n... (truncated; full output in docs/EVIDENCE.md)"
        lines.append(output if output else "(no output)")
        lines.append("[exit code: %d]" % record["exit_code"])
        lines.append("```")
        lines.append("")
    lines.append("## Ready files for the edit")
    lines.append("")
    for path in sorted(shots.glob("terminal_*.txt")):
        lines.append("- `docs/screenshots/%s`" % path.name)
    for item in video.get("extra_files", []):
        lines.append("- `%s`" % item)
    lines.append("")
    lines.append("## OBS/screen-recording notes")
    lines.append("")
    lines.append("- Record a 1920x1080 terminal at 120x32 characters; the commands above fit without wrapping.")
    lines.append("- Run every command from the repository root so the relative paths match.")
    lines.append("- The JSON runs are for the evidence log only and are not needed on camera.")
    lines.append("")
    lines.append("## Caveats to state on camera")
    lines.append("")
    lines.append(video["caveats"])
    lines.append("")
    (ROOT / "docs" / "video_assets.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    raise SystemExit(main())
