"""CLI behaviour tests for model-pii-redactor."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

from pii_redactor.cli import main

ROOT = pathlib.Path(__file__).resolve().parent.parent
POISONED = str(ROOT / "examples" / "poisoned_output.txt")
CLEAN = str(ROOT / "examples" / "clean_output.txt")


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_scan_json_has_masked_previews(self):
        code, out, _ = run(["scan", POISONED, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertGreaterEqual(payload["summary"]["total"], 8)
        self.assertIn("preview", payload["findings"][0])
        self.assertNotIn("jane.doe@acme-corp.example", out)

    def test_gate_blocks_pii(self):
        code, _, err = run(["scan", POISONED, "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertIn("FAIL", err)

    def test_clean_passes(self):
        code, _, _ = run(["scan", CLEAN, "--fail-on", "low"])
        self.assertEqual(code, 0)

    def test_redact_output_file_scans_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "redacted.txt"
            code, _, err = run(["redact", POISONED, "-o", str(target)])
            self.assertEqual(code, 0)
            self.assertIn("wrote", err)
            self.assertIn("[REDACTED:EMAIL]", target.read_text(encoding="utf-8"))
            code, _, _ = run(["scan", str(target), "--fail-on", "low"])
            self.assertEqual(code, 0)

    def test_hash_mode_json(self):
        code, out, _ = run(["redact", POISONED, "--mode", "hash", "--salt", "pepper", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertIn("EMAIL:sha256:", payload["text"])
        self.assertNotIn("jane.doe@acme-corp.example", payload["text"])

    def test_redact_json(self):
        code, out, _ = run(["redact", POISONED, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["text"].count("[REDACTED:"), payload["summary"]["total"])

    def test_report_json_leaves_text_unchanged(self):
        code, out, _ = run(["report", POISONED, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["mode"], "report")
        self.assertIn("jane.doe@acme-corp.example", payload["text"])

    def test_missing_file_exits_2(self):
        code, _, err = run(["scan", "does-not-exist.txt"])
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_bad_mode_exits_2(self):
        with self.assertRaises(SystemExit) as context:
            run(["redact", POISONED, "--mode", "bogus"])
        self.assertEqual(context.exception.code, 2)

    def test_stdin_input(self):
        original = sys.stdin
        sys.stdin = io.StringIO("mail jane.doe@acme-corp.example")
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["scan", "-", "--json"])
        finally:
            sys.stdin = original
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["summary"]["counts"]["EMAIL"], 1)
