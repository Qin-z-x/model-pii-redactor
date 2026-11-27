"""Unit tests for the pii_redactor core."""

from __future__ import annotations

import unittest

from pii_redactor import detect, luhn_valid, mask_value, redact, scan, summarize


def kinds(text):
    return [finding.kind for finding in scan(text)]


class DetectorTests(unittest.TestCase):
    def test_email_is_detected(self):
        findings = scan("Contact jane.doe@acme-corp.example for details.")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "EMAIL")
        self.assertEqual(findings[0].severity, "medium")

    def test_email_false_positive_requires_tld(self):
        self.assertEqual(scan("user@localhost and a@b"), [])

    def test_us_phone_is_detected(self):
        self.assertEqual(kinds("Call +1 415 555 0132 today."), ["PHONE"])

    def test_e164_phone_is_detected(self):
        self.assertEqual(kinds("Reach me at +14155550132."), ["PHONE"])

    def test_cn_mobile_is_detected(self):
        self.assertEqual(kinds("Mobile: 13812345678"), ["PHONE"])

    def test_date_is_not_a_phone(self):
        self.assertEqual(scan("Deployed on 2026-11-27 at 14:05."), [])

    def test_long_order_number_is_not_a_phone(self):
        self.assertEqual(scan("Order 1234567890123 shipped."), [])

    def test_luhn_valid_card_is_high(self):
        findings = scan("Card: 4111 1111 1111 1111")
        self.assertEqual([finding.kind for finding in findings], ["CREDIT_CARD"])
        self.assertEqual(findings[0].severity, "high")

    def test_invalid_luhn_is_not_a_card(self):
        self.assertEqual(scan("Card: 4111 1111 1111 1112"), [])

    def test_luhn_helper_rejects_short_numbers(self):
        self.assertFalse(luhn_valid("411111111111"))

    def test_private_ip_is_low(self):
        findings = scan("Staging endpoint: 10.12.34.56")
        self.assertEqual([finding.kind for finding in findings], ["PRIVATE_IP"])
        self.assertEqual(findings[0].severity, "low")

    def test_public_ip_is_not_flagged(self):
        self.assertEqual(scan("Resolver: 8.8.8.8"), [])

    def test_public_range_172_32_is_not_private(self):
        self.assertEqual(scan("Host 172.32.1.1"), [])

    def test_openai_key_is_high(self):
        findings = scan("key=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345")
        self.assertIn("API_KEY", [finding.kind for finding in findings])
        self.assertTrue(all(finding.severity == "high" for finding in findings))

    def test_github_and_aws_keys_are_detected(self):
        text = "ghp_0123456789abcdefghijklmnopqrstuvwxyz and AKIAIOSFODNN7EXAMPLE"
        self.assertEqual(kinds(text), ["API_KEY", "API_KEY"])

    def test_short_fake_prefixes_are_not_keys(self):
        self.assertEqual(scan("sk-abc ghp_123 AKIA123"), [])

    def test_jwt_is_detected(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        self.assertEqual(kinds(token), ["JWT"])

    def test_secret_assignment_is_detected(self):
        self.assertEqual(kinds('password = "hunter2-super-secret"'), ["SECRET"])

    def test_bearer_token_is_one_finding(self):
        token = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        findings = scan(token)
        self.assertEqual(len(findings), 1)
        self.assertEqual([finding.severity for finding in findings], ["high"])


class MaskingTests(unittest.TestCase):
    def test_email_preview_masks_local_part(self):
        preview = mask_value("EMAIL", "jane.doe@acme-corp.example")
        self.assertEqual(preview, "j***@acme-corp.example")
        self.assertNotIn("jane.doe", preview)

    def test_card_preview_keeps_last_four(self):
        self.assertEqual(mask_value("CREDIT_CARD", "4111 1111 1111 1111"), "**** **** **** 1111")

    def test_report_preview_does_not_contain_raw_value(self):
        result = redact("Mail jane.doe@acme-corp.example now", "report")
        self.assertNotIn("jane.doe@acme-corp.example", str(result["findings"]))
        self.assertEqual(result["text"], "Mail jane.doe@acme-corp.example now")


class RedactionTests(unittest.TestCase):
    TEXT = "Mail jane.doe@acme-corp.example, card 4111 1111 1111 1111, key sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345."

    def test_redact_mode_replaces_values_and_rescans_clean(self):
        result = redact(self.TEXT, "redact")
        self.assertIn("[REDACTED:EMAIL]", result["text"])
        self.assertIn("[REDACTED:CREDIT_CARD]", result["text"])
        self.assertNotIn("jane.doe@acme-corp.example", result["text"])
        self.assertEqual(scan(result["text"]), [])

    def test_hash_mode_is_deterministic_and_salted(self):
        first = redact(self.TEXT, "hash", salt="pepper")
        second = redact(self.TEXT, "hash", salt="pepper")
        other = redact(self.TEXT, "hash", salt="different")
        self.assertEqual(first["text"], second["text"])
        self.assertNotEqual(first["text"], other["text"])
        self.assertIn("EMAIL:sha256:", first["text"])
        self.assertEqual(scan(first["text"]), [])

    def test_report_mode_returns_original_text(self):
        result = redact(self.TEXT, "report")
        self.assertEqual(result["text"], self.TEXT)
        self.assertFalse(result["clean"])

    def test_counts_and_summary(self):
        findings = scan(self.TEXT)
        summary = summarize(findings)
        self.assertEqual(summary["counts"]["EMAIL"], 1)
        self.assertEqual(summary["counts"]["CREDIT_CARD"], 1)
        self.assertGreaterEqual(summary["by_severity"]["high"], 2)
        self.assertEqual(summary["max_severity"], "high")

    def test_overlaps_are_resolved(self):
        findings = detect("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        resolved = scan("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        self.assertLessEqual(len(resolved), len(findings))
        for earlier, later in zip(resolved, resolved[1:]):
            self.assertLessEqual(earlier.end, later.start)

    def test_bad_mode_raises(self):
        with self.assertRaises(ValueError):
            redact("hello", "bogus")


class CleanExampleTests(unittest.TestCase):
    def test_clean_example_has_no_findings(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        text = (root / "examples" / "clean_output.txt").read_text(encoding="utf-8")
        self.assertEqual(scan(text), [])

    def test_poisoned_example_has_five_high_findings(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        text = (root / "examples" / "poisoned_output.txt").read_text(encoding="utf-8")
        summary = summarize(scan(text))
        self.assertGreaterEqual(summary["by_severity"]["high"], 5)
        self.assertGreaterEqual(summary["total"], 8)
