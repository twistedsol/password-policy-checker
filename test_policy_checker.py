import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

import policy_checker as pc

GOOD = {
    "min_length": 12, "max_length": 128, "check_breached_passwords": True,
    "mfa_required": True, "max_failed_attempts": 5,
    "hash_algorithm": "argon2id", "salted": True, "reset_token_minutes": 30,
}


def rules(policy):
    return {f["rule"] for f in pc.check_policy(policy)}


def with_(**changes):
    policy = dict(GOOD)
    policy.update(changes)
    return policy


class LengthTests(unittest.TestCase):
    def test_good_policy_is_clean(self):
        self.assertEqual(pc.check_policy(GOOD), [])

    def test_missing_min_length(self):
        policy = dict(GOOD)
        del policy["min_length"]
        self.assertIn("min-length-missing", rules(policy))

    def test_short_min_length_is_high(self):
        found = [f for f in pc.check_policy(with_(min_length=6))
                 if f["rule"] == "min-length-short"]
        self.assertEqual(found[0]["severity"], "high")

    def test_seven_is_short_eight_is_low(self):
        self.assertIn("min-length-short", rules(with_(min_length=7)))
        self.assertIn("min-length-low", rules(with_(min_length=8)))
        self.assertNotIn("min-length-short", rules(with_(min_length=8)))

    def test_eleven_is_low_twelve_is_fine(self):
        self.assertIn("min-length-low", rules(with_(min_length=11)))
        self.assertNotIn("min-length-low", rules(with_(min_length=12)))

    def test_max_length_blocks_passphrases(self):
        self.assertIn("max-length-low", rules(with_(max_length=16)))
        self.assertNotIn("max-length-low", rules(with_(max_length=64)))

    def test_text_instead_of_number_counts_as_missing(self):
        self.assertIn("min-length-missing", rules(with_(min_length="12")))

    def test_boolean_is_not_a_number(self):
        self.assertIn("min-length-missing", rules(with_(min_length=True)))


class RuleTests(unittest.TestCase):
    def test_complexity_needs_three_rules(self):
        two = with_(require_uppercase=True, require_digit=True)
        three = with_(require_uppercase=True, require_digit=True, require_symbol=True)
        self.assertNotIn("complexity-forced", rules(two))
        self.assertIn("complexity-forced", rules(three))

    def test_forced_expiry(self):
        self.assertIn("forced-expiry", rules(with_(max_age_days=90)))
        self.assertNotIn("forced-expiry", rules(with_(max_age_days=0)))
        self.assertNotIn("forced-expiry", rules(with_(max_age_days=365)))

    def test_breached_check_missing_or_false(self):
        policy = dict(GOOD)
        del policy["check_breached_passwords"]
        self.assertIn("no-breached-check", rules(policy))
        self.assertIn("no-breached-check", rules(with_(check_breached_passwords=False)))

    def test_no_mfa_is_high(self):
        found = [f for f in pc.check_policy(with_(mfa_required=False))
                 if f["rule"] == "no-mfa"]
        self.assertEqual(found[0]["severity"], "high")

    def test_lockout(self):
        self.assertIn("no-lockout", rules(with_(max_failed_attempts=0)))
        self.assertIn("no-lockout", rules(with_(max_failed_attempts=None)))
        self.assertIn("lockout-weak", rules(with_(max_failed_attempts=50)))
        self.assertNotIn("lockout-weak", rules(with_(max_failed_attempts=10)))

    def test_hashes(self):
        for bad in ("md5", "SHA1", " plaintext "):
            self.assertIn("hash-weak", rules(with_(hash_algorithm=bad)), bad)
        for good in ("bcrypt", "Argon2id", "scrypt", "pbkdf2"):
            self.assertNotIn("hash-weak", rules(with_(hash_algorithm=good)), good)
        self.assertIn("hash-unknown", rules(with_(hash_algorithm="homemade")))

    def test_hash_missing(self):
        policy = dict(GOOD)
        del policy["hash_algorithm"]
        self.assertIn("hash-missing", rules(policy))

    def test_unsalted_only_when_explicitly_false(self):
        self.assertIn("unsalted", rules(with_(salted=False)))
        policy = dict(GOOD)
        del policy["salted"]
        self.assertNotIn("unsalted", rules(policy))

    def test_reset_and_recovery(self):
        self.assertIn("reset-token-long", rules(with_(reset_token_minutes=1440)))
        self.assertNotIn("reset-token-long", rules(with_(reset_token_minutes=60)))
        self.assertIn("security-questions", rules(with_(security_questions=True)))

    def test_paste(self):
        self.assertIn("paste-blocked", rules(with_(allow_paste=False)))
        self.assertNotIn("paste-blocked", rules(with_(allow_paste=True)))


class OutputTests(unittest.TestCase):
    def test_sorted_high_first(self):
        findings = pc.check_policy({})
        order = [pc.SEVERITIES[f["severity"]] for f in findings]
        self.assertEqual(order, sorted(order, reverse=True))

    def test_filter_findings(self):
        findings = pc.check_policy({})
        high = pc.filter_findings(findings, "high")
        self.assertTrue(high)
        self.assertTrue(all(f["severity"] == "high" for f in high))

    def test_text_and_json(self):
        results = [("p.json", pc.check_policy(with_(mfa_required=False)))]
        self.assertIn("no-mfa", pc.format_text(results))
        data = json.loads(pc.format_json(results))
        self.assertEqual(data[0]["policy"], "p.json")
        self.assertEqual(data[0]["findings"][0]["rule"], "no-mfa")

    def test_clean_text(self):
        self.assertIn("No findings", pc.format_text([("ok.json", [])]))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name, content):
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content if isinstance(content, str) else json.dumps(content))
        return path

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = pc.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_clean_exit_0(self):
        code, out, _ = self.run_cli(self.write("a.json", GOOD))
        self.assertEqual(code, 0)
        self.assertIn("No findings", out)

    def test_high_finding_exit_1(self):
        code, _, _ = self.run_cli(self.write("a.json", with_(mfa_required=False)))
        self.assertEqual(code, 1)

    def test_fail_on_levels(self):
        path = self.write("a.json", with_(max_age_days=90))
        self.assertEqual(self.run_cli(path)[0], 0)
        self.assertEqual(self.run_cli(path, "--fail-on", "low")[0], 1)

    def test_min_severity_hides_low(self):
        path = self.write("a.json", with_(max_age_days=90))
        _, out, _ = self.run_cli(path, "--min-severity", "medium")
        self.assertNotIn("forced-expiry", out)

    def test_json_format(self):
        path = self.write("a.json", with_(mfa_required=False))
        _, out, _ = self.run_cli(path, "--format", "json")
        self.assertEqual(json.loads(out)[0]["findings"][0]["rule"], "no-mfa")

    def test_missing_file_exit_2(self):
        code, _, err = self.run_cli(os.path.join(self.dir.name, "nope.json"))
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_bad_json_exit_2(self):
        code, _, err = self.run_cli(self.write("bad.json", "{oops"))
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", err)

    def test_list_instead_of_object_exit_2(self):
        code, _, err = self.run_cli(self.write("list.json", "[1, 2]"))
        self.assertEqual(code, 2)
        self.assertIn("JSON object", err)

    def test_several_files(self):
        a = self.write("a.json", GOOD)
        b = self.write("b.json", with_(mfa_required=False))
        code, out, _ = self.run_cli(a, b)
        self.assertEqual(code, 1)
        self.assertEqual(out.count("finding(s)"), 2)


class SampleFileTests(unittest.TestCase):
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_policies")

    def count(self, name):
        policy = pc.load_policy(os.path.join(self.base, name))
        return pc.check_policy(policy)

    def test_weak_legacy(self):
        findings = self.count("01_weak_legacy.json")
        self.assertEqual(len(findings), 12)
        self.assertEqual(sum(f["severity"] == "high" for f in findings), 5)

    def test_average_company(self):
        self.assertEqual(len(self.count("02_average_company.json")), 3)

    def test_modern(self):
        self.assertEqual(self.count("03_modern.json"), [])


if __name__ == "__main__":
    unittest.main()
