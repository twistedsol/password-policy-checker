#!/usr/bin/env python3
"""Password policy checker.

Reads password POLICY files (JSON) and flags settings that are weak or
out of date. It never sees real passwords, only the rules a system uses.

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = bad input.
"""
import argparse
import json
import sys

SEVERITIES = {"low": 1, "medium": 2, "high": 3}

STRONG_HASHES = {"argon2id", "argon2i", "argon2d", "bcrypt", "scrypt", "pbkdf2"}
BROKEN_HASHES = {"plaintext", "none", "md5", "sha1", "sha256", "sha512", "ntlm", "lm"}


class PolicyError(Exception):
    """Raised when a policy file cannot be used."""


def load_policy(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        raise PolicyError("file not found: %s" % path)
    except json.JSONDecodeError as exc:
        raise PolicyError("not valid JSON: %s (%s)" % (path, exc.msg))
    except OSError as exc:
        raise PolicyError("cannot read %s: %s" % (path, exc.strerror))
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object: %s" % path)
    return data


def _finding(rule, severity, message, fix):
    return {"rule": rule, "severity": severity, "message": message, "fix": fix}


def _num(policy, key):
    """Return a number for key, or None when missing or not a number."""
    value = policy.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def check_policy(policy):
    findings = []

    # Length
    min_len = _num(policy, "min_length")
    if min_len is None:
        findings.append(_finding(
            "min-length-missing", "medium",
            "No minimum length is stated.",
            "Set min_length to at least 12 (8 is the floor if MFA is on)."))
    elif min_len < 8:
        findings.append(_finding(
            "min-length-short", "high",
            "Minimum length is %d, which is too short." % min_len,
            "Require at least 12 characters."))
    elif min_len < 12:
        findings.append(_finding(
            "min-length-low", "medium",
            "Minimum length is %d. Longer is much harder to guess." % min_len,
            "Raise the minimum to 12 or more."))

    max_len = _num(policy, "max_length")
    if max_len is not None and max_len < 64:
        findings.append(_finding(
            "max-length-low", "medium",
            "Maximum length is %d, which blocks passphrases." % max_len,
            "Allow at least 64 characters."))

    # Rules that look strict but are discouraged
    complexity = [k for k in ("require_uppercase", "require_lowercase",
                              "require_digit", "require_symbol")
                  if policy.get(k) is True]
    if len(complexity) >= 3:
        findings.append(_finding(
            "complexity-forced", "low",
            "Forces character-type rules (%s)." % ", ".join(complexity),
            "Prefer length plus a blocklist; forced symbols lead to 'Password1!'."))

    max_age = _num(policy, "max_age_days")
    if max_age is not None and 0 < max_age <= 180:
        findings.append(_finding(
            "forced-expiry", "low",
            "Passwords expire every %d days." % max_age,
            "Only force a change after a suspected breach."))

    # Things that are missing
    if policy.get("check_breached_passwords") is not True:
        findings.append(_finding(
            "no-breached-check", "medium",
            "Passwords are not checked against known breached lists.",
            "Reject passwords found in a breached-password list."))

    if policy.get("mfa_required") is not True:
        findings.append(_finding(
            "no-mfa", "high",
            "Multi-factor authentication is not required.",
            "Require MFA, at least for admin and remote access."))

    # Lockout
    attempts = _num(policy, "max_failed_attempts")
    if attempts is None or attempts <= 0:
        findings.append(_finding(
            "no-lockout", "high",
            "There is no limit on failed sign-in attempts.",
            "Lock or slow the account after 5 to 10 failures."))
    elif attempts > 10:
        findings.append(_finding(
            "lockout-weak", "medium",
            "Lockout only starts after %d failed attempts." % attempts,
            "Lower it to 10 or fewer."))

    # Storage
    algo = policy.get("hash_algorithm")
    algo_name = algo.strip().lower() if isinstance(algo, str) else None
    if algo_name is None:
        findings.append(_finding(
            "hash-missing", "medium",
            "The password hashing method is not stated.",
            "Record it. Use argon2id, bcrypt, scrypt or PBKDF2."))
    elif algo_name in BROKEN_HASHES:
        findings.append(_finding(
            "hash-weak", "high",
            "Passwords are stored with '%s', which is not safe." % algo_name,
            "Switch to argon2id, bcrypt, scrypt or PBKDF2."))
    elif algo_name not in STRONG_HASHES:
        findings.append(_finding(
            "hash-unknown", "low",
            "Hash method '%s' is not one I recognise." % algo_name,
            "Check it is a slow, salted password hash."))
    if policy.get("salted") is False:
        findings.append(_finding(
            "unsalted", "high",
            "Password hashes are not salted.",
            "Use a unique random salt for every password."))

    # Recovery
    reset = _num(policy, "reset_token_minutes")
    if reset is not None and reset > 60:
        findings.append(_finding(
            "reset-token-long", "medium",
            "Reset links stay valid for %d minutes." % reset,
            "Expire reset links within 60 minutes and make them single use."))
    if policy.get("security_questions") is True:
        findings.append(_finding(
            "security-questions", "medium",
            "Security questions are used for recovery.",
            "Answers are often guessable. Use email or an authenticator instead."))
    if policy.get("allow_paste") is False:
        findings.append(_finding(
            "paste-blocked", "low",
            "Pasting into the password box is blocked.",
            "Allow paste so password managers work."))

    findings.sort(key=lambda f: (-SEVERITIES[f["severity"]], f["rule"]))
    return findings


def filter_findings(findings, min_severity):
    floor = SEVERITIES[min_severity]
    return [f for f in findings if SEVERITIES[f["severity"]] >= floor]


def format_text(results):
    lines = []
    for name, findings in results:
        lines.append("%s: %d finding(s)" % (name, len(findings)))
        for f in findings:
            lines.append("  [%s] %s: %s" % (f["severity"].upper(), f["rule"], f["message"]))
            lines.append("      Fix: %s" % f["fix"])
        if not findings:
            lines.append("  No findings.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_json(results):
    payload = [{"policy": name, "findings": findings} for name, findings in results]
    return json.dumps(payload, indent=2) + "\n"


def build_parser():
    parser = argparse.ArgumentParser(
        description="Check password policy files for weak settings.")
    parser.add_argument("files", nargs="+", help="policy JSON file(s)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--min-severity", choices=tuple(SEVERITIES), default="low",
                        help="hide findings below this level")
    parser.add_argument("--fail-on", choices=tuple(SEVERITIES), default="high",
                        help="exit 1 if any finding is at or above this level")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    results = []
    worst = 0
    for path in args.files:
        try:
            policy = load_policy(path)
        except PolicyError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        findings = check_policy(policy)
        for f in findings:
            worst = max(worst, SEVERITIES[f["severity"]])
        results.append((path, filter_findings(findings, args.min_severity)))
    output = format_json(results) if args.format == "json" else format_text(results)
    sys.stdout.write(output)
    return 1 if worst >= SEVERITIES[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
