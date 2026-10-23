# Password policy checker

![tests](https://github.com/twistedsol/password-policy-checker/actions/workflows/tests.yml/badge.svg)

A small Python tool that reads a password **policy** file and flags settings that are weak or out of date. It never sees real passwords, only the rules a system uses (length, lockout, hashing, MFA and so on). Standard library only, no installs.

## Run it

```
python policy_checker.py sample_policies/01_weak_legacy.json
python policy_checker.py sample_policies/*.json
python policy_checker.py sample_policies/02_average_company.json --format json
```

On Windows I use `py -3.13` instead of `python`.

Three sample policies are included. They are made up for practice:

| File | What it is | Findings |
|---|---|---|
| `01_weak_legacy.json` | An old intranet with many bad settings | 12 (5 high) |
| `02_average_company.json` | Looks fine but has gaps | 3 (0 high) |
| `03_modern.json` | Follows current advice | 0 |

## What it checks

| Rule | Severity | Flags |
|---|---|---|
| min-length-missing | medium | No minimum length stated |
| min-length-short | high | Minimum under 8 |
| min-length-low | medium | Minimum 8 to 11 |
| max-length-low | medium | Maximum under 64 (blocks passphrases) |
| complexity-forced | low | Three or more forced character-type rules |
| forced-expiry | low | Forced change every 180 days or less |
| no-breached-check | medium | No check against breached-password lists |
| no-mfa | high | MFA not required |
| no-lockout | high | No limit on failed attempts |
| lockout-weak | medium | Lockout only after more than 10 attempts |
| hash-weak | high | md5, sha1, plain sha256 or plaintext storage |
| hash-missing / hash-unknown | medium / low | Hash method not stated or not recognised |
| unsalted | high | Hashes are explicitly not salted |
| reset-token-long | medium | Reset links valid for more than 60 minutes |
| security-questions | medium | Security questions used for recovery |
| paste-blocked | low | Pasting into the password box is blocked |

## Options

- `--format text|json` (default text)
- `--min-severity low|medium|high` hides findings below that level
- `--fail-on low|medium|high` sets which level makes the exit code 1 (default high)

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` bad input (missing file or invalid JSON).

## Policy file format

A JSON object. Every key is optional, and only keys that are present are judged (the few exceptions are listed above as "missing").

```json
{
  "name": "My system",
  "min_length": 12,
  "max_length": 128,
  "require_uppercase": false,
  "max_age_days": 0,
  "check_breached_passwords": true,
  "mfa_required": true,
  "max_failed_attempts": 5,
  "hash_algorithm": "argon2id",
  "salted": true,
  "reset_token_minutes": 30,
  "security_questions": false,
  "allow_paste": true
}
```

## Test it

```
python -m unittest -v
```

34 tests cover each rule, the exact edges (7 vs 8, 11 vs 12), bad input, the command line and the sample files. GitHub Actions runs them on Python 3.10 and 3.12.

## How I built it

I used AI to help write the code and tests, then ran everything myself, read each rule and checked the sample results by hand. The rules follow current public guidance on passwords (long passphrases, breached-password checks, MFA, slow salted hashes, no forced rotation).

## Limits

- It judges a policy **file**, not a live system. If the file says one thing and the system does another, it cannot tell.
- It cannot test passwords or check how a site really stores them.
- The thresholds (12 characters, 10 attempts, 60 minutes) are sensible defaults, not law. Your own standard may differ.
- Only the settings listed above are checked.

## Next ideas

- Read policy exports from real tools (for example an AWS IAM account password policy)
- Add an HTML report
- Add a score out of 100
