# LAB 5C — Bandit-Based Detection and Remediation of Insecure Python Practices

| Detail | Value |
|---|---|
| Name | Aditey Mehra |
| Roll Number | 2301730266 |
| University | K.R. Mangalam University |
| Programme | B.Tech CSE (AI & ML) |
| Section | D |
| Semester | 7 |
| Subject | Secure Coding and Vulnerabilities |
| Lab | 5C |
| GitHub Repository | https://github.com/incognito-unlimited/Lab5C-Bandit-Python-Security |

---

## 1. Aim

To create a Python program containing at least three insecure coding practices, analyse it using Bandit, interpret the reported findings, remediate the code using secure alternatives, rerun Bandit with equivalent configuration, functionally verify the fix, and publish the complete work to GitHub.

## 2. Objectives

1. Create an intentionally insecure program with a hard-coded password, `shell=True` subprocess execution and `random`-based token generation.
2. Install Bandit, record its version and capture complete findings in text and JSON form.
3. Explain the security implications and the exact Bandit test IDs emitted.
4. Replace the insecure practices with secure alternatives.
5. Rerun Bandit and compare findings before and after remediation without fabricating results.
6. Capture genuine screenshots and publish the work to GitHub.

## 3. Introduction

Bandit is a static-analysis tool for Python that searches source code for common security issues and reports findings with test identifiers, severity, confidence and source locations. This experiment demonstrates three common insecure practices: embedding credentials in source code, invoking a shell with untrusted input, and using a non-cryptographic pseudo-random generator for security-sensitive tokens. Static analysis is most useful when its exact output is preserved and then corroborated with runtime tests.

## 4. Vulnerable program

File: `vulnerable.py`

```python
import random
import subprocess

PASSWORD = "Admin@123"

def generate_token():
    return str(random.randint(100000, 999999))

def run_command(user_input):
    return subprocess.check_output(
        "echo " + user_input,
        shell=True,
        text=True
    )

if __name__ == "__main__":
    print("Password:", PASSWORD)
    print("Token:", generate_token())
    print(run_command(input("Enter text: ")))
```

`Admin@123` is a synthetic laboratory credential, not a real secret. All tests used controlled local input and a harmless fixed `echo` payload.

## 5. Bandit installation and scan — before remediation

```bash
python --version                 # Python 3.11.9
python -m pip install bandit     # Bandit 1.9.4 installed
python -m bandit --version
python -m bandit -r vulnerable.py -f txt  -o evidence/bandit_before.txt
python -m bandit -r vulnerable.py -f json -o evidence/bandit_before.json
```

**Actual findings (4 total: High 1, Medium 0, Low 3):**

| Test ID | Finding | Severity | Confidence | Location |
|---|---|---|---|---|
| `B404:blacklist` | Consider possible security implications associated with the subprocess module | Low | High | `vulnerable.py:2:0` |
| `B105:hardcoded_password_string` | Possible hardcoded password: `'Admin@123'` | Low | Medium | `vulnerable.py:4:11` |
| `B311:blacklist` | Standard pseudo-random generators are not suitable for security/cryptographic purposes | Low | High | `vulnerable.py:7:15` |
| `B602:subprocess_popen_with_shell_equals_true` | subprocess call with `shell=True` identified, security issue | **High** | High | `vulnerable.py:12:11` |

## 6. Findings interpretation

### 6.1 Hard-coded password — B105

Credentials embedded in source code are exposed through Git history, source distributions, build artefacts and logs. They cannot be rotated without changing and redeploying the code, and they are visible to every reader of the repository. Remediation: read the credential from an environment variable or a secret manager and never commit or print real secrets.

### 6.2 `subprocess` with `shell=True` — B602

With `shell=True`, the command string is interpreted by a shell, so metacharacters in untrusted input become syntax. The functional test supplied `hello & echo INJECTED_MARKER`; the vulnerable program executed a second `echo` command. Remediation: use `subprocess.run()` with an argument list and `shell=False`, validate input, set a timeout and avoid external commands when an in-process alternative exists.

### 6.3 `random` for security tokens — B311

`random` implements a Mersenne Twister designed for simulation, not cryptography. Its state can be recovered from observed outputs, making tokens predictable; a six-digit token also has only 900,000 possible values. Remediation: use `secrets.token_urlsafe()` or an equivalent cryptographically secure generator.

### 6.4 Subprocess import advisory — B404

Bandit also reports a low-severity generic advisory on `import subprocess`. This is not one of the three target practices, but it is recorded because the scanner emitted it.

## 7. Remediated program

File: `secure_app.py` (key sections)

```python
import os
import secrets
import subprocess
import sys

ECHO_CODE = "import sys; print(sys.argv[1])"

def get_password() -> str:
    password = os.environ.get("APP_PASSWORD")
    if not password:
        raise ConfigurationError("APP_PASSWORD is not configured")
    return password

def generate_token() -> str:
    return secrets.token_urlsafe(32)

def run_command(user_input: str) -> str:
    text = validate_input(user_input)
    try:
        result = subprocess.run(
            [sys.executable, "-c", ECHO_CODE, text],
            check=True,
            capture_output=True,
            text=True,
            shell=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        raise CommandError("The requested operation could not be completed") from None
    return result.stdout.rstrip("\n")
```

No credential literal or `shell=True` remains. The executable and argument list are fixed; only a validated text value varies. Errors are reported generically without paths or exception details. `validate_input()` rejects empty, overlong and control-character input while permitting shell metacharacters as ordinary literal text, which makes the shell-injection contrast testable.

An in-process `print()` would be simpler for a real echo feature; the subprocess call is retained only to demonstrate the secure argument-list pattern.

## 8. Bandit analysis — after remediation

```bash
python -m bandit -r secure_app.py -f txt  -o evidence/bandit_after.txt
python -m bandit -r secure_app.py -f json -o evidence/bandit_after.json
```

| Metric | Before | After | Interpretation |
|---|---:|---:|---|
| Total findings | 4 | 2 | Reduced by 2 |
| High severity | 1 | 0 | `B602` removed |
| Medium severity | 0 | 0 | Unchanged |
| Low severity | 3 | 2 | `B105` and `B311` removed; `B404` retained and `B603` introduced |

**Test IDs removed:** `B105`, `B311`, `B602`. **Retained:** `B404`. **Newly introduced:** `B603` (`subprocess_without_shell_equals_true`, Low/High, `secure_app.py:68`).

`B603` is a generic advisory raised whenever subprocess is used. Here the executable is fixed (`sys.executable`), the argument list is fixed apart from one validated value, `shell=False` is explicit, a timeout is set and errors are handled safely. Both residual findings are documented rather than suppressed with `#nosec`.

## 9. Functional and security testing

Command: `python tests/functional_tests.py`. Full real output is in `evidence/test_results.txt`.

| Test | Expected | Actual |
|---|---|---|
| `APP_PASSWORD` unset | Clean configuration error | `Error: APP_PASSWORD is not configured`, no token |
| Test-only password set | Configuration read, no printing | Token printed; credential absent from output |
| Secret never printed | Value absent from stdout/stderr | PASS |
| Multiple tokens | Distinct high-entropy values | 5 distinct URL-safe tokens, ≥32 characters |
| `secrets` usage | `secrets.token_urlsafe`, no `random` | PASS (static check) |
| Ordinary text | Echoed | `hello world` echoed |
| Shell metacharacters | Literal handling | `hello & echo INJECTED_MARKER` echoed as one literal line |
| Vulnerable comparison | Shell executes second command | Vulnerable printed a separate `INJECTED_MARKER` line; secure did not |
| Fresh Bandit scan | Target IDs absent | 2 findings (`B404`, `B603`); `B105`, `B311`, `B602` absent |

Static checks confirmed: no `shell=True`, explicit `shell=False`, `subprocess.run` argument list, no hard-coded credential literal, environment-based credential, no password print. **Result: 15/15 checks passed.**

## 10. Screenshots

Genuine captures in `evidence/screenshots/`:

1. `01_vulnerable_source.png`
2. `02_bandit_install.png`
3. `03_bandit_before.png`
4. `04_secure_source.png`
5. `05_bandit_after.png`
6. `06_functional_tests.png`
7. `07_github_repository.png`

## 11. GitHub URL

https://github.com/incognito-unlimited/Lab5C-Bandit-Python-Security

## 12. Result and conclusion

Bandit 1.9.4 detected all three target insecure practices in `vulnerable.py`: `B105` (hard-coded password), `B602` (shell execution) and `B311` (weak randomness), together with advisory `B404`. The remediated program removed all three target findings, reduced total findings from 4 to 2 and high-severity findings from 1 to 0, and passed 15/15 functional and static checks. Two low-severity subprocess advisories remain and are honestly documented rather than suppressed. The experiment shows that static analysis is effective when its exact output is preserved, but secure APIs, environment-based configuration and runtime verification are required to actually remove the underlying risk.
