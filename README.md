# Lab 5C — Bandit: Detection and Remediation of Insecure Python Practices

**Student:** Aditey Mehra (2301730266)  
**University:** K.R. Mangalam University  
**Programme:** B.Tech CSE (AI & ML) — Section D — Semester 7  
**Subject:** Secure Coding and Vulnerabilities  
**Repository:** https://github.com/incognito-unlimited/Lab5C-Bandit-Python-Security

---

## 1. Aim

To create a Python program containing at least three insecure coding practices, analyse it with Bandit, interpret the findings, remediate the code with secure alternatives, rerun Bandit with equivalent configuration, verify the fix functionally, and publish the project to GitHub.

## 2. Objectives

- Create an intentionally insecure program with a hard-coded password, `shell=True` subprocess execution and `random`-based token generation.
- Install Bandit, record its version and capture complete text and JSON reports.
- Explain the actual test IDs, severity, confidence and source locations.
- Replace each insecure practice with a secure alternative.
- Rerun Bandit with the same version and equivalent options and compare findings honestly.
- Execute nine functional/security test groups and preserve the real output.
- Capture genuine screenshots, publish to GitHub and produce the report.

## 3. Project structure

```
Lab5C-Bandit-Python-Security/
├── vulnerable.py                  # intentionally insecure program
├── secure_app.py                  # remediated program
├── tests/
│   └── functional_tests.py        # reproducible 9-group test harness
├── evidence/
│   ├── bandit_before.txt          # baseline Bandit text report
│   ├── bandit_before.json         # baseline Bandit JSON report
│   ├── bandit_after.txt           # post-fix Bandit text report
│   ├── bandit_after.json          # post-fix Bandit JSON report
│   ├── bandit_comparison.txt      # before/after comparison
│   ├── bandit_tool_info.txt       # Python and Bandit version
│   ├── bandit_install_console.txt # verbatim install/version transcript
│   ├── functional_test_console.txt# verbatim execution transcript
│   ├── test_results.txt           # full functional-test output
│   └── screenshots/               # 7 genuine screenshots
├── report/
│   ├── Lab5C_Report.md
│   ├── Lab_5C_Bandit_Python_Security_Aditey_Mehra.docx
│   └── Lab_5C_Bandit_Python_Security_Aditey_Mehra.pdf
├── README.md
└── .gitignore
```

## 4. Toolchain

Bandit was not initially available, so it was installed with the prescribed command:

```bash
python --version
# Python 3.11.9
python -m pip install bandit
python -m bandit --version
# __main__.py 1.9.4
#   python version = 3.11.9 (tags/v3.11.9:de54cf5, Apr  2 2024, 10:12:12) [MSC v.1938 64 bit (AMD64)]
```

Environment: Windows, Python 3.11.9, Bandit 1.9.4. No `#nosec` suppressions were used.

## 5. Vulnerable implementation

`vulnerable.py` contains all three required insecure practices:

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

`Admin@123` is a synthetic lab credential, not a real secret. The injection demonstration used only a fixed harmless `echo` payload.

## 6. Bandit findings — before remediation

```bash
python -m bandit -r vulnerable.py -f txt -o evidence/bandit_before.txt
python -m bandit -r vulnerable.py -f json -o evidence/bandit_before.json
```

| Test ID | Finding | Severity | Confidence | Location |
|---|---|---|---|---|
| `B404:blacklist` | Consider possible security implications associated with the subprocess module | Low | High | `vulnerable.py:2:0` |
| `B105:hardcoded_password_string` | Possible hardcoded password: `'Admin@123'` | Low | Medium | `vulnerable.py:4:11` |
| `B311:blacklist` | Standard pseudo-random generators are not suitable for security/cryptographic purposes | Low | High | `vulnerable.py:7:15` |
| `B602:subprocess_popen_with_shell_equals_true` | subprocess call with `shell=True` identified, security issue | **High** | High | `vulnerable.py:12:11` |

Totals: **4 findings — High 1, Medium 0, Low 3**. Confidence: High 3, Medium 1.

### Security impact

- **Hard-coded password (B105):** credentials embedded in source are exposed through Git history, source distributions and logs, are difficult to rotate, and are shared with everyone who can read the repository. Use environment variables or a secret manager and never commit real secrets.
- **`shell=True` (B602):** the shell interprets metacharacters. With `'hello & echo INJECTED_MARKER'` as input, the vulnerable program executed a second command (verified in the functional tests). Use `subprocess.run()` with an argument list and `shell=False`, validate input, and prefer in-process alternatives where possible.
- **`random` for tokens (B311):** Mersenne Twister output is predictable once enough values are observed; a six-digit token has only 900,000 possibilities. Use `secrets.token_urlsafe()` for security-sensitive tokens.

`B404` is a generic import-level advisory about the subprocess module; it is not one of the three target practices but is reported here because Bandit emitted it.

## 7. Secure implementation

`secure_app.py` applies the following changes:

- No credential literal exists in source. `get_password()` reads `APP_PASSWORD` from the environment, and the value is never printed or logged.
- `generate_token()` uses `secrets.token_urlsafe(32)`.
- `run_command()` calls `subprocess.run([sys.executable, "-c", ECHO_CODE, text], check=True, capture_output=True, text=True, shell=False, timeout=5)`. The executable and argument list are fixed; only a validated text value varies.
- `validate_input()` rejects empty/overlong input and control characters while allowing shell metacharacters as ordinary literal text.
- Subprocess and configuration errors become short generic messages with no paths, commands or exception details.

Residual consideration: the external `echo` is unnecessary in a real application; an in-process `print` would be preferable. It is retained here solely to demonstrate the secure `subprocess.run()` argument-list pattern.

## 8. Bandit analysis — after remediation

```bash
python -m bandit -r secure_app.py -f txt -o evidence/bandit_after.txt
python -m bandit -r secure_app.py -f json -o evidence/bandit_after.json
```

| Test ID | Finding | Severity | Confidence | Location |
|---|---|---|---|---|
| `B404:blacklist` | subprocess module import advisory | Low | High | `secure_app.py:13:0` |
| `B603:subprocess_without_shell_equals_true` | subprocess call — check for execution of untrusted input | Low | High | `secure_app.py:68:17` |

| Metric | Before | After |
|---|---:|---:|
| Total findings | 4 | 2 |
| High severity | 1 | 0 |
| Medium severity | 0 | 0 |
| Low severity | 3 | 2 |

**Removed:** `B105`, `B311`, `B602`. **Retained:** `B404`. **Newly introduced:** `B603`.

`B603` is a low-severity generic warning triggered by any subprocess use. In this program the executable is fixed (`sys.executable`), the argument list is fixed apart from one validated text value, `shell=False` is explicit, a timeout is set, and errors are handled generically. Both `B404` and `B603` are accepted residual advisories rather than instances of the target insecure practices; no finding is claimed to have been removed unless the report supports it.

## 9. Functional testing

Run `python tests/functional_tests.py`; full real output is in `evidence/test_results.txt`.

| Test | Result |
|---|---|
| `APP_PASSWORD` unset | `Error: APP_PASSWORD is not configured`, no token printed |
| Test-only `APP_PASSWORD` set | configuration accepted, token printed, credential absent from all output |
| Password never printed | PASS — searched stdout and stderr for the value and `Password:` |
| Five generated tokens | 5 distinct URL-safe tokens, each ≥32 characters |
| `secrets` usage | `secrets.token_urlsafe` present; `import random` absent |
| Ordinary text input | echoed correctly |
| Input with shell metacharacters | echoed as one literal line |
| Literal vs. vulnerable comparison | vulnerable executed a second `echo`; secure did not |
| `shell=True` / hard-coded literal / static checks | all absent; `shell=False` and env lookup present |
| Fresh Bandit scan | 2 findings (`B404`, `B603`); target IDs absent |

**Result: 15/15 checks passed.**

## 10. Evidence and screenshots

- `evidence/bandit_before.txt`, `bandit_before.json`, `bandit_after.txt`, `bandit_after.json` — genuine scanner reports.
- `evidence/bandit_comparison.txt` — before/after comparison.
- `evidence/test_results.txt` — full reproducible test output.
- `evidence/bandit_install_console.txt`, `functional_test_console.txt` — verbatim transcripts.

Genuine screenshots in `evidence/screenshots/`:

1. `01_vulnerable_source.png`
2. `02_bandit_install.png`
3. `03_bandit_before.png`
4. `04_secure_source.png`
5. `05_bandit_after.png`
6. `06_functional_tests.png`
7. `07_github_repository.png`

## 11. Result and conclusion

All three target insecure practices were present in `vulnerable.py` and were detected by Bandit 1.9.4 with exact IDs `B105`, `B602` and `B311`, plus an advisory `B404`. The remediated program removed all three target findings, lowered total findings from 4 to 2 and high-severity findings from 1 to 0, and passed 15/15 functional and static checks. Two low-severity subprocess advisories (`B404`, `B603`) remain and are documented transparently rather than suppressed. Secure credential configuration, cryptographically strong token generation and shell-free argument-list execution together remove the demonstrated risks.

---

**GitHub URL:** https://github.com/incognito-unlimited/Lab5C-Bandit-Python-Security
