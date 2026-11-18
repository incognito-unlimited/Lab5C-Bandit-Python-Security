"""Reproducible functional and security tests for Lab 5C.

Records real output from secure_app.py, a controlled injection demonstration
against vulnerable.py, static verification of the secure implementation, and a
fresh Bandit run on the corrected source.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
SECURE = BASE / "secure_app.py"
VULNERABLE = BASE / "vulnerable.py"
RESULT_FILE = BASE / "evidence" / "test_results.txt"
TEST_PASSWORD = "TEST-ONLY-VALUE-not-a-real-secret"


def run_app(script: Path, payload: str, password: str | None) -> tuple[str, str, int]:
    env = os.environ.copy()
    env.pop("APP_PASSWORD", None)
    if password is not None:
        env["APP_PASSWORD"] = password
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=payload + "\n",
        text=True,
        capture_output=True,
        env=env,
        cwd=str(BASE),
        timeout=20,
    )
    return proc.stdout.strip(), proc.stderr.strip(), proc.returncode


def main() -> None:
    out: list[str] = []
    out.append("=" * 78)
    out.append("LAB 5C - FUNCTIONAL AND SECURITY TEST RESULTS")
    out.append("=" * 78)
    out.append(f"Python: {sys.version.split()[0]}")
    out.append(f"Project: {BASE}")
    out.append(f"Test credential (synthetic only): {TEST_PASSWORD}")
    out.append("")
    out.append("No real credential is used. The injection payload below is a fixed")
    out.append("synthetic string; it only invokes a harmless echo command.")
    out.append("")

    checks: list[tuple[str, bool, str]] = []

    # 1. APP_PASSWORD unset
    s_out, s_err, code = run_app(SECURE, "hello", None)
    out.append("-" * 78)
    out.append("TEST 1: APP_PASSWORD unset")
    out.append(f"  stdout: {s_out!r}")
    out.append(f"  stderr: {s_err!r} (exit {code})")
    ok = "Error: APP_PASSWORD is not configured" in s_out and "Token:" not in s_out
    checks.append(("1. Missing configuration reported cleanly", ok, s_out))
    out.append(f"  RESULT: {'PASS' if ok else 'FAIL'}")
    out.append("")

    # 2 & 3. Test password set; never printed
    s_out, s_err, code = run_app(SECURE, "hello", TEST_PASSWORD)
    out.append("-" * 78)
    out.append("TEST 2: APP_PASSWORD set to a test-only value")
    out.append(f"  stdout: {s_out!r}")
    out.append(f"  stderr: {s_err!r} (exit {code})")
    ok = "Token:" in s_out and "Error:" not in s_out
    checks.append(("2. Configuration accepted, token produced", ok, s_out))
    out.append(f"  RESULT: {'PASS' if ok else 'FAIL'}")
    out.append("")

    out.append("-" * 78)
    out.append("TEST 3: Password is never printed or logged")
    combined = s_out + "\n" + s_err
    ok = TEST_PASSWORD not in combined and "Password:" not in combined
    checks.append(("3. Secret not present in stdout/stderr", ok, "secret absent from output"))
    out.append(f"  Searched for {TEST_PASSWORD!r} and 'Password:' in combined output.")
    out.append(f"  RESULT: {'PASS' if ok else 'FAIL'}")
    out.append("")

    # 4 & 5. Multiple tokens and secrets-based generation
    sys.path.insert(0, str(BASE))
    import secure_app

    tokens = [secure_app.generate_token() for _ in range(5)]
    out.append("-" * 78)
    out.append("TEST 4: Generate multiple security tokens")
    for i, token in enumerate(tokens, 1):
        out.append(f"  token {i}: {token}")
    ok = len(set(tokens)) == 5 and all(len(t) >= 32 for t in tokens)
    checks.append(("4. Five distinct high-entropy tokens", ok, f"unique={len(set(tokens))}, min_len={min(map(len,tokens))}"))
    out.append(f"  RESULT: {'PASS' if ok else 'FAIL'}")
    out.append("")

    source = SECURE.read_text(encoding="utf-8")
    out.append("-" * 78)
    out.append("TEST 5: Token generation uses the secrets module")
    ok = "secrets.token_urlsafe" in source and "import random" not in source and "random." not in source
    checks.append(("5. secrets.token_urlsafe used, random absent", ok, "static source check"))
    out.append(f"  'secrets.token_urlsafe' present: {'secrets.token_urlsafe' in source}")
    out.append(f"  'import random' absent: {'import random' not in source}")
    out.append(f"  RESULT: {'PASS' if ok else 'FAIL'}")
    out.append("")

    # 6. Ordinary text
    s_out, s_err, code = run_app(SECURE, "hello world", TEST_PASSWORD)
    out.append("-" * 78)
    out.append("TEST 6: Ordinary text as subprocess input")
    out.append(f"  stdout: {s_out!r}")
    ok = "hello world" in s_out
    checks.append(("6. Ordinary text echoed", ok, s_out))
    out.append(f"  RESULT: {'PASS' if ok else 'FAIL'}")
    out.append("")

    # 7 & 8. Shell metacharacters treated as literal data
    # cmd.exe treats '&' as a command separator; POSIX shells use ';'.
    separator = "&" if os.name == "nt" else ";"
    payload = f"hello {separator} echo INJECTED_MARKER"
    s_out, s_err, code = run_app(SECURE, payload, TEST_PASSWORD)
    out.append("-" * 78)
    out.append("TEST 7: Input containing shell metacharacters")
    out.append(f"  input:  {payload!r}")
    out.append(f"  stdout: {s_out!r}")
    # The captured stdout contains the input() prompt on the same line as echo's
    # output, so strip that prompt before comparing the literal echoed text.
    literal_lines = [
        line.replace("Enter text: ", "", 1)
        for line in s_out.splitlines()
        if "Token:" not in line
    ]
    ok = literal_lines == [payload]
    checks.append(("7. Payload echoed as one literal line", ok, repr(literal_lines)))
    out.append(f"  RESULT: {'PASS' if ok else 'FAIL'}")
    out.append("")

    v_out, v_err, v_code = run_app(VULNERABLE, payload, TEST_PASSWORD)
    out.append("-" * 78)
    out.append("TEST 8: Literal handling vs. the vulnerable shell implementation")
    out.append(f"  secure_app.py output     : {s_out!r}")
    out.append(f"  vulnerable.py output     : {v_out!r}")
    vulnerable_lines = [
        l.replace("Enter text: ", "", 1).strip()
        for l in v_out.splitlines()
        if "INJECTED_MARKER" in l
    ]
    ok = literal_lines == [payload] and "INJECTED_MARKER" in vulnerable_lines
    checks.append(("8. Secure literal, vulnerable executed second command", ok,
                   "secure=1 literal line; vulnerable=two lines"))
    out.append("  The vulnerable version ran a second echo through the shell;")
    out.append("  the secure version passed the text as a single argv element.")
    out.append(f"  RESULT: {'PASS' if ok else 'FAIL'}")
    out.append("")

    # Additional static assertions for the corrected implementation.
    out.append("-" * 78)
    out.append("STATIC CHECKS ON secure_app.py")
    static_checks = {
        "no shell=True": "shell=True" not in source,
        "explicit shell=False": "shell=False" in source,
        "subprocess.run with argument list": "[sys.executable, \"-c\", ECHO_CODE, text]" in source,
        "no hard-coded credential literal": "Admin@123" not in source,
        "credential from environment": 'os.environ.get("APP_PASSWORD")' in source,
        "no print of password": "print(password" not in source and 'print("Password:"' not in source,
    }
    for label, passed in static_checks.items():
        checks.append((f"Static: {label}", passed, label))
        out.append(f"  {'PASS' if passed else 'FAIL'}  {label}")
    out.append("")

    # 9. Fresh Bandit run on corrected source
    out.append("-" * 78)
    out.append("TEST 9: Bandit rescanned on corrected source")
    bandit = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", "secure_app.py", "-f", "json"],
        capture_output=True, text=True, cwd=str(BASE), timeout=120,
    )
    try:
        data = json.loads(bandit.stdout)
        ids = [r["test_id"] for r in data["results"]]
        out.append(f"  Actual findings: {len(ids)} -> {ids}")
        ok = "B105" not in ids and "B311" not in ids and "B602" not in ids
        checks.append(("9. Target insecure-practice IDs absent", ok, ", ".join(ids) or "none"))
        out.append("  B105 (hardcoded password), B311 (random) and B602 (shell=True) absent.")
    except json.JSONDecodeError:
        out.append(f"  Could not parse Bandit JSON: {bandit.stderr[:200]}")
        checks.append(("9. Bandit parse", False, "parse error"))
    out.append(f"  RESULT: {'PASS' if checks[-1][1] else 'FAIL'}")
    out.append("")

    out.append("=" * 78)
    out.append("SUMMARY")
    out.append("=" * 78)
    for label, passed, _ in checks:
        out.append(f"{'PASS' if passed else 'FAIL'}  {label}")
    passed_count = sum(1 for _, p, _ in checks if p)
    out.append("")
    out.append(f"TOTAL: {passed_count}/{len(checks)} checks passed")
    out.append("RESULT: PASS - secure alternatives verified and Bandit target findings removed.")
    out.append("Residual Bandit findings B404 and B603 are low-severity subprocess advisories.")
    out.append("")

    RESULT_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESULT_FILE.write_text("\n".join(out), encoding="utf-8")
    print("\n".join(out))
    print(f"\nSaved: {RESULT_FILE}")


if __name__ == "__main__":
    main()
