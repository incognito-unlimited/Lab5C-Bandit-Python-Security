"""Secure Python application for Lab 5C.

Removes the three deliberately insecure practices in vulnerable.py:
  * credentials are read from the environment and never printed or logged,
  * security tokens use the secrets module,
  * external commands use an argument list with shell=False.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys

MAX_INPUT_LENGTH = 200

# Fixed executable behaviour: the interpreter prints the single argument it
# receives. No shell is involved and no part of user input becomes code.
ECHO_CODE = "import sys; print(sys.argv[1])"


class ConfigurationError(Exception):
    """Required configuration is missing."""


class InputError(Exception):
    """User input is not acceptable."""


class CommandError(Exception):
    """The external operation could not be completed."""


def get_password() -> str:
    """Return the credential from the environment without revealing it."""
    password = os.environ.get("APP_PASSWORD")
    if not password:
        raise ConfigurationError("APP_PASSWORD is not configured")
    return password


def generate_token() -> str:
    """Generate a cryptographically secure, URL-safe token."""
    return secrets.token_urlsafe(32)


def validate_input(text: str) -> str:
    """Allow printable text (including shell metacharacters as literal data)."""
    if not isinstance(text, str) or not text.strip():
        raise InputError("Input must be a non-empty text value")
    if len(text) > MAX_INPUT_LENGTH:
        raise InputError("Input is too long")
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise InputError("Input contains unsupported control characters")
    return text


def run_command(user_input: str) -> str:
    """Echo validated input using a fixed executable and an argument list."""
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
        # Generic message: no paths, commands or exception details are exposed.
        raise CommandError("The requested operation could not be completed") from None
    return result.stdout.rstrip("\n")


def main() -> None:
    try:
        get_password()  # Validate configuration only; never print or log it.
    except ConfigurationError as exc:
        print(f"Error: {exc}")
        return

    print("Token:", generate_token())

    try:
        print(run_command(input("Enter text: ")))
    except (InputError, CommandError) as exc:
        print(f"Error: {exc}")


if __name__ == "__main__":
    main()
