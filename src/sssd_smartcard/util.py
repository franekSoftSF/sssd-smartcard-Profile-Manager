"""Small shared helpers: subprocess wrapper, platform checks, formatting."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Sequence


@dataclass
class CommandResult:
    """Outcome of an external command."""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    found: bool = True

    @property
    def ok(self) -> bool:
        return self.found and self.returncode == 0

    @property
    def output(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()


def is_linux() -> bool:
    return platform.system() == "Linux"


def which(name: str) -> str | None:
    return shutil.which(name)


def run(
    argv: Sequence[str],
    *,
    timeout: int = 30,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run a command, never raising on failure.

    A missing binary yields ``found=False`` instead of an exception so callers
    can degrade to "unknown" rather than crash.
    """
    argv = list(argv)
    if which(argv[0]) is None and not os.path.isabs(argv[0]):
        return CommandResult(argv, 127, "", f"{argv[0]}: not found", found=False)
    if os.path.isabs(argv[0]) and not os.path.exists(argv[0]):
        return CommandResult(argv, 127, "", f"{argv[0]}: not found", found=False)
    merged = dict(os.environ)
    merged.setdefault("LC_ALL", "C")
    if env:
        merged.update(env)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            env=merged,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(argv, 124, "", f"timed out after {timeout}s")
    except OSError as exc:  # permission denied, exec format error, ...
        return CommandResult(argv, 126, "", str(exc), found=False)
    return CommandResult(argv, proc.returncode, proc.stdout or "", proc.stderr or "")


def service_or_socket_active(
    service: str, socket: str | None = None
) -> tuple[bool | None, str]:
    """Is *service* available, counting socket activation as available?

    ``systemctl is-active pcscd.service`` reports ``inactive`` on a perfectly
    healthy system, because pcscd is socket-activated: systemd holds
    ``pcscd.socket`` open and only starts the daemon when a client connects.
    Checking the service alone therefore produces a false alarm on every
    default Ubuntu and Fedora install.

    Returns ``(available, detail)``; ``available`` is ``None`` when systemd
    cannot be reached at all.
    """
    result = run(["systemctl", "is-active", service], timeout=10)
    if not result.found:
        return None, "systemctl not available"
    state = result.stdout.strip() or result.stderr.strip()
    if state == "active":
        return True, f"{service} is active"

    if socket:
        sock = run(["systemctl", "is-active", socket], timeout=10)
        sock_state = sock.stdout.strip() or sock.stderr.strip()
        if sock_state == "active":
            return True, (
                f"{socket} is active; {service} is {state} because it is "
                "socket-activated and starts on demand"
            )
        return False, f"{service} is {state} and {socket} is {sock_state}"
    return False, f"{service} is {state}"


def run_interactive(
    argv: Sequence[str],
    *,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run a command with the terminal attached, capturing nothing.

    Used for ``kinit``, which prompts for the Smart Card PIN.  The PIN is typed
    straight into kinit; this process never sees it, never buffers it and never
    stores it.

    ``env`` adds variables to the inherited environment -- used to point
    ``KRB5_TRACE`` at a file, so the mechanism kinit actually negotiated can be
    read afterwards without capturing the terminal.
    """
    argv = list(argv)
    if which(argv[0]) is None:
        return CommandResult(argv, 127, "", f"{argv[0]}: not found", found=False)
    child_env = None
    if env:
        child_env = dict(os.environ)
        child_env.update(env)
    try:
        proc = subprocess.run(argv, timeout=timeout, env=child_env)
    except subprocess.TimeoutExpired:
        return CommandResult(argv, 124, "", f"timed out after {timeout}s")
    except OSError as exc:
        return CommandResult(argv, 126, "", str(exc), found=False)
    return CommandResult(argv, proc.returncode, "", "")


def http_get(
    url: str, *, timeout: int = 30, post: bytes | None = None,
    content_type: str | None = None,
) -> tuple[bytes, str]:
    """Fetch *url*, returning ``(body, error)``.

    curl rather than urllib: a Microsoft CA publishes its AIA and CDP paths
    full of percent-encoded spaces, and curl handles those without a second
    round of encoding. The body goes to a file because it is usually DER, and
    the shared ``run`` helper decodes stdout as text.
    """
    if not url.lower().startswith(("http://", "https://")):
        return b"", f"{url}: only http(s) is fetched"
    if which("curl") is None:
        return b"", "curl is not installed"

    import tempfile

    with tempfile.TemporaryDirectory(prefix="sssd-smartcard-http-") as tmp:
        target = os.path.join(tmp, "body")
        argv = ["curl", "-sSfL", "--max-time", str(timeout), "-o", target]
        if content_type:
            argv += ["-H", f"Content-Type: {content_type}"]
        if post is not None:
            post_file = os.path.join(tmp, "request")
            with open(post_file, "wb") as handle:
                handle.write(post)
            argv += ["--data-binary", f"@{post_file}"]
        argv.append(url)
        result = run(argv, timeout=timeout + 10)
        if not result.ok:
            detail = result.stderr.strip().splitlines()
            return b"", f"{url}: {detail[0] if detail else 'request failed'}"
        try:
            with open(target, "rb") as handle:
                body = handle.read()
        except OSError as exc:
            return b"", f"{url}: nothing was downloaded ({exc})"
    if not body:
        return b"", f"{url}: the response was empty"
    return body, ""


def hexfmt(data: bytes, *, sep: str = ":", upper: bool = True) -> str:
    """Render bytes as ``AA:BB:CC``."""
    text = sep.join(f"{b:02x}" for b in data)
    return text.upper() if upper else text


@dataclass
class Check:
    """One diagnostic result."""

    name: str
    status: str  # PASS | WARN | FAIL | SKIP | INFO
    detail: str = ""
    hint: str = ""
    data: dict = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.status == "FAIL"


STATUS_ORDER = {"FAIL": 0, "WARN": 1, "INFO": 2, "SKIP": 3, "PASS": 4}
