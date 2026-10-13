#!/usr/bin/env python3
"""Read a test-environment JSON file and emit shell assignments.

Kept as its own file rather than a heredoc inside the shell helper: a heredoc
nested in a command substitution is fragile to quote, and this way the parser
can be tested on its own.

Usage:
    env.py <file> <scalar keys> <list keys> <bool keys>

Each key group is one space-separated string. Output is one assignment per
line, values quoted with shlex.quote so the caller can eval it safely:

    ENV_DOMAIN=ad.example.com
    ENV_DNS=('10.0.0.10' '10.0.0.11')
    ENV_CRL=1

Unknown keys are an error, not a warning: a typo that is silently dropped
leaves the operator believing a setting took effect.
"""

from __future__ import annotations

import json
import shlex
import sys


#: The template, with the values that cannot be discovered left obviously
#: unset. Discovered values are substituted by ``--init key=value``.
TEMPLATE_ORDER = [
    "domain", "realm", "dns", "search", "hostname", "role",
    "join_user", "test_user", "ca", "crl", "ocsp", "desktop",
    "smartcard_required", "notes",
]

TEMPLATE_DEFAULTS: dict[str, object] = {
    "domain": "ad.example.com",
    "realm": "AD.EXAMPLE.COM",
    "dns": ["10.0.0.10"],
    "search": ["ad.example.com"],
    "hostname": "wks01",
    "role": "server",
    "join_user": "administrator",
    "test_user": "someone@ad.example.com",
    "ca": ["/root/pki/root-ca.pem", "/root/pki/issuing-ca.pem"],
    "crl": True,
    "ocsp": False,
    "desktop": False,
    "smartcard_required": False,
    "notes": "describe this environment so a later run is unambiguous",
}

LIST_FIELDS = {"dns", "search", "ca"}
BOOL_FIELDS = {"crl", "ocsp", "desktop", "smartcard_required"}


def init(pairs: list[str]) -> int:
    """Emit the template JSON with *pairs* (``key=value``) substituted.

    A list field takes a comma-separated value. Anything not given keeps the
    example default, so an operator can see the shape of what is missing
    rather than having to guess the key names.
    """
    data = dict(TEMPLATE_DEFAULTS)
    for pair in pairs:
        key, _, value = pair.partition("=")
        key = key.strip()
        if key not in TEMPLATE_DEFAULTS:
            print(f"--init: unknown key {key!r}", file=sys.stderr)
            return 1
        if not value:
            continue
        if key in LIST_FIELDS:
            data[key] = [v.strip() for v in value.split(",") if v.strip()]
        elif key in BOOL_FIELDS:
            data[key] = value.strip().lower() in ("true", "yes", "1", "on")
        else:
            data[key] = value

    # Anything that follows from the domain should follow from it, or the file
    # ends up half filled in: a real domain with the example realm beside it.
    given = {pair.partition("=")[0].strip() for pair in pairs}
    domain = str(data["domain"])
    if "domain" in given:
        if "realm" not in given:
            data["realm"] = domain.upper()
        if "search" not in given:
            data["search"] = [domain]
        if "test_user" not in given:
            data["test_user"] = f"someone@{domain}"

    ordered = {k: data[k] for k in TEMPLATE_ORDER if k in data}
    print(json.dumps(ordered, indent=2, ensure_ascii=False))
    return 0


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "--init":
        return init(argv[2:])

    if len(argv) != 5:
        print(f"usage: {argv[0]} <file> <scalars> <lists> <bools>", file=sys.stderr)
        return 2

    path = argv[1]
    scalars = argv[2].split()
    lists = argv[3].split()
    bools = argv[4].split()
    known = set(scalars) | set(lists) | set(bools)

    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except ValueError as exc:
        print(f"{path}: not valid JSON -- {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"{path}: {exc}", file=sys.stderr)
        return 1

    if not isinstance(data, dict):
        print(f"{path}: the top level must be a JSON object", file=sys.stderr)
        return 1

    unknown = sorted(set(data) - known)
    if unknown:
        print(
            f"{path}: unknown key(s) {', '.join(unknown)}; accepted keys are "
            + ", ".join(sorted(known)),
            file=sys.stderr,
        )
        return 1

    out: list[str] = []

    for key in scalars:
        value = data.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            print(f"{path}: {key} must be a string", file=sys.stderr)
            return 1
        out.append(f"ENV_{key.upper()}={shlex.quote(str(value))}")

    for key in lists:
        value = data.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(
            not isinstance(v, bool) and isinstance(v, (str, int, float)) for v in value
        ):
            print(
                f"{path}: {key} must be a string or a list of strings",
                file=sys.stderr,
            )
            return 1
        items = " ".join(shlex.quote(str(v)) for v in value)
        out.append(f"ENV_{key.upper()}=({items})")

    truthy = {"true", "yes", "1", "on"}
    falsy = {"false", "no", "0", "off"}
    for key in bools:
        value = data.get(key)
        if value is None:
            continue
        if isinstance(value, bool):
            out.append(f"ENV_{key.upper()}={1 if value else 0}")
        elif str(value).strip().lower() in truthy:
            out.append(f"ENV_{key.upper()}=1")
        elif str(value).strip().lower() in falsy:
            out.append(f"ENV_{key.upper()}=0")
        else:
            print(f"{path}: {key} must be true or false", file=sys.stderr)
            return 1

    # An AD realm is the domain upper-cased. Deriving it saves the operator
    # from stating the same thing twice and getting one of them wrong.
    if data.get("domain") and not data.get("realm"):
        out.append(f"ENV_REALM={shlex.quote(str(data['domain']).upper())}")

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
