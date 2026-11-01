"""Redact bundled source views while keeping physical line numbers useful.

These sources are review material, not restorable backups. Re-importing them must
carry a diagnostic that prevents a complete export claim. Uploaded originals stay
in browser memory and are never read or persisted by this helper.
"""

import re

_SECRET = re.compile(
    r'\b(password|secret|private-key|preshared-key|auth-key|authentication-password|encryption-password|tcp-md5-key)=("(?:\\.|[^"\\])*"|[^\s]+)',
    re.I,
)


def redact_export(text):
    """Mask credential values and credential-bearing records, preserving line count."""
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        end = index
        while lines[end].rstrip().endswith("\\") and end + 1 < len(lines):
            end += 1
        if end > index and re.search(
            r"\b(password|secret|private-key|preshared-key|auth-key|authentication-password|encryption-password|tcp-md5-key)\s*=",
            "\n".join(lines[index : end + 1]),
            re.I,
        ):
            lines[index : end + 1] = [
                "# [credential-bearing continued statement omitted]"
            ] * (end - index + 1)
        index = end + 1
    output = []
    section = ""
    suppress_continuation = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("/"):
            section = stripped.split(" add ", 1)[0].split(" set ", 1)[0]
        credential_record = section in (
            "/ppp secret",
            "/snmp community",
            "/user",
            "/ip ipsec identity",
        )
        if suppress_continuation or (
            credential_record and stripped and not stripped.startswith("#")
        ):
            output.append("# [credential-bearing source record omitted]")
            suppress_continuation = stripped.endswith("\\")
        elif stripped.startswith(("# serial number", "# software id")):
            output.append("# [device identifier omitted]")
        else:
            output.append(
                _SECRET.sub(lambda match: match.group(1) + '="[REDACTED]"', line)
            )
    return "\n".join(output) + "\n"
