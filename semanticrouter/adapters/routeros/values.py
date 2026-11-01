"""Decode small RouterOS scalar conventions used by multiple feature adapters."""

import re


def enabled(a):
    """Interpret explicit RouterOS disabled=yes; omitted disabled means enabled.

    This convention is used only for recognized configuration records. It does not
    claim that an enabled interface, server or peer is operational."""
    return a.get("disabled", "no") != "yes"


def milliseconds(value):
    """Normalize the supported ms/s duration syntax, returning None for unknown forms."""
    m = re.fullmatch(r"([\d.]+)(ms|s)", value or "")
    return int(float(m[1]) * (1000 if m[2] == "s" else 1)) if m else None
