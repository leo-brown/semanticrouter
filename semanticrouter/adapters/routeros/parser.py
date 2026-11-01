"""Lex a RouterOS export without executing any router commands.

The parser preserves command order, source lines, bracketed selectors and unknown
statements. Interpretation belongs to feature adapters; this layer never guesses
the result of a device-dependent selector or runs a RouterOS script."""

import re
from dataclasses import dataclass

from ...model import Source


@dataclass
class Command:
    """A lexical export statement and its provenance, with no execution semantics.

    Attributes remain vendor-specific here. A selector is retained as text rather
    than resolved against an imagined device state; ``opaque`` blocks export proof."""

    path: str
    verb: str
    attributes: dict[str, str]
    selector: str
    source: Source
    opaque: bool = False


def tokens(line):
    # RouterOS double quotes, escaped characters, and bracketed selectors.
    """Split one logical RouterOS line while respecting quotes, escapes and selectors.

    Bracket contents stay together and double quotes delimit values rather than
    becoming part of them. RouterOS hexadecimal escapes are decoded as characters.
    An unfinished quote, escape or selector is rejected instead of truncated."""
    out, buf, quoted, depth, i = [], "", False, 0, 0
    while i < len(line):
        c = line[i]
        if c == "\\":
            i += 1
            if i >= len(line):
                raise ValueError("Trailing escape")
            c = line[i]
            if i + 1 < len(line) and re.fullmatch("[0-9a-fA-F]{2}", line[i : i + 2]):
                c = chr(int(line[i : i + 2], 16))
                i += 1
            else:
                c = {"n": "\n", "r": "\r", "t": "\t"}.get(c, c)
            buf += c
        elif c == '"':
            quoted = not quoted
        elif not quoted and c == "[":
            depth += 1
            buf += c
        elif not quoted and c == "]":
            depth -= 1
            buf += c
        elif not quoted and depth == 0 and c.isspace():
            if buf:
                out.append(buf)
                buf = ""
        else:
            buf += c
        i += 1
    if quoted or depth:
        raise ValueError("Unclosed quote or selector")
    if buf:
        out.append(buf)
    return out


def parse(text, path="<memory>"):
    """Yield ordered commands from terse or section-oriented RouterOS export text.

    Backslash continuations retain the starting physical line as evidence. Bare
    section declarations update context; suspicious executable-looking text becomes
    an opaque command. Abbreviated keys inherit their preceding property group.
    This parser never evaluates a script, selector, substitution or expression."""
    section, pending, start = "", "", 0
    for no, physical in enumerate(text.splitlines(), 1):
        if not pending:
            start = no
        line = pending + physical.strip()
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        pending = ""
        if not line or line.startswith("#"):
            continue
        ts = tokens(line)
        verb_index = next(
            (
                i
                for i, t in enumerate(ts)
                if t in ("add", "set", "remove", "enable", "disable")
            ),
            None,
        )
        if line.startswith("/"):
            if verb_index is None:
                section = "/" + " ".join(line.strip("/").replace("/", " ").split())
                if any(x in line for x in (";", "{", "}", "=", "[", "]")):
                    yield Command(
                        section, "unsupported", {}, "", Source(path, start), True
                    )
                continue
            section = "/" + " ".join(
                " ".join(ts[:verb_index]).strip("/").replace("/", " ").split()
            )
        elif verb_index != 0:
            yield Command(section, "unsupported", {}, "", Source(path, start), True)
            continue
        if verb_index is None:
            continue
        attrs, selector, group, opaque = {}, [], "", False
        for t in ts[verb_index + 1 :]:
            if t.startswith("[") or "=" not in t:
                selector.append(t)
                continue
            k, v = t.split("=", 1)
            if k.startswith("."):
                k = group + k
            elif "." in k:
                group = k.rsplit(".", 1)[0]
            else:
                group = ""
            if k in attrs:
                opaque = True
            attrs[k] = v
        # Scripts may look like commands; never claim full interpretation.
        if ";" in line and not any(k in attrs for k in ("rule", "comment")):
            opaque = True
        yield Command(
            section,
            ts[verb_index],
            attrs,
            " ".join(selector),
            Source(path, start),
            opaque,
        )
    if pending:
        raise ValueError(f"{path}:{start}: unfinished continuation")
