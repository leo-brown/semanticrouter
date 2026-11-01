import json
import re
from importlib.resources import files

from .model import Platform


def definition(name):
    """Load a bundled JSON definition through importlib.resources.

    Resource lookup works from a checkout, installed wheel or browser virtual
    filesystem; it must never depend on the process working directory."""
    return json.loads(
        files("semanticrouter").joinpath("firmware", name + ".json").read_text()
    )


def detect(text, paths, version=None):
    """Separate exact version evidence, syntax-family evidence and hardware identity.

    An explicit override supplies a missing exact version but cannot silently
    contradict recognizable syntax. Mixed family markers are rejected rather than
    selecting whichever happened to appear first."""
    header = re.search(r"^#.*\bby RouterOS\s+([0-9][\w.\-]+)", text, re.M)
    model = re.search(r"^#\s*model\s*=\s*(.+)$", text, re.M)
    p = Platform(
        version=version or (header.group(1) if header else None),
        hardware=model.group(1).strip() if model else None,
    )
    if p.version:
        p.family = p.version.split(".")[0]
        p.evidence.append("explicit override" if version else "RouterOS export header")
    hits = []
    for family in ("6", "7"):
        markers = definition("routeros-" + family)["syntax_markers"]
        found = sorted(set(paths) & set(markers))
        if found:
            hits.append(family)
            p.evidence.extend(found)
    if len(hits) > 1 or (p.family and any(x != p.family for x in hits)):
        raise ValueError("Conflicting RouterOS syntax/version evidence")
    if not p.family and hits:
        p.family = hits[0]
    if p.family and p.family not in ("6", "7"):
        raise ValueError("Unsupported RouterOS family: " + p.family)
    return p
