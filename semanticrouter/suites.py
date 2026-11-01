"""Explicit, portable collections of user-editable rules; no suite is auto-enabled."""

import json
from importlib.resources import files

from .rules import validate_rules


def validate_suite(value):
    """Validate imported suite data before it can replace or add active rules."""
    if not isinstance(value, dict) or set(value) - {
        "id",
        "name",
        "description",
        "rules",
        "variables",
        "devices",
    }:
        raise ValueError(
            "Suite supports id, name, description, rules, variables and devices"
        )
    if not isinstance(value.get("name"), str) or not value["name"].strip():
        raise ValueError("Suite needs a name")
    if not isinstance(value.get("variables", {}), dict):
        raise ValueError("Suite variables must be an object")
    if "rules" not in value:
        raise ValueError("Suite needs a rules array, even when empty")
    if "devices" in value and (
        not isinstance(value["devices"], list)
        or any(not isinstance(name, str) for name in value["devices"])
    ):
        raise ValueError("Suite devices must be an array of names")
    validate_rules(value["rules"])
    return value


def example_suites():
    """Return optional examples as normal editable files, never hidden check code."""
    return [
        validate_suite(
            json.loads(
                files("semanticrouter").joinpath("suites", name + ".json").read_text()
            )
        )
        for name in ("baseline", "brighton")
    ]
