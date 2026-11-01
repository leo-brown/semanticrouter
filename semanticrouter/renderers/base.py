"""Shared export result types and the explicit unsupported-conversion error."""

from dataclasses import dataclass, field


class UnsupportedExport(ValueError):
    """A target/version or completeness requirement that cannot be satisfied."""


@dataclass
class ExportResult:
    """Rendered text, explicit completeness and human-readable omission diagnostics.

    A partial result is a review fragment; callers must not present it as a complete
    replacement configuration or apply it automatically."""

    text: str
    complete: bool
    diagnostics: list[str] = field(default_factory=list)
