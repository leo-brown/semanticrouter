"""Capability-checked export orchestration over the common router model.

Renderers return output plus omissions. A complete export is refused whenever an
imported property, common feature or unresolved diagnostic lacks a mapping. Partial
fragments require an explicit opt-in and carry a visible banner.
"""

from .renderers import ios, routeros
from .renderers.base import ExportResult, UnsupportedExport

__all__ = ["ExportResult", "UnsupportedExport", "export_router"]


def export_router(router, vendor, version, allow_partial=False):
    """Render a concrete vendor/version target, refusing silent feature loss.

    ``allow_partial`` permits a labelled fragment; it never changes the returned
    completeness status or suppresses omission diagnostics. The caller owns any
    eventual application or control-plane attachment on a target device.
    """
    renderers = {"routeros": routeros.render, "cisco-ios": ios.render}
    if vendor not in renderers:
        raise UnsupportedExport("Unknown target vendor " + vendor)
    lines, diagnostics = renderers[vendor](router, version)

    def issue(message):
        diagnostics.append(message)

    if router.unexported:
        issue(
            f"{len(router.unexported)} source commands contain unmapped features/properties; full-device export is blocked."
        )
    if router.firewall_v4.connection_tracking is not None:
        issue("Connection tracking setting is not exported.")
    if (
        router.interfaces
        or router.firewall_v6
        or router.ppp_servers
        or router.radius
        or router.snmp_enabled is not None
    ):
        issue(
            "Interfaces, IPv6, PPP, RADIUS and SNMP are inspection-only in this release."
        )
    if router.diagnostics and any(
        d.code not in ("version-unknown",) for d in router.diagnostics
    ):
        issue("Import has unresolved semantic diagnostics.")
    if any(not x.supported for x in router.bgp.policies):
        issue("Unresolved route-policy semantics.")
    # A manually constructed model can contain features without source provenance.
    if router.ospf_interfaces or router.ppp_local_addresses:
        issue("OSPF/PPP profile export unsupported.")
    complete = not diagnostics
    if not complete and not allow_partial:
        raise UnsupportedExport("\n".join(diagnostics))
    header = "#" if vendor == "routeros" else "!"
    banner = f"{header} SemanticRouter: " + (
        "complete supported model"
        if complete
        else "PARTIAL CONFIGURATION — omitted features; review diagnostics"
    )
    return ExportResult(banner + "\n" + "\n".join(lines) + "\n", complete, diagnostics)
