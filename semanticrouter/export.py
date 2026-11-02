"""Dispatch source-aware RouterOS export separately from portable conversion.

Native export preserves original settings and verifies the requested semantic edits.
Portable renderers require a target mapping for every feature; their omissions block
complete conversion. Partial fragments need explicit opt-in and a visible banner.
"""

from .renderers import ios, routeros
from .renderers.base import ExportResult, UnsupportedExport

__all__ = ["ExportResult", "UnsupportedExport", "export_router"]


def export_router(
    router,
    vendor,
    version,
    allow_partial=False,
    *,
    source_text=None,
    source_version=None,
):
    """Render a concrete vendor/version target, refusing silent feature loss.

    ``allow_partial`` permits a labelled fragment; it never changes the returned
    completeness status or suppresses omission diagnostics. The caller owns any
    eventual application or control-plane attachment on a target device.
    """
    renderers = {"routeros": routeros.render, "cisco-ios": ios.render}
    if vendor not in renderers:
        raise UnsupportedExport("Unknown target vendor " + vendor)
    source_text = (
        source_text
        if source_text is not None
        else getattr(router, "_routeros_source", None)
    )
    source_version = source_version or getattr(router, "_routeros_source_version", None)
    if vendor == "routeros" and source_text is not None:
        from .adapters.routeros import RouterOSRouter
        from .renderers.routeros_native import render_complete

        original = RouterOSRouter(router.name, source_text, version=source_version)
        family = original.bgp.family
        if version == "source" or family != "6":
            # Semantic uncertainty is not an omission when its original syntax is
            # retained. A changed model must still pass native round-trip validation.
            return render_complete(router, version, source_text, source_version)
    if version == "source":
        raise UnsupportedExport(
            "Original-syntax export requires the imported original configuration."
        )
    lines, diagnostics = renderers[vendor](router, version)

    def issue(message):
        diagnostics.append(message)

    if router.unexported:
        issue(
            f"{len(router.unexported)} statements lack portable target mappings; complete conversion is blocked."
        )
    if router.firewall_v4.connection_tracking is not None:
        issue("The selected converter does not render connection tracking.")
    if (
        router.interfaces
        or router.firewall_v6
        or router.ppp_servers
        or router.radius
        or router.snmp_enabled is not None
    ):
        issue(
            "The selected converter does not render interfaces, IPv6, PPP, RADIUS or SNMP. Complete RouterOS export uses the original configuration."
        )
    if router.diagnostics and any(
        d.code not in ("version-unknown",) for d in router.diagnostics
    ):
        issue("Import has unresolved semantic diagnostics.")
    if any(not x.supported for x in router.bgp.policies):
        issue("Unresolved route-policy semantics.")
    # A manually constructed model can contain features without source provenance.
    if router.ospf_interfaces or router.ppp_local_addresses:
        issue("The selected converter does not render OSPF or PPP profiles.")
    complete = not diagnostics
    if not complete and not allow_partial:
        raise UnsupportedExport("\n".join(diagnostics))
    header = "#" if vendor == "routeros" else "!"
    banner = f"{header} SemanticRouter: " + (
        "complete supported model"
        if complete
        else "PARTIAL CONFIGURATION — omitted features; review diagnostics"
    )
    text = banner + "\n" + "\n".join(lines) + "\n"
    verification = {}
    if complete and vendor == "routeros":
        from .adapters.routeros import RouterOSRouter
        from .renderers.routeros_native import functional

        restored = RouterOSRouter(router.name, text, version=version).to_common()
        if functional(restored) != functional(router):
            raise UnsupportedExport(
                "Generated RouterOS configuration did not round-trip to the requested semantic model."
            )
        verification = {"semantic_match": True, "native_statement_match": None}
    return ExportResult(text, complete, diagnostics, verification=verification)
