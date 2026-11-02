# Complete RouterOS export

Use
`semanticrouter export input.cfg --vendor routeros --version source --output output.rsc`.
The original input is an import document kept separately from the public semantic model.
Native statements, selectors, scripts, credentials, comments and properties outside the
inspection subset are retained. Model edits update only their mapped properties. Objects
can be enabled, disabled, reordered, added or removed where the common model supplies
all required settings. The file remains a configuration export; no command is executed
or applied to a router by this software.

`source` preserves the imported syntax and its declared firmware metadata. It does not
guess a running version from hardware or silently downgrade an instance-based BGP config
to the pre-7.20 format. Explicit targets are checked for the known BGP layout boundary.
[RouterOS BGP documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/328220/BGP)
describes the 7.20 instance change. Its native-export definition is
`semanticrouter/firmware/routeros-7.20.json`.

## Automatic comparison

Every successful complete source-aware export checks both:

1. **Requested model → output → re-imported model.** All functional fields must match.
   Comparison uses semantic objects, not source text. Whitespace, quoting and parameter
   order can change; behaviorally significant rule order is retained. Inventory labels,
   source line numbers, import diagnostics and selected software target are excluded;
   equivalent legacy discard/reject route actions are normalized.
2. **Native statement ledger → output.** Paths, verbs, selectors, all property values
   and statement order must match the original plus the deliberately applied edits. This
   includes fields such as RADIUS secrets that never enter the common model. Losing one
   fails export even when the semantic model alone would not detect the loss.

For an unedited model, the complete native statement sequence is also compared directly
to the original input. Comments and native literals are retained; absolute command paths
keep reordered/inserted statements independent of RouterOS section context. The result
includes `verification` with semantic/native matches and input/output counts. The
browser displays those checks above the configuration preview. Native inspection
uncertainty remains unknown for tests; preserving an original complex filter does not
pretend to understand or prove its routing behavior.

These checks prove representation fidelity, not successful application to a particular
router, installed packages, live connectivity or hidden factory defaults. Imports still
need the same prepared-device context as their original RouterOS exports. Output is not
an in-place reconciliation script.

## Originals and private fields

Python `load()` retains a private source artifact excluded from dataclass repr and
`to_dict()` JSON. Direct export can therefore preserve fields deliberately omitted from
the model. JSON models by themselves contain no such artifact. After hydration, supply
`source_text=original` to `export_router(...)`, or load the original again.

The browser keeps locally loaded originals in memory. Private hosted snapshots keep
redacted review copies. On an explicit complete export, an authenticated `source.php`
endpoint supplies an immutable copy of the exact imported original. The endpoint accepts
only build-selected names and exact snapshot hashes; later collector updates cannot
alter that copy or mix a new backup with an older model. Originals are stored inside the
separate guarded PHP export endpoint, never in `data.php`, `engine.json` or model JSON,
and the export-only cache is not included in workspace downloads. A complete downloaded
config includes private fields present in its original. An explicitly loaded local
source can also enter a workspace download.

If an operator edited a redacted review source, the app keeps that work and asks for its
original before full export; it never silently replaces those source edits. A standalone
build with only redacted sources needs an original loaded locally. Model audits and rule
changes never fetch or reparse originals.

## Translation scope

A same-syntax export can retain native features that have no platform-independent
mapping. Cross-vendor conversion cannot copy RouterOS syntax into Cisco IOS. ROS6→ROS7
migration of the supported semantic subset remains available with a concrete target, for
example `--version 7.19.3`; unknown legacy features still require explicit mappings.
Cisco output remains an IPv4 ACL artifact, with explicit partial-fragment opt-in where
needed. Source-aware full export never substitutes such a fragment for a complete file.

Some model-only edits lack enough information to construct native objects. For example,
a new OSPF adjacency needs its area/template settings, a new modern BGP connection needs
its instance definition, and physical Ethernet ports need their original set/find
selector. Add these complete definitions to the original source and import it. They are
not guessed from partial model fields. Existing complete definitions are preserved.
