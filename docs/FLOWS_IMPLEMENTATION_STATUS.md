# Flows, inventory and export status

September 19, 2026.

| Milestone | Status |
| --- | --- |
| Session summaries | [PR #4](https://github.com/shart-cloud/PacketQuapture/pull/4) merged; [read_flows API and validation](FLOWS.md) |
| Inventory and explicit refresh | [PR #5](https://github.com/shart-cloud/PacketQuapture/pull/5) merged; [API and identity contract](CAPTURE_INVENTORY.md) |
| Catalog-assisted timestamp selection | [PR #6](https://github.com/shart-cloud/PacketQuapture/pull/6) merged; [scope and fallback](CATALOG_PRUNING.md) |
| Standalone PCAP writer | [PR #7](https://github.com/shart-cloud/PacketQuapture/pull/7) merged with native checks passing; [writer contract](PCAP_WRITER.md) |
| SQL PCAP export | Implemented locally on `pcap-copy`; [types, ordering, publication and validation](PCAP_EXPORT.md); publication and hosted checks pending |

Core planned functionality is implemented. Conservative limitations remain explicit:
strict catalog mode scans weak identities, S3 pruning awaits provider verification,
no catalog counts become optimizer bounds, and exported timestamps have microsecond
precision. Within-file indexes, nanosecond reader/export APIs, cross-file stateful
aggregation and WASM remain follow-ups rather than part of these releases.

The user's pre-existing `docs/CURRENT_HANDOFF.md` and untracked
`docs/FLOWS_INVENTORY_EXPORT_PLAN.md` edits are preserved and excluded from commits.
