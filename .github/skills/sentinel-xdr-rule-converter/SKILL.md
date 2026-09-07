---
name: sentinel-xdr-rule-converter
description: Convert every Microsoft Sentinel analytic rule in a solution into a Defender XDR Custom Detection YAML under the solution's XDR Detections folder.
---

# Convert Sentinel analytic rules to XDR Detection YAML

Use the `sentinel-xdr-migration` MCP server.

## Inputs

- The path to one solution folder under `Solutions/`.
- Optional table, function, and column mappings.

## Workflow

1. Call `inspect_sentinel_solution`.
2. Review the analytic-rule count and source paths.
3. If deterministic rewrites are needed, create
   `XDR Detections/migration-config.yaml`.
4. Call `convert_sentinel_solution` with `overwrite=false`.
5. Do not overwrite conflicting generated files without explicit approval.
6. Report:
   - converted count;
   - needs-review count;
   - conflicts;
   - every warning and error.

The converter must not modify `Analytic Rules` or `Package/mainTemplate.json`.
Generated detections must remain disabled.
