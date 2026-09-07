---
name: sentinel-xdr-detection-validator
description: Validate generated XDR Detection YAML structurally and validate source and converted KQL with Microsoft Sentinel MCP tools.
---

# Validate XDR Detection YAML

Use both MCP servers:

- `sentinel-xdr-migration`
- Microsoft Sentinel data exploration:
  `https://sentinel.microsoft.com/mcp/data-exploration`

## Workflow

1. Call `validate_xdr_detections`.
2. Stop if structural errors remain.
3. Call `get_runtime_validation_plan`.
4. For every rule, use the Microsoft Sentinel MCP data-exploration tools to:
   - execute the original `sentinelQuery`;
   - execute the `advancedHuntingQuery`;
   - record whether each query binds and executes;
   - compare returned entity columns when representative rows exist.
5. Zero rows are not proof of behavioral parity. Record them as execution
   success with data validation still pending.
6. Do not change `contentProvenance.conversion.status` to `validated` unless
   both queries execute and the entity output has been reviewed.

Return a per-rule result and an overall pass/needs-review summary.
