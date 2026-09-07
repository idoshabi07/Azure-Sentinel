---
name: sentinel-xdr-migration-orchestrator
description: Orchestrate conversion of a Microsoft Sentinel solution into Defender XDR Custom Detection YAML and validate it with the local migration MCP server and Microsoft Sentinel MCP.
requiredSkills:
  - sentinel-xdr-rule-converter
  - sentinel-xdr-detection-validator
---

# Migrate a Microsoft Sentinel solution to XDR Detection YAML

## Scope

This milestone creates and validates `XDR Detections/*.yaml`.

It does not:

- generate or modify ARM templates;
- deploy analytic rules or Custom Detections;
- generate or ingest mock data;
- convert workbooks;
- compare generated alerts.

## Workflow

1. Confirm the solution path.
2. Use `sentinel-xdr-rule-converter`.
3. Review every `needsReview` result. Never present it as XDR-ready.
4. Use `sentinel-xdr-detection-validator`.
5. Report:
   - source analytic rules;
   - generated detection files;
   - deterministic rewrites;
   - provenance status;
   - Sentinel and Advanced Hunting execution status;
   - unresolved parity gaps.

An XDR-ready result requires valid YAML, no conversion errors, successful
runtime execution on both platforms, and reviewed entity mappings.
