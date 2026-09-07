# Microsoft Sentinel to Defender XDR migration toolkit

This toolkit converts the analytic rules in a Microsoft Sentinel solution into
versioned Defender XDR Custom Detection YAML files.

The first milestone intentionally stops before ARM generation. It creates and
validates:

```text
Solutions/<solution>/
  Analytic Rules/
    <rule>.yaml
  XDR Detections/
    <rule>.yaml
    manifest.json
```

Each XDR Detection YAML contains:

- the properties required to generate a
  `Microsoft.Security/detectionRules` resource;
- a disabled-by-default lifecycle state;
- converted KQL;
- translated entity mappings;
- one supported MITRE tactic;
- a `contentProvenance` block linking the detection to its source analytic
  rule and recording conversion warnings.

The YAML contract is defined in
[`schema/xdr-detection.schema.json`](schema/xdr-detection.schema.json).

## Safety model

Conversion is conservative. A file is still generated when manual work is
needed, but `contentProvenance.conversion.status` is set to `needsReview` and
validation fails until blocking issues are resolved. The tool never changes
files under `Analytic Rules` and does not modify `Package/mainTemplate.json`.

Generated detections start with:

```yaml
properties:
  status: disabled
```

## Install

```powershell
cd Tools\SentinelToXDRMigration
python -m pip install -e .
```

## Command line

Inspect a solution:

```powershell
python -m sentinel_xdr_migration.cli inspect `
  --solution "Solutions\Azure Activity"
```

Convert every analytic rule:

```powershell
python -m sentinel_xdr_migration.cli convert `
  --solution "Solutions\Azure Activity"
```

Validate the generated YAML:

```powershell
python -m sentinel_xdr_migration.cli validate `
  --solution "Solutions\Azure Activity"
```

Use `--overwrite` to replace previously generated files. Without it, the
converter refuses to overwrite a file whose content differs.

## Optional migration configuration

Create `XDR Detections/migration-config.yaml` when a solution needs explicit
table, function, or column rewrites:

```yaml
schemaVersion: 1.0.0
tableMappings:
  LegacyTable_CL: CurrentTable_CL
functionMappings:
  LegacyParser: CurrentParser
columnMappings:
  LegacyTable_CL:
    UserName: AccountUpn
```

Mappings are applied token-by-token. `TimeGenerated` is converted to
`Timestamp` by default because Custom Detection queries require `Timestamp`.
Rewrites skip quoted strings and line comments. Source query frequency and
period are retained in `contentProvenance.source.schedule`; a period that
cannot be demonstrated in the query is flagged for review.

The generated file declares `resourceType:
Microsoft.Security/detectionRules`. A later packaging milestone can consume
this field and the `apiVersion`/`properties` block without reinterpreting the
source analytic rule.

## MCP server

Run the local stdio MCP server:

```powershell
python Tools\SentinelToXDRMigration\mcp_server.py
```

It exposes:

- `inspect_sentinel_solution`
- `convert_sentinel_solution`
- `validate_xdr_detections`
- `get_runtime_validation_plan`

See [`mcp.example.json`](mcp.example.json) for a VS Code configuration that
pairs this local server with Microsoft's Sentinel data-exploration MCP server:

`https://sentinel.microsoft.com/mcp/data-exploration`

The Microsoft-hosted server requires the roles and onboarding described in
[Microsoft Sentinel MCP documentation](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-get-started).

## Logging

Runtime logs and reports are written below `Data/`:

- `Data/logs/sentinel-xdr-migration.log`
- `Data/reports/last-conversion.json`

These files are local execution artifacts and are ignored by Git.

## Tests

```powershell
python -m unittest discover -s Tools\SentinelToXDRMigration\tests -p "test_*.py"
```

## Planned milestones

- mock-data generation and DCR ingestion;
- Sentinel analytic-rule and XDR Custom Detection deployment;
- alert and entity parity comparison;
- workbook conversion;
- solution migration dashboard;
- ARM/Content Hub package generation from `XDR Detections`.
