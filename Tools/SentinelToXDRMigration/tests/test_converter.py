from __future__ import annotations

import tempfile
import tomllib
import unittest
from pathlib import Path

import yaml

from sentinel_xdr_migration.converter import (
    convert_solution,
    inspect_solution,
    runtime_validation_plan,
    validate_solution,
)
from sentinel_xdr_migration import __version__


RULE = """\
id: 11111111-2222-3333-4444-555555555555
name: Suspicious test activity
description: Detects a representative activity.
severity: High
queryFrequency: 1h
queryPeriod: 1h
tactics:
  - Discovery
relevantTechniques:
  - T1087
query: |
  TestTable_CL
  | where TimeGenerated > ago(1h)
  | project TimeGenerated, AccountUpn, IPAddress
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Upn
        columnName: AccountUpn
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
version: 1.0.0
kind: Scheduled
"""


class ConverterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.solution = Path(self.temp.name) / "Sample"
        rules = self.solution / "Analytic Rules"
        rules.mkdir(parents=True)
        (rules / "SampleRule.yaml").write_text(RULE, encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_inspect_finds_analytic_rules(self) -> None:
        result = inspect_solution(self.solution)
        self.assertEqual(result["analyticRuleCount"], 1)
        self.assertEqual(result["existingXdrDetectionCount"], 0)

    def test_convert_writes_versioned_provenance_and_disabled_detection(self) -> None:
        result = convert_solution(self.solution)
        self.assertEqual(result["converted"], 1)
        output = self.solution / "XDR Detections" / "SampleRule.yaml"
        document = yaml.safe_load(output.read_text(encoding="utf-8"))
        self.assertEqual(document["schemaVersion"], "1.0.0")
        self.assertEqual(document["resourceType"], "Microsoft.Security/detectionRules")
        self.assertEqual(document["properties"]["status"], "disabled")
        self.assertIn("Timestamp", document["properties"]["queryCondition"]["queryText"])
        self.assertEqual(
            document["contentProvenance"]["source"]["id"],
            "11111111-2222-3333-4444-555555555555",
        )
        self.assertEqual(
            document["contentProvenance"]["conversion"]["requiredWorkloads"], ["sentinel"]
        )
        self.assertFalse(document["contentProvenance"]["conversion"]["reviewRequired"])

    def test_validate_accepts_generated_detection(self) -> None:
        convert_solution(self.solution)
        result = validate_solution(self.solution)
        self.assertEqual(result["valid"], 1)
        self.assertEqual(result["invalid"], 0)

    def test_converter_refuses_to_overwrite_different_content(self) -> None:
        convert_solution(self.solution)
        output = self.solution / "XDR Detections" / "SampleRule.yaml"
        output.write_text("changed: true\n", encoding="utf-8")
        result = convert_solution(self.solution)
        self.assertEqual(result["conflicts"], 1)

    def test_runtime_plan_pairs_source_and_converted_queries(self) -> None:
        convert_solution(self.solution)
        result = runtime_validation_plan(self.solution)
        self.assertEqual(len(result["rules"]), 1)
        self.assertIn("TimeGenerated", result["rules"][0]["sentinelQuery"])
        self.assertIn("Timestamp", result["rules"][0]["advancedHuntingQuery"])

    def test_explicit_mappings_are_applied(self) -> None:
        output = self.solution / "XDR Detections"
        output.mkdir()
        (output / "migration-config.yaml").write_text(
            """\
schemaVersion: 1.0.0
tableMappings:
  TestTable_CL: DeviceEvents
functionMappings: {}
columnMappings:
  TestTable_CL:
    AccountUpn: InitiatingProcessAccountUpn
""",
            encoding="utf-8",
        )
        convert_solution(self.solution)
        document = yaml.safe_load((output / "SampleRule.yaml").read_text(encoding="utf-8"))
        query = document["properties"]["queryCondition"]["queryText"]
        self.assertIn("DeviceEvents", query)
        self.assertIn("InitiatingProcessAccountUpn", query)
        validation = validate_solution(self.solution)
        self.assertEqual(validation["total"], 1)

    def test_missing_asset_mapping_requires_review(self) -> None:
        path = self.solution / "Analytic Rules" / "SampleRule.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        document["entityMappings"] = [
            {
                "entityType": "URL",
                "fieldMappings": [{"identifier": "Url", "columnName": "Url"}],
            }
        ]
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        result = convert_solution(self.solution)
        self.assertEqual(result["needsReview"], 1)
        validation = validate_solution(self.solution)
        self.assertEqual(validation["invalid"], 1)

    def test_iso_frequency_is_preserved(self) -> None:
        path = self.solution / "Analytic Rules" / "SampleRule.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        document["queryFrequency"] = "PT30M"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        convert_solution(self.solution)
        output = yaml.safe_load(
            (self.solution / "XDR Detections" / "SampleRule.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(output["properties"]["schedule"]["frequency"], "PT30M")

    def test_rewrites_skip_strings_and_comments(self) -> None:
        path = self.solution / "Analytic Rules" / "SampleRule.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        document["query"] = """\
TestTable_CL
| extend Label = "TimeGenerated" // TimeGenerated stays in this comment
| where TimeGenerated > ago(1h)
| project TimeGenerated, AccountUpn, IPAddress, Label
"""
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        convert_solution(self.solution)
        output = yaml.safe_load(
            (self.solution / "XDR Detections" / "SampleRule.yaml").read_text(encoding="utf-8")
        )
        query = output["properties"]["queryCondition"]["queryText"]
        self.assertIn('"TimeGenerated"', query)
        self.assertIn("// TimeGenerated stays in this comment", query)
        self.assertIn("| where Timestamp", query)

    def test_package_and_provenance_versions_match(self) -> None:
        pyproject = tomllib.loads(
            (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(pyproject["project"]["version"], __version__)


if __name__ == "__main__":
    unittest.main()
