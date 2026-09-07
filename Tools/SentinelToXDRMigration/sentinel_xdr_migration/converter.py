from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from . import __version__

SCHEMA_VERSION = "1.0.0"
DETECTION_API_VERSION = "2026-06-01-preview"
REQUIRED_ASSET_COLLECTIONS = frozenset({"hosts", "accounts", "mailboxes", "ips"})
SUPPORTED_SEVERITIES = frozenset({"informational", "low", "medium", "high"})
BLOCKING_KQL_PATTERNS = {
    r"\bworkspace\s*\(": "cross-workspace queries require manual redesign",
    r"\bexternaldata\s*\(": "externaldata is not supported in scheduled Custom Detections",
}
REVIEW_KQL_PATTERNS = {
    r"\bsearch\b": "search queries should be replaced with explicit tables",
    r"\bunion\s+isfuzzy\s*=\s*true\b": "isfuzzy unions can still fail semantic binding in Advanced Hunting",
    r"\b_[Ii]m_[A-Za-z0-9_]+\s*\(": "ASIM parser availability must be verified in Advanced Hunting",
}

ENTITY_MAP: dict[str, tuple[str, dict[str, str | None]]] = {
    "Host": (
        "hosts",
        {
            "HostName": "nameColumn",
            "NetBiosName": "netBiosNameColumn",
            "NTDomain": "ntDomainColumn",
            "DnsDomain": "dnsDomainColumn",
            "DeviceId": "deviceIdColumn",
        },
    ),
    "Account": (
        "accounts",
        {
            "Name": "nameColumn",
            "NTDomain": "ntDomainColumn",
            "DnsDomain": "dnsDomainColumn",
            "UPNSuffix": "upnSuffixColumn",
            "Upn": "upnColumn",
            "Sid": "sidColumn",
            "AadUserId": "aadUserIdColumn",
        },
    ),
    "IP": ("ips", {"Address": "addressColumn"}),
    "URL": ("urls", {"Url": "addressColumn"}),
    "AzureResource": ("azureResources", {"ResourceId": "resourceIdColumn"}),
    "CloudApplication": ("cloudApplications", {"AppId": "appIdColumn", "Name": "nameColumn"}),
    "Mailbox": ("mailboxes", {"MailboxPrimaryAddress": "primaryAddressColumn"}),
    "MailMessage": (
        "mailMessages",
        {
            "NetworkMessageId": "networkMessageIdColumn",
            "Recipient": "recipientColumn",
            "Sender": "senderColumn",
            "P1Sender": "senderColumn",
            "P2Sender": "senderColumn",
            "Subject": "subjectColumn",
        },
    ),
}

ACCOUNT_IDENTITIES = (
    frozenset({"upnColumn"}),
    frozenset({"aadUserIdColumn"}),
    frozenset({"sidColumn"}),
    frozenset({"nameColumn", "upnSuffixColumn"}),
    frozenset({"nameColumn", "ntDomainColumn"}),
    frozenset({"nameColumn", "dnsDomainColumn"}),
)


class XdrYamlDumper(yaml.SafeDumper):
    pass


def _represent_string(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


XdrYamlDumper.add_representer(str, _represent_string)


@dataclass(frozen=True)
class ConversionResult:
    source: Path
    output: Path
    status: str
    warnings: tuple[str, ...]
    errors: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": str(self.source),
            "output": str(self.output),
            "status": self.status,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


def configure_logging(tool_root: Path) -> None:
    log_dir = tool_root / "Data" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(log_dir / "sentinel-xdr-migration.log", encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:72] or "custom-detection"


def iso_duration(value: Any, default: str = "PT1H") -> tuple[str, str | None]:
    text = str(value or "").strip().lower()
    iso = text.upper()
    if re.fullmatch(
        r"P(?:(?:\d+D)(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?|T(?:\d+H)?(?:\d+M)?(?:\d+S)?)",
        iso,
    ):
        return iso, None
    match = re.fullmatch(r"(\d+)\s*([smhd])", text)
    if not match:
        return default, f"unrecognized queryFrequency {value!r}; defaulted to {default}"
    amount, unit = match.groups()
    return {
        "s": f"PT{amount}S",
        "m": f"PT{amount}M",
        "h": f"PT{amount}H",
        "d": f"P{amount}D",
    }[unit], None


def solution_paths(solution: str | Path) -> tuple[Path, Path, Path]:
    root = Path(solution).expanduser().resolve()
    analytic = root / "Analytic Rules"
    output = root / "XDR Detections"
    if not root.is_dir():
        raise ValueError(f"solution path does not exist: {root}")
    if not analytic.is_dir():
        raise ValueError(f"solution has no 'Analytic Rules' folder: {root}")
    return root, analytic, output


def load_config(output_dir: Path, explicit: str | Path | None = None) -> dict[str, Any]:
    path = Path(explicit).expanduser().resolve() if explicit else output_dir / "migration-config.yaml"
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        value = yaml.safe_load(handle) or {}
    if not isinstance(value, dict):
        raise ValueError(f"migration config must contain a YAML object: {path}")
    return value


def analytic_rule_files(solution: str | Path) -> list[Path]:
    _, analytic, _ = solution_paths(solution)
    return sorted([*analytic.glob("*.yaml"), *analytic.glob("*.yml")])


def xdr_detection_files(output: Path) -> list[Path]:
    return sorted(
        path
        for path in [*output.glob("*.yaml"), *output.glob("*.yml")]
        if path.name.lower() != "migration-config.yaml"
    )


def inspect_solution(solution: str | Path) -> dict[str, Any]:
    root, analytic, output = solution_paths(solution)
    files = analytic_rule_files(root)
    return {
        "solution": str(root),
        "analyticRulesDirectory": str(analytic),
        "xdrDetectionsDirectory": str(output),
        "analyticRuleCount": len(files),
        "analyticRules": [path.name for path in files],
        "existingXdrDetectionCount": len(xdr_detection_files(output)) if output.exists() else 0,
    }


def _replace_code_segment(segment: str, pattern: re.Pattern[str], mappings: dict[str, str]) -> str:
    pieces = re.split(r"""('(?:''|[^'])*'|"(?:\\"|[^"])*")""", segment)
    for index in range(0, len(pieces), 2):
        pieces[index] = pattern.sub(lambda match: mappings[match.group(0)], pieces[index])
    return "".join(pieces)


def _token_replace(query: str, mappings: dict[str, str]) -> str:
    if not mappings:
        return query
    pattern = re.compile(
        r"\b(?:" + "|".join(re.escape(source) for source in sorted(mappings, key=len, reverse=True)) + r")\b"
    )
    output = []
    for line in query.splitlines(keepends=True):
        code, separator, comment = line.partition("//")
        output.append(_replace_code_segment(code, pattern, mappings))
        if separator:
            output.append(separator + comment)
    return "".join(output)


def convert_query(query: str, config: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    warnings: list[str] = []
    errors: list[str] = []
    converted = query.strip()

    column_mappings: dict[str, str] = {"TimeGenerated": "Timestamp"}
    configured_columns = config.get("columnMappings") or {}
    if configured_columns and all(isinstance(value, str) for value in configured_columns.values()):
        column_mappings.update({str(k): str(v) for k, v in configured_columns.items()})
    else:
        for mapping in configured_columns.values():
            if isinstance(mapping, dict):
                column_mappings.update({str(k): str(v) for k, v in mapping.items()})
    mappings: dict[str, str] = {}
    mappings.update({str(k): str(v) for k, v in (config.get("functionMappings") or {}).items()})
    mappings.update({str(k): str(v) for k, v in (config.get("tableMappings") or {}).items()})
    mappings.update(column_mappings)
    converted = _token_replace(converted, mappings)
    converted = "\n".join(line.rstrip() for line in converted.splitlines())
    converted = re.sub(r";\s*\Z", "", converted)

    for pattern, message in BLOCKING_KQL_PATTERNS.items():
        if re.search(pattern, converted, re.IGNORECASE):
            errors.append(message)
    for pattern, message in REVIEW_KQL_PATTERNS.items():
        if re.search(pattern, converted, re.IGNORECASE):
            warnings.append(message)

    if not re.search(r"\bTimestamp\b", converted):
        errors.append("converted query does not expose or reference the required Timestamp column")
    return converted, warnings, errors


def _valid_account(fields: dict[str, str]) -> bool:
    present = set(fields)
    return any(required <= present for required in ACCOUNT_IDENTITIES)


def convert_entities(doc: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    output: dict[str, list[dict[str, Any]]] = {}
    warnings: list[str] = []
    counters: dict[str, int] = {}

    for entity in doc.get("entityMappings") or []:
        entity_type = str(entity.get("entityType") or "")
        if entity_type not in ENTITY_MAP:
            warnings.append(f"{entity_type or 'Unknown entity'} has no supported Custom Detection mapping")
            continue
        collection, identifiers = ENTITY_MAP[entity_type]
        fields: dict[str, str] = {}
        for mapping in entity.get("fieldMappings") or []:
            identifier = str(mapping.get("identifier") or "")
            column = str(mapping.get("columnName") or "")
            target = identifiers.get(identifier)
            if target and column:
                fields[target] = column
            elif identifier:
                warnings.append(f"{entity_type}.{identifier} has no supported Custom Detection field")
        if entity_type == "Account" and fields and not _valid_account(fields):
            warnings.append("Account mapping is incomplete and was removed")
            fields = {}
        if fields:
            counters[collection] = counters.get(collection, 0) + 1
            identifier = collection[:-1] if collection.endswith("s") else collection
            output.setdefault(collection, []).append(
                {"id": f"{identifier}{counters[collection]}", **fields}
            )
    return output, warnings


def _techniques(values: list[str] | None) -> list[dict[str, Any]]:
    if not values:
        return []
    value = str(values[0]).strip()
    if not value:
        return []
    base, _, suffix = value.partition(".")
    result: dict[str, Any] = {"technique": base}
    if suffix:
        result["subTechniques"] = [value]
    return [result]


def build_xdr_document(source: Path, solution_root: Path, config: dict[str, Any]) -> dict[str, Any]:
    with source.open(encoding="utf-8-sig") as handle:
        doc = yaml.safe_load(handle) or {}
    if not isinstance(doc, dict):
        raise ValueError(f"analytic rule must contain a YAML object: {source}")

    source_query = str(doc.get("query") or "")
    converted_query, query_warnings, errors = convert_query(source_query, config)
    warnings = list(query_warnings)
    review_reasons = list(query_warnings)
    frequency, frequency_warning = iso_duration(doc.get("queryFrequency"))
    if frequency_warning:
        warnings.append(frequency_warning)
        review_reasons.append(frequency_warning)
    query_period = str(doc.get("queryPeriod") or "").strip()
    if query_period and query_period.lower() not in source_query.lower():
        reason = "source queryPeriod has no direct Custom Detection schedule field; verify the KQL lookback"
        warnings.append(reason)
        review_reasons.append(reason)
    mappings, mapping_warnings = convert_entities(doc)
    warnings.extend(mapping_warnings)

    tactics = [str(value) for value in doc.get("tactics") or [] if value]
    relevant = [str(value) for value in doc.get("relevantTechniques") or [] if value]
    if len(tactics) > 1:
        reason = "Custom Detections support one tactic; only the first tactic was retained"
        warnings.append(reason)
        review_reasons.append(reason)
    if len(relevant) > 1:
        reason = "Multiple MITRE techniques require review and were omitted"
        warnings.append(reason)
        review_reasons.append(reason)
    if not mappings:
        errors.append("no supported entity mappings were produced")
    elif not REQUIRED_ASSET_COLLECTIONS.intersection(mappings):
        errors.append("a Host, Account, Mailbox, or IP mapping is required")

    source_id = str(doc.get("id") or "")
    if not source_id:
        errors.append("source analytic rule has no id")
    display_name = str(doc.get("name") or source.stem)
    detection_id = f"xdr-{slugify(display_name)}-{source_id[:8] or 'unversioned'}"
    severity = str(doc.get("severity") or "Medium").lower()
    if severity not in SUPPORTED_SEVERITIES:
        warnings.append(f"unsupported severity {severity!r}; changed to medium")
        severity = "medium"

    tactic_payload: list[dict[str, Any]] = []
    if tactics:
        tactic = {"tactic": tactics[0]}
        technique_payload = _techniques(relevant) if len(tactics) == 1 and len(relevant) == 1 else []
        if technique_payload:
            tactic["techniques"] = technique_payload
        tactic_payload.append(tactic)

    alert: dict[str, Any] = {
        "title": display_name[:120],
        "description": str(doc.get("description") or display_name).strip()[:600],
        "severity": severity,
        "entityMappings": mappings,
    }
    if tactic_payload:
        alert["tactics"] = tactic_payload

    status = "needsReview" if errors or review_reasons else "converted"
    relative_source = source.relative_to(solution_root).as_posix()
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "CustomDetection",
        "resourceType": "Microsoft.Security/detectionRules",
        "apiVersion": DETECTION_API_VERSION,
        "contentProvenance": {
            "source": {
                "platform": "Microsoft Sentinel",
                "kind": "AnalyticsRule",
                "id": source_id,
                "path": relative_source,
                "version": str(doc.get("version") or ""),
                "querySha256": hashlib.sha256(source_query.encode("utf-8")).hexdigest(),
                "schedule": {
                    "queryFrequency": str(doc.get("queryFrequency") or ""),
                    "queryPeriod": query_period,
                },
            },
            "conversion": {
                "tool": "sentinel-to-xdr-migration",
                "version": __version__,
                "status": status,
                "reviewRequired": bool(errors or review_reasons),
                "reviewReasons": review_reasons,
                "requiredWorkloads": ["sentinel"],
                "warnings": warnings,
                "errors": errors,
                "originalTactics": tactics,
                "originalTechniques": relevant,
            },
        },
        "properties": {
            "id": detection_id,
            "displayName": display_name[:120],
            "status": "disabled",
            "queryCondition": {"queryText": converted_query},
            "schedule": {"frequency": frequency},
            "detectionAction": {"alertTemplate": alert},
        },
    }


def validate_document(document: dict[str, Any]) -> list[str]:
    schema_path = Path(__file__).resolve().parents[1] / "schema" / "xdr-detection.schema.json"
    with schema_path.open(encoding="utf-8") as handle:
        schema = json.load(handle)
    errors = [
        f"schema: {error.message}"
        for error in Draft202012Validator(schema).iter_errors(document)
    ]
    if document.get("schemaVersion") != SCHEMA_VERSION:
        errors.append(f"schemaVersion must be {SCHEMA_VERSION}")
    if document.get("kind") != "CustomDetection":
        errors.append("kind must be CustomDetection")
    if document.get("resourceType") != "Microsoft.Security/detectionRules":
        errors.append("resourceType must be Microsoft.Security/detectionRules")
    provenance = document.get("contentProvenance") or {}
    source = provenance.get("source") or {}
    conversion = provenance.get("conversion") or {}
    properties = document.get("properties") or {}
    for field in ("platform", "kind", "id", "path", "querySha256"):
        if not source.get(field):
            errors.append(f"contentProvenance.source.{field} is required")
    if conversion.get("status") not in {"converted", "needsReview"}:
        errors.append("contentProvenance.conversion.status is invalid")
    if conversion.get("errors"):
        errors.extend(f"conversion: {value}" for value in conversion["errors"])
    if properties.get("status") != "disabled":
        errors.append("properties.status must be disabled")
    query = ((properties.get("queryCondition") or {}).get("queryText") or "")
    if not query:
        errors.append("properties.queryCondition.queryText is required")
    elif not re.search(r"\bTimestamp\b", query):
        errors.append("query must expose or reference Timestamp")
    alert = ((properties.get("detectionAction") or {}).get("alertTemplate") or {})
    mappings = alert.get("entityMappings") or {}
    if not mappings:
        errors.append("alertTemplate.entityMappings is required")
    if not REQUIRED_ASSET_COLLECTIONS.intersection(mappings):
        errors.append("at least one Host, Account, Mailbox, or IP mapping is required")
    if len(alert.get("tactics") or []) > 1:
        errors.append("at most one tactic is supported")
    return errors


def convert_solution(
    solution: str | Path,
    *,
    overwrite: bool = False,
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    root, _, output = solution_paths(solution)
    output.mkdir(parents=True, exist_ok=True)
    config = load_config(output, config_path)
    results: list[ConversionResult] = []

    for source in analytic_rule_files(root):
        target = output / source.name
        document = build_xdr_document(source, root, config)
        rendered = yaml.dump(
            document,
            Dumper=XdrYamlDumper,
            sort_keys=False,
            allow_unicode=False,
            width=120,
        )
        if target.exists() and not overwrite:
            existing = target.read_text(encoding="utf-8")
            if existing != rendered:
                results.append(
                    ConversionResult(
                        source,
                        target,
                        "conflict",
                        (),
                        ("output exists with different content; rerun with --overwrite",),
                    )
                )
                continue
        target.write_text(rendered, encoding="utf-8", newline="\n")
        conversion = document["contentProvenance"]["conversion"]
        results.append(
            ConversionResult(
                source,
                target,
                conversion["status"],
                tuple(conversion["warnings"]),
                tuple(conversion["errors"]),
            )
        )

    summary = {
        "solution": str(root),
        "outputDirectory": str(output),
        "total": len(results),
        "converted": sum(result.status == "converted" for result in results),
        "needsReview": sum(result.status == "needsReview" for result in results),
        "conflicts": sum(result.status == "conflict" for result in results),
        "results": [result.as_dict() for result in results],
    }
    (output / "manifest.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    report_path = Path(__file__).resolve().parents[1] / "Data" / "reports" / "last-conversion.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return summary


def validate_solution(solution: str | Path) -> dict[str, Any]:
    root, _, output = solution_paths(solution)
    files = xdr_detection_files(output) if output.exists() else []
    results = []
    for path in files:
        try:
            with path.open(encoding="utf-8-sig") as handle:
                document = yaml.safe_load(handle) or {}
            errors = validate_document(document)
        except (OSError, yaml.YAMLError, ValueError) as exc:
            errors = [str(exc)]
        results.append({"file": str(path), "valid": not errors, "errors": errors})
    return {
        "solution": str(root),
        "total": len(results),
        "valid": sum(item["valid"] for item in results),
        "invalid": sum(not item["valid"] for item in results),
        "results": results,
    }


def runtime_validation_plan(solution: str | Path) -> dict[str, Any]:
    root, _, output = solution_paths(solution)
    plan = []
    for path in xdr_detection_files(output):
        with path.open(encoding="utf-8-sig") as handle:
            document = yaml.safe_load(handle) or {}
        source_path = root / document["contentProvenance"]["source"]["path"]
        with source_path.open(encoding="utf-8-sig") as handle:
            source = yaml.safe_load(handle) or {}
        plan.append(
            {
                "detection": path.name,
                "sourceRule": str(source_path),
                "sentinelQuery": str(source.get("query") or ""),
                "advancedHuntingQuery": document["properties"]["queryCondition"]["queryText"],
            }
        )
    return {
        "solution": str(root),
        "instructions": (
            "Run sentinelQuery and advancedHuntingQuery through the Microsoft Sentinel "
            "data-exploration MCP tools. Record execution errors and compare output entities."
        ),
        "rules": plan,
    }
