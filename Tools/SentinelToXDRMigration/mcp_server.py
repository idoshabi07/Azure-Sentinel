from __future__ import annotations

import json
import sys
from pathlib import Path

TOOL_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOL_ROOT))

from mcp.server.fastmcp import FastMCP

from sentinel_xdr_migration.converter import (
    configure_logging,
    convert_solution,
    inspect_solution,
    runtime_validation_plan,
    validate_solution,
)

configure_logging(TOOL_ROOT)
mcp = FastMCP("Microsoft Sentinel to Defender XDR migration")


def _json(value: dict) -> str:
    return json.dumps(value, indent=2)


@mcp.tool()
def inspect_sentinel_solution(solution_path: str) -> str:
    """Inventory analytic rules and existing XDR Detection YAML in a solution folder."""
    return _json(inspect_solution(solution_path))


@mcp.tool()
def convert_sentinel_solution(
    solution_path: str, overwrite: bool = False, config_path: str | None = None
) -> str:
    """Convert all Analytic Rules into disabled XDR Detection YAML files."""
    return _json(
        convert_solution(solution_path, overwrite=overwrite, config_path=config_path)
    )


@mcp.tool()
def validate_xdr_detections(solution_path: str) -> str:
    """Validate XDR Detection YAML files and return actionable errors."""
    return _json(validate_solution(solution_path))


@mcp.tool()
def get_runtime_validation_plan(solution_path: str) -> str:
    """Return paired Sentinel and Advanced Hunting queries for Sentinel MCP validation."""
    return _json(runtime_validation_plan(solution_path))


if __name__ == "__main__":
    mcp.run(transport="stdio")
