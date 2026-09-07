from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .converter import (
    configure_logging,
    convert_solution,
    inspect_solution,
    runtime_validation_plan,
    validate_solution,
)


def _print(value: dict) -> None:
    print(json.dumps(value, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert Microsoft Sentinel analytic rules into XDR Custom Detection YAML."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("inspect", "convert", "validate", "validation-plan"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--solution", required=True)
        if command == "convert":
            subparser.add_argument("--overwrite", action="store_true")
            subparser.add_argument("--config")

    args = parser.parse_args(argv)
    tool_root = Path(__file__).resolve().parents[1]
    configure_logging(tool_root)

    try:
        if args.command == "inspect":
            result = inspect_solution(args.solution)
        elif args.command == "convert":
            result = convert_solution(
                args.solution, overwrite=args.overwrite, config_path=args.config
            )
        elif args.command == "validate":
            result = validate_solution(args.solution)
        else:
            result = runtime_validation_plan(args.solution)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    _print(result)
    if args.command == "validate" and result["invalid"]:
        return 1
    if args.command == "convert" and (result["needsReview"] or result["conflicts"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
