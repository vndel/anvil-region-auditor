"""Command-line entry point and report renderers."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys
from .scan import scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only inventory and structural checks for Minecraft .mca files")
    parser.add_argument("path", type=Path, help="world directory, region directory, or one .mca file")
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text", dest="output_format")
    parser.add_argument("--output", type=Path, help="write report to this file; default is stdout")
    parser.add_argument("--include-entities", action="store_true", help="also scan world/entities")
    parser.add_argument("--include-poi", action="store_true", help="also scan world/poi")
    return parser


def render_text(reports: list[tuple[str, object]]) -> str:
    lines = ["kind\tpath\tbytes\tchunks\terrors\twarnings"]
    for kind, report in reports:
        lines.append(f"{kind}\t{report.path}\t{report.file_bytes}\t{report.allocated_slots}\t{report.errors}\t{report.warnings}")
        for finding in report.findings:
            suffix = f" (slot {finding.slot})" if finding.slot is not None else ""
            lines.append(f"  {finding.severity.upper()} {finding.code}{suffix}: {finding.message}")
    return "\n".join(lines) + "\n"


def render_json(reports: list[tuple[str, object]]) -> str:
    payload = {"regions": [{"kind": kind, **report.to_dict()} for kind, report in reports]}
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_csv(reports: list[tuple[str, object]]) -> str:
    from io import StringIO
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=("kind", "path", "region_x", "region_z", "file_bytes", "allocated_slots", "errors", "warnings"))
    writer.writeheader()
    for kind, report in reports:
        writer.writerow({"kind": kind, "path": report.path, "region_x": report.region_x, "region_z": report.region_z, "file_bytes": report.file_bytes, "allocated_slots": report.allocated_slots, "errors": report.errors, "warnings": report.warnings})
    return output.getvalue()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        reports = scan(args.path, args.include_entities, args.include_poi)
        rendered = {"text": render_text, "json": render_json, "csv": render_csv}[args.output_format](reports)
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (OSError, PermissionError) as exc:
        print(f"anvil-audit: {exc}", file=sys.stderr)
        return 2
    return 1 if any(report.errors for _, report in reports) else 0
