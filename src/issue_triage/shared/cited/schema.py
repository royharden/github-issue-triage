"""Generate deterministic model schemas only when explicitly invoked."""

import argparse
import json
from pathlib import Path

from .models import POINTER_ADAPTER, Finding, Resolution, ResolutionContext, SourceArtifact


def schemas() -> dict[str, dict]:
    return {
        "pointer.schema.json": POINTER_ADAPTER.json_schema(),
        "finding.schema.json": Finding.model_json_schema(),
        "source.schema.json": SourceArtifact.model_json_schema(),
        "resolution.schema.json": Resolution.model_json_schema(),
        "resolution-context.schema.json": ResolutionContext.model_json_schema(),
    }


def encoded_schemas() -> dict[str, str]:
    return {
        name: json.dumps(schema, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        for name, schema in schemas().items()
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export structural cited model schemas")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in encoded_schemas().items():
        (args.out / name).write_text(text, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
