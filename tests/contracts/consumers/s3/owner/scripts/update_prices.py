"""Validate a caller-supplied snapshot and write a new local copy; no fetching or overwrite."""

import argparse
import json
from pathlib import Path

from issue_triage.shared.callledger.pricing import load_snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    snapshot = load_snapshot(args.source)
    content = json.dumps(snapshot.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    # Exclusive creation refuses accidental replacement, including same source/destination.
    with args.destination.open("x", encoding="utf-8", newline="\n") as output:
        output.write(content)
    print(f"Validated {len(snapshot.policies)} policies; snapshot {snapshot.snapshot_sha256}")
    print(f"Provenance: {snapshot.provenance.origin}; no provider access established")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
