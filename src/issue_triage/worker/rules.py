"""Trusted rules worker: stdin data only, no tools, provider client or credential discovery."""

import json
import os
import socket
import sys

from ..judges.rules import judge_rules
from .bundle import MAX_BUNDLE_BYTES, analyze, parse_bundle


def main():
    def denied(*args, **kwargs):
        raise RuntimeError("rules_worker_network_disabled")

    socket.create_connection = denied
    socket.socket.connect = denied
    try:
        if not sys.flags.isolated or not sys.dont_write_bytecode:
            raise ValueError("isolated_bytecode_disabled_worker_required")
        data = sys.stdin.buffer.read(MAX_BUNDLE_BYTES + 1)
        bundle = parse_bundle(data)
        analysis = analyze(bundle)
        judgment = judge_rules(analysis.context)
        output = {
            "bundle_sha256": bundle.sha256,
            "judgment": judgment.model_dump(mode="json"),
            "isolated": True,
            "dont_write_bytecode": sys.dont_write_bytecode,
            "environment_names": sorted(os.environ),
            "provider_dispatch": "disabled",
        }
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        print('{"error":"rules_worker_unavailable"}')
        return 1
