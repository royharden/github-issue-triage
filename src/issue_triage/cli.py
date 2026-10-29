"""Explicit fixture commands and a separate public local HTTP rehearsal. No real capture/apply."""

import argparse
import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path

from .apply.dry_run import dry_run
from .review.local import DecisionRequest, record_provisional
from .worker.bundle import MAX_BUNDLE_BYTES, parse_bundle
from .worker.local import LocalWorkflow


def read_bounded(path, limit):
    with open(path, "rb") as reader:
        data = reader.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input_byte_limit")
    return data


def sha256_argument(value):
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise argparse.ArgumentTypeError("expected a lowercase SHA256 of the input file bytes")
    return value


def read_bundle(path, expected_sha256):
    """Pin original bytes before parsing or opening a local state directory."""
    data = read_bounded(path, MAX_BUNDLE_BYTES)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("input_sha256_mismatch")
    return parse_bundle(data)


def status():
    return {
        "app": "github-issue-triage",
        "stage": "local_fixture_workflow",
        "mode": "offline",
        "dry_run": True,
        "triage_implemented": True,
        "triage_scope": "explicit_fixture_inventory_only",
        "evaluations": "not_yet_measured",
        "fixtures": "independent_corpus_sealed_agent_provisional",
        "human_authority": "not_authenticated",
        "live_apply": "unavailable",
        "implemented_components": [
            "signed_synthetic_intake",
            "durable_jobs",
            "codeindex_and_cited_report",
            "text_screen",
            "actual_scrubbed_rules_subprocess",
            "current_field_proposals",
            "canonical_S2_provisional_review",
            "idempotent_zero_write_dry_run",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Triage an explicit local fixture and rehearse review/dry-run."
    )
    parser.add_argument("--offline", action="store_true", help="Network-free status/commands.")
    commands = parser.add_subparsers(dest="command")
    triage = commands.add_parser(
        "triage", help="Submit a labelled local fixture and process one queued job."
    )
    triage.add_argument("--input", required=True)
    triage.add_argument("--input-sha256", required=True, type=sha256_argument)
    triage.add_argument("--state-dir", required=True)
    triage.add_argument("--delivery-id", required=True)
    queue = commands.add_parser("queue", help="List durable local job states.")
    queue.add_argument("--state-dir", required=True)
    show = commands.add_parser("show", help="Show current proposal and evidence pointers as JSON.")
    show.add_argument("--state-dir", required=True)
    show.add_argument("--issue", required=True)
    review = commands.add_parser(
        "review", help="Record an exact provisional rehearsal decision JSON file."
    )
    review.add_argument("--state-dir", required=True)
    review.add_argument("--decision", required=True)
    review.add_argument("--provisional", action="store_true", required=True)
    apply = commands.add_parser(
        "dry-run", help="Persist repeatable previews with zero HTTP writes."
    )
    apply.add_argument("--state-dir", required=True)
    apply.add_argument("--issue", required=True)
    apply.add_argument("--provisional", action="store_true", required=True)
    serve = commands.add_parser(
        "serve-demo", help="Serve an explicit local HTTP rehearsal with public synthetic keys."
    )
    serve.add_argument("--state-dir", required=True)
    serve.add_argument("--origin", required=True, help="Exact http://loopback:port origin.")
    capture_checks = commands.add_parser(
        "capture-check", help="Inspect retained captured work; no fetch, classification or apply."
    )
    capture_checks.add_argument("--database", required=True, help="Existing application database.")
    capture_checks.add_argument("--work-key", required=True, type=sha256_argument)
    capture_checks.add_argument("--installation-id", required=True, type=int)
    capture_checks.add_argument("--repository-id", required=True, type=int)
    capture_checks.add_argument("--owner", required=True)
    capture_checks.add_argument("--repository", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "serve-demo":
            if args.offline:
                raise ValueError("offline_flag_disallows_listener")
            from .review.http import serve_demo

            serve_demo(state_root=args.state_dir, origin=args.origin)
            return 0
        if args.command == "capture-check":
            from .shared.ghapp.capture import RepositoryIdentity
            from .store import JobStore
            from .worker.capture_checks import check_capture

            identity = RepositoryIdentity(
                args.installation_id, args.repository_id, args.owner, args.repository
            )
            # Refuse a typo instead of creating a new empty application database.
            database = Path(args.database)
            if not database.is_file():
                raise ValueError("capture_database_unavailable")
            with JobStore(database) as jobs:
                output = check_capture(jobs, identity, args.work_key).wire()
        elif args.command is None:
            output = status()
        else:
            if args.command == "triage":
                bundle = read_bundle(args.input, args.input_sha256)
            elif args.command == "review":
                decision = DecisionRequest.parse_json(read_bounded(args.decision, 65536))
            with LocalWorkflow(args.state_dir) as workflow:
                if args.command == "triage":
                    outcome = workflow.submit(bundle, args.delivery_id)
                    processed = workflow.run_once()
                    try:
                        current = workflow.result(bundle.issue.key.stable_id).model_dump(
                            mode="json"
                        )
                    except Exception:
                        current = None
                    output = {
                        "ingestion_origin": "synthetic_signed_local_bundle",
                        "intake": asdict(outcome),
                        "processed": processed is not None,
                        "result": current,
                    }
                elif args.command == "queue":
                    output = {"jobs": workflow.queue()}
                elif args.command == "show":
                    output = workflow.result(args.issue).model_dump(mode="json")
                elif args.command == "review":
                    receipt = record_provisional(workflow, decision)
                    output = {
                        "receipt": receipt.model_dump(mode="json"),
                        "authority": "agent_provisional",
                        "remote_apply_allowed": False,
                    }
                else:
                    output = {
                        "receipts": dry_run(workflow, args.issue, provisional=args.provisional),
                        "mode": "dry_run",
                        "http_writes": 0,
                    }
        print(json.dumps(output, sort_keys=True, indent=2))
        return 0
    except Exception:
        print(
            '{"status":"refused","reason":"local_command_unavailable_or_invalid","remote_apply_allowed":false}'
        )
        return 2
