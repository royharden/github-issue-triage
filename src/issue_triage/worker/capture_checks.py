"""Read-only reference checks of a bound retained capture; no fixture or Git-auth upgrade."""

from dataclasses import dataclass, field

from ..ingest.capture import CaptureIntake, RetainedCapture
from ..shared.codeindex.canonical import canonical_bytes, digest
from ..shared.codeindex.index import CodeIndex, build_index
from ..shared.codeindex.inventory import InventoryReader, inventory_from_files
from ..shared.codeindex.models import SnapshotRef
from ..shared.codeindex.report import ExistenceReport, build_existence_report
from ..shared.ghapp.capture import RepositoryIdentity
from ..store import JobStore, StoreError


@dataclass(frozen=True, slots=True)
class CaptureChecks:
    """Original stored identity plus a canonical report, without processing authority."""

    retained: RetainedCapture = field(repr=False)
    report: ExistenceReport = field(repr=False)
    index: CodeIndex = field(repr=False)

    def wire(self):
        value = self.retained
        return {
            "capture_checks_schema_version": 1,
            "work_key": value.work_key,
            "issue_key": value.issue.key.stable_id,
            "issue_sha256": value.issue.sha256,
            "capture": {
                "source_kind": "retained_capture",
                "snapshot_id": value.snapshot_id,
                "captured_at": value.captured_at,
                "commit_sha": value.commit_sha,
                "inventory_sha256": value.inventory_sha256,
                "provenance": value.provenance,
                "authenticated_github_origin": False,
            },
            "report_sha256": self.report.sha256,
            "report": self.report.wire(),
            "authority": "retained_input_reference_checks_only",
            "current_processing_authority": False,
            "s5_cited_proposals_supported": False,
        }

    def canonical_bytes(self):
        return canonical_bytes(self.wire())

    @property
    def sha256(self):
        return digest(self.wire())


def check_capture(jobs: JobStore, identity: RepositoryIdentity, work_key: str) -> CaptureChecks:
    """Use accepted loader integrity checks; never accept caller files or source refs.

    The caller already owns the open store and configured repository identity. This
    function opens no database and changes no job, lease, result or receipt. Historical
    captures are inspectable; current issue/lease checks belong to future processing.
    """
    if type(jobs) is not JobStore or type(identity) is not RepositoryIdentity:
        raise StoreError("invalid_capture_check_input")
    retained = CaptureIntake(jobs, identity).load(work_key)
    inventory = inventory_from_files(retained.capture.files)
    if inventory.sha256 != retained.inventory_sha256:
        raise StoreError("stored_capture_inventory_mismatch")
    snapshot = SnapshotRef(
        f"github-repository-{identity.repository_id}",
        "retained_capture",
        retained.snapshot_id,
        retained.inventory_sha256,
        retained.captured_at,
        True,
    )
    index = build_index(snapshot, InventoryReader(inventory, retained.capture.files))
    report = build_existence_report(index, retained.issue.model_bound_text)
    return CaptureChecks(retained, report, index)
