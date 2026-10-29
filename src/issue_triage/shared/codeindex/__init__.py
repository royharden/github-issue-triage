"""Portable deterministic code evidence foundations; no owner app or provider imports."""

from .canonical import CodeIndexError
from .inventory import InventoryEntry, InventoryReader, RawInventory, inventory_from_files
from .references import ExtractionPolicy, Query, Reference, extract_references

__all__ = [
    "CodeIndexError",
    "InventoryEntry",
    "InventoryReader",
    "RawInventory",
    "inventory_from_files",
    "ExtractionPolicy",
    "Query",
    "Reference",
    "extract_references",
]


def __getattr__(name):
    # Raw inventory/reference imports remain stdlib-only; parser binding is explicit and lazy.
    if name in {"build_index", "resolve_pointer", "CodeIndex"}:
        from . import index

        return getattr(index, name)
    if name in {"SnapshotRef", "CodePointer", "IndexPolicy"}:
        from . import models

        return getattr(models, name)
    if name in {
        "CandidatePolicy",
        "MappingAuthority",
        "TrustedMapping",
        "Resolution",
        "relevant_coverage",
    }:
        from . import resolution

        return getattr(resolution, name)
    if name in {
        "ExistenceReport",
        "ReportItemRef",
        "build_existence_report",
        "resolve_report_item",
    }:
        from . import report

        return getattr(report, name)
    if name in {"to_cited_file", "to_cited_report", "CodeIndexCitedResolver", "install_codeindex"}:
        from . import cited_adapter

        return getattr(cited_adapter, name)
    raise AttributeError(name)
