"""Actual owner-local containment, link and bounded policy controls."""

import os
import subprocess

import pytest

from issue_triage.shared.rulings.store import JournalStore, PathRefused


@pytest.mark.parametrize(
    "name",
    [
        "../outside.jsonl",
        "sub/other.jsonl",
        r"sub\other.jsonl",
        "CON.jsonl",
        "NUL.jsonl",
        "C:outside.jsonl",
        ".jsonl",
    ],
)
def test_untrusted_leaf_cannot_traverse_or_target_windows_device(tmp_path, name):
    with pytest.raises(PathRefused):
        JournalStore(tmp_path, name)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "policy",
    [
        {"lock_deadline_s": True},
        {"lock_deadline_s": float("nan")},
        {"lock_deadline_s": 0},
        {"max_events": True},
        {"max_journal_bytes": 0},
    ],
)
def test_policy_bounds_are_finite_strict_and_positive(tmp_path, policy):
    with pytest.raises(ValueError):
        JournalStore(tmp_path, **policy)


def test_hardlinked_journal_and_wrong_file_type_refuse_without_external_mutation(tmp_path):
    root = tmp_path / "private"
    root.mkdir()
    target = tmp_path / "external-owned-fixture.txt"
    target.write_text("synthetic canary", encoding="utf-8")
    journal = root / "rulings.jsonl"
    os.link(target, journal)
    with pytest.raises(PathRefused):
        JournalStore(root)
    assert target.read_text() == "synthetic canary"
    journal.unlink()
    journal.mkdir()
    with pytest.raises(PathRefused):
        JournalStore(root)


def test_actual_directory_reparse_alias_refused_before_any_target_file(tmp_path):
    target = tmp_path / "owned-outside"
    target.mkdir()
    alias = tmp_path / "alias"
    # All paths are literal owned temporary paths; removing the alias never traverses its target.
    assert alias.parent.resolve() == tmp_path.resolve()
    if os.name == "nt":
        result = subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(alias), str(target)],
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, "Windows directory junction control was not created"
    else:
        os.symlink(target, alias, target_is_directory=True)
    try:
        with pytest.raises(PathRefused, match="reparse_or_symlink_refused"):
            JournalStore(alias)
        assert list(target.iterdir()) == []
    finally:
        if os.name == "nt":
            os.rmdir(alias)
        else:
            alias.unlink()


def test_windows_unc_root_refuses_before_any_filesystem_probe(monkeypatch):
    import issue_triage.shared.rulings.store as module

    if os.name == "nt":

        def no_probe(*args, **kwargs):
            raise AssertionError("remote root was probed")

        monkeypatch.setattr(module, "_not_reparse", no_probe)
        with pytest.raises(PathRefused, match="unc_or_device_root_refused"):
            JournalStore(r"\\example.invalid\share\private")


def test_windows_mapped_remote_drive_policy_refuses_before_file_probe(tmp_path, monkeypatch):
    import issue_triage.shared.rulings.store as module

    if os.name == "nt":
        monkeypatch.setattr(module, "_drive_type", lambda root: 4)

        def no_probe(*args, **kwargs):
            raise AssertionError("remote drive was probed")

        monkeypatch.setattr(module, "_not_reparse", no_probe)
        with pytest.raises(PathRefused, match="remote_drive_refused"):
            JournalStore(tmp_path)
