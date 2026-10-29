"""Original tiny hostile archives only; no independent sealed fixtures or filesystem extraction."""

import builtins
import gzip
import hashlib
import io
import tarfile

import pytest

from issue_triage.shared.ghapp.archive import ArchiveError, ArchiveLimits, validate_archive


def make(entries, *, format=tarfile.PAX_FORMAT, pax_headers=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:", format=format, pax_headers=pax_headers) as archive:
        for name, value in entries:
            if isinstance(value, tarfile.TarInfo):
                info, content = value, b""
            else:
                info = tarfile.TarInfo(name)
                content = value
                info.size = len(content)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
    return gzip.compress(output.getvalue(), mtime=0)


def test_safe_original_binary_empty_crlf_unicode_files_never_write(monkeypatch):
    original = {
        "a.py": b"def probe():\r\n    return 1\r\n",
        "empty.py": b"",
        "b.bin": b"\x00\xff",
        "é.py": b"x=1\n",
    }
    raw = make(
        [("synthetic-root/" + path, data) for path, data in original.items()],
        pax_headers={"comment": "synthetic capture"},
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("archive attempted filesystem IO")

    monkeypatch.setattr(builtins, "open", forbidden)
    result = validate_archive(raw)
    assert dict(result.files) == original
    assert result.compressed_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.total_file_bytes == sum(map(len, original.values()))
    assert "probe" not in repr(result)
    with pytest.raises(TypeError):
        result.files["new"] = b"x"


@pytest.mark.parametrize(
    "path",
    [
        "/root/file",
        "root/../escape",
        "root/./file",
        "root//file",
        "C:/escape",
        "\\\\server\\share",
        "root/a\\b",
        "root/CON.py",
        "root/aux",
        "root/a.",
        "root/a ",
        "root/control\x01",
        "root/a:b",
    ],
)
def test_hostile_paths_are_rejected(path):
    with pytest.raises(ArchiveError, match="unsafe_archive_path"):
        validate_archive(make([(path, b"x")]))


@pytest.mark.parametrize(
    "kind",
    [
        tarfile.SYMTYPE,
        tarfile.LNKTYPE,
        tarfile.CHRTYPE,
        tarfile.BLKTYPE,
        tarfile.FIFOTYPE,
        tarfile.GNUTYPE_SPARSE,
    ],
)
def test_links_devices_fifo_and_sparse_rejected(kind):
    info = tarfile.TarInfo("root/unsafe")
    info.type = kind
    info.linkname = "../../escape"
    with pytest.raises(ArchiveError, match="unsupported_archive_type"):
        validate_archive(make([(info.name, info)]))


@pytest.mark.parametrize(
    "names",
    [("root/a.py", "root/a.py"), ("root/A.py", "root/a.py"), ("root/é.py", "root/e\u0301.py")],
)
def test_duplicate_case_and_unicode_collisions(names):
    with pytest.raises(ArchiveError, match="duplicate_or_case_colliding_path"):
        validate_archive(make([(name, b"x") for name in names]))


@pytest.mark.parametrize("names", [("root/a", "root/a/b"), ("root/a/b", "root/a")])
def test_file_directory_collisions(names):
    with pytest.raises(ArchiveError, match="file_directory_collision"):
        validate_archive(make([(name, b"x") for name in names]))


def test_multiple_roots_no_root_and_empty_archive():
    with pytest.raises(ArchiveError, match="multiple_archive_roots"):
        validate_archive(make([("one/a", b"x"), ("two/b", b"x")]))
    with pytest.raises(ArchiveError, match="missing_archive_root_directory"):
        validate_archive(make([("unrooted.py", b"x")]))
    with pytest.raises(ArchiveError, match="empty_archive"):
        validate_archive(make([]))


def test_compressed_expanded_and_file_caps_never_truncate():
    raw = make([("root/a", b"x"), ("root/b", b"y")])
    with pytest.raises(ArchiveError, match="compressed_archive_limit"):
        validate_archive(raw, limits=ArchiveLimits(max_compressed_bytes=len(raw) - 1))
    with pytest.raises(ArchiveError, match="expanded_archive_limit"):
        validate_archive(gzip.compress(b"a" * 20000), limits=ArchiveLimits(max_expanded_bytes=4096))
    with pytest.raises(ArchiveError, match="archive_file_limit"):
        validate_archive(raw, limits=ArchiveLimits(max_files=1))


def test_metadata_cap_unknown_pax_and_truncated_or_hidden_archive_tail():
    with pytest.raises(ArchiveError, match="archive_metadata_limit"):
        validate_archive(make([("root/" + "x" * 70000, b"x")]))
    with pytest.raises(ArchiveError, match="unsupported_archive_metadata"):
        validate_archive(make([("root/a", b"x")], pax_headers={"size": "1"}))
    expanded = gzip.decompress(make([("root/a", b"x")]))
    with pytest.raises(ArchiveError, match="invalid_archive_end"):
        validate_archive(gzip.compress(expanded + b"hidden-nonzero-tail"))
    with pytest.raises(ArchiveError):
        validate_archive(gzip.compress(expanded[:512]))


def test_gnu_long_names_supported_within_profile():
    path = "root/" + "nested/" * 20 + "file.py"
    result = validate_archive(make([(path, b"x=1\n")], format=tarfile.GNU_FORMAT))
    assert dict(result.files) == {path.split("/", 1)[1]: b"x=1\n"}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_files": True},
        {"max_files": 5001},
        {"max_expanded_bytes": 104857601},
        {"max_compressed_bytes": 0},
    ],
)
def test_limits_can_only_tighten(kwargs):
    with pytest.raises(ArchiveError, match="invalid_archive_limits"):
        ArchiveLimits(**kwargs)
