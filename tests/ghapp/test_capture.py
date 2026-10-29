"""Authored transport controls only; no HTTP/account/origin or intake admission claim."""

import gzip
import hashlib
import io
import json
import tarfile
import traceback

import pytest

from issue_triage.shared.ghapp.archive import ArchiveLimits
from issue_triage.shared.ghapp.capture import (
    CapturedRepository,
    CaptureError,
    RepositoryIdentity,
    capture_repository,
)
from issue_triage.shared.ghapp.reader import ReadResponse

SHA = "a" * 40
ROOT = "https://api.github.com/repos/synthetic/demo"
TOKEN = "SYNTHETIC_CAPTURE_SECRET_CANARY"
IDENTITY = RepositoryIdentity(11, 22, "synthetic", "demo")


def archive(files=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as handle:
        for path, body in (files or {"src/main.py": b"def example(): pass\n"}).items():
            member = tarfile.TarInfo("synthetic-demo-root/" + path)
            member.size = len(body)
            handle.addfile(member, io.BytesIO(body))
    return gzip.compress(stream.getvalue(), mtime=0)


def response(value):
    return ReadResponse(200, {}, json.dumps(value).encode())


class Transport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, request, **bounds):
        self.calls.append((request, bounds))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def transport(*, metadata=None, revision=None, raw=None, redirected=True):
    values = [
        response(
            metadata
            if metadata is not None
            else {"id": 22, "full_name": "synthetic/demo", "default_branch": "main"}
        ),
        response(revision if revision is not None else {"sha": SHA}),
    ]
    if redirected:
        values.append(
            ReadResponse(
                302,
                {"location": f"https://codeload.github.com/synthetic/demo/legacy.tar.gz/{SHA}"},
                b"",
            )
        )
    values.append(ReadResponse(200, {}, archive() if raw is None else raw))
    return Transport(*values)


def capture(port=None, *, clock=lambda: 0, **kwargs):
    return capture_repository(
        IDENTITY,
        token=TOKEN,
        transport=port or transport(),
        clock=clock,
        provenance="synthetic_transport",
        **kwargs,
    )


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    import socket

    def denied(*args, **kwargs):
        pytest.fail("unexpected real socket use")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def test_fixed_calls_exact_sha_archive_auth_strip_and_immutable_manifest():
    port = transport()
    value = capture(port)
    assert [item[0].url for item in port.calls] == [
        ROOT,
        ROOT + "/commits/main",
        ROOT + "/tarball/" + SHA,
        f"https://codeload.github.com/synthetic/demo/legacy.tar.gz/{SHA}",
    ]
    assert all(item[0].headers["authorization"] == "Bearer " + TOKEN for item in port.calls[:3])
    assert "authorization" not in port.calls[3][0].headers
    assert value.commit_sha == SHA and value.provenance == "synthetic_transport"
    assert value.files == {"src/main.py": b"def example(): pass\n"}
    with pytest.raises(TypeError):
        value.files["new.py"] = b"mutated"
    manifest = json.loads(value.manifest_bytes())
    assert manifest["installation_id"] == 11 and manifest["repository_id"] == 22
    assert manifest["files"][0]["sha256"] == hashlib.sha256(value.files["src/main.py"]).hexdigest()
    assert value.manifest_sha256 == hashlib.sha256(value.manifest_bytes()).hexdigest()
    assert TOKEN not in repr(value) and TOKEN.encode() not in value.manifest_bytes()
    assert all(0 < bounds["timeout_seconds"] <= 30 for _, bounds in port.calls)


@pytest.mark.parametrize(
    "metadata",
    [
        {"id": True, "full_name": "synthetic/demo", "default_branch": "main"},
        {"id": 23, "full_name": "synthetic/demo", "default_branch": "main"},
        {"id": 22, "full_name": "other/demo", "default_branch": "main"},
        {"id": 22, "full_name": 123, "default_branch": "main"},
    ],
)
def test_repository_mismatch_stops_before_ref_or_archive(metadata):
    port = transport(metadata=metadata)
    with pytest.raises(CaptureError, match="capture_repository_mismatch"):
        capture(port)
    assert len(port.calls) == 1


@pytest.mark.parametrize(
    "branch", [None, "", "../main", "a//b", "a?b", "a#b", "a%b", "a\\b", "a\n", "x" * 256, "\ud800"]
)
def test_unsafe_metadata_branch_never_becomes_a_request(branch):
    port = transport(metadata={"id": 22, "full_name": "synthetic/demo", "default_branch": branch})
    with pytest.raises(CaptureError, match="invalid_capture_branch"):
        capture(port)
    assert len(port.calls) == 1


def test_branch_with_slash_is_one_encoded_ref_and_resolved_once():
    port = transport(
        metadata={"id": 22, "full_name": "synthetic/demo", "default_branch": "release/current"}
    )
    capture(port)
    assert port.calls[1][0].url == ROOT + "/commits/release%2Fcurrent"
    assert sum("/commits/" in request.url for request, _ in port.calls) == 1


@pytest.mark.parametrize("revision", [None, 1, "a" * 39, "a" * 64, "A" * 40, "../main"])
def test_noncanonical_revision_stops_before_archive(revision):
    port = transport(revision={"sha": revision})
    with pytest.raises(CaptureError, match="invalid_capture_revision"):
        capture(port)
    assert len(port.calls) == 2


@pytest.mark.parametrize(
    "raw", [b'{"id":22,"id":22}', b'{"id":NaN}', b"[]", b"\xff", b"{" + b"[" * 1100]
)
def test_malformed_duplicate_nonfinite_metadata_refuses(raw):
    port = Transport(ReadResponse(200, {}, raw))
    with pytest.raises(CaptureError, match="invalid_capture_metadata"):
        capture(port)
    assert len(port.calls) == 1


@pytest.mark.parametrize(
    "location",
    [
        "https://api.github.com/other",
        "https://codeload.github.com/other/demo/legacy.tar.gz/" + SHA,
        "https://codeload.github.com/synthetic/demo/legacy.tar.gz/" + "b" * 40,
        "https://codeload.github.com/synthetic/demo/legacy.tar.gz/" + SHA + "?other=1",
        "https://evil.example/secret",
    ],
)
def test_archive_redirect_scope_refuses_before_second_archive_get(location):
    port = transport()
    port.responses[2] = ReadResponse(302, {"location": location}, b"")
    with pytest.raises(CaptureError, match="capture_read_failed"):
        capture(port)
    assert len(port.calls) == 3


def test_metadata_redirect_cannot_reselect_repository():
    port = Transport(ReadResponse(302, {"location": ROOT + "/other"}, b""))
    with pytest.raises(CaptureError, match="capture_read_failed"):
        capture(port)
    assert len(port.calls) == 1


@pytest.mark.parametrize("raw", [b"bad archive", archive({"../escape.py": b"unsafe"})])
def test_archive_validation_failure_is_closed(raw):
    with pytest.raises(CaptureError, match="capture_archive_refused"):
        capture(transport(raw=raw))


def test_compressed_and_expanded_limits_preserved():
    with pytest.raises(CaptureError):
        capture(limits=ArchiveLimits(max_compressed_bytes=1))
    with pytest.raises(CaptureError, match="capture_archive_refused"):
        capture(limits=ArchiveLimits(max_expanded_bytes=512))


def test_one_budget_decreases_across_metadata_ref_and_archive():
    current = [0]
    port = transport(redirected=False)
    original = port.get

    def get(request, **bounds):
        result = original(request, **bounds)
        current[0] += 5
        return result

    port.get = get
    capture(port, clock=lambda: current[0])
    assert [bounds["timeout_seconds"] for _, bounds in port.calls] == [30, 25, 20]


def test_expiry_during_archive_parse_refuses_return(monkeypatch):
    import issue_triage.shared.ghapp.capture as module

    current = [0]
    original = module.validate_archive

    def parse(*args, **kwargs):
        value = original(*args, **kwargs)
        current[0] = 30
        return value

    monkeypatch.setattr(module, "validate_archive", parse)
    with pytest.raises(CaptureError, match="capture_deadline"):
        capture(clock=lambda: current[0])


@pytest.mark.parametrize("clock", [lambda: float("nan"), lambda: True])
def test_invalid_clock_refuses_before_transport(clock):
    port = transport()
    with pytest.raises(CaptureError, match="invalid_capture_clock"):
        capture(port, clock=clock)
    assert not port.calls


def test_transport_errors_do_not_leak_token_or_retry():
    port = Transport(RuntimeError(TOKEN))
    with pytest.raises(CaptureError) as error:
        capture(port)
    assert TOKEN not in "".join(traceback.format_exception(error.value))
    assert len(port.calls) == 1


@pytest.mark.parametrize(
    "values",
    [
        (True, 22, "synthetic", "demo"),
        (11, 0, "synthetic", "demo"),
        (11, 22, "https://evil.example", "demo"),
        (11, 22, "synthetic", "../demo"),
    ],
)
def test_approved_identity_validation(values):
    with pytest.raises(CaptureError, match="invalid_capture_repository"):
        RepositoryIdentity(*values)


@pytest.mark.parametrize("raw", [b'{"id":22,"unused":1e999}', b'{"id":22,"nested":{"x":1,"x":2}}'])
def test_nonfinite_exponent_and_nested_duplicates_refuse(raw):
    with pytest.raises(CaptureError, match="invalid_capture_metadata"):
        capture(Transport(ReadResponse(200, {}, raw)))


@pytest.mark.parametrize("status", [403, 404, 429, 500])
def test_http_refusal_stops_without_retry(status):
    port = Transport(ReadResponse(status, {}, b"untrusted error"))
    with pytest.raises(CaptureError, match="capture_read_failed"):
        capture(port)
    assert len(port.calls) == 1


def test_metadata_byte_bound_refuses_oversized_response():
    port = Transport(ReadResponse(200, {}, b" " * (1048576 + 1)))
    with pytest.raises(CaptureError, match="capture_read_failed"):
        capture(port)
    assert port.calls[0][1]["max_bytes"] == 1048576


def test_clock_failure_is_closed_and_backwards_clock_refuses():
    def failed_clock():
        raise RuntimeError(TOKEN)

    with pytest.raises(CaptureError) as error:
        capture(clock=failed_clock)
    assert TOKEN not in "".join(traceback.format_exception(error.value))
    values = iter([10, 9])
    with pytest.raises(CaptureError, match="invalid_capture_clock"):
        capture(clock=lambda: next(values))


def test_total_deadline_expiring_in_first_get_stops_before_ref():
    current = [0]
    port = transport()
    original = port.get

    def get(request, **bounds):
        result = original(request, **bounds)
        current[0] = 30
        return result

    port.get = get
    with pytest.raises(CaptureError):
        capture(port, clock=lambda: current[0])
    assert len(port.calls) == 1


def test_manifest_binds_names_and_bytes_with_deterministic_file_order():
    one = capture(transport(raw=archive({"a.py": b"one", "b.py": b"two"})))
    two = capture(transport(raw=archive({"b.py": b"two", "a.py": b"one"})))
    assert json.loads(one.manifest_bytes())["files"] == json.loads(two.manifest_bytes())["files"]
    changed = capture(transport(raw=archive({"a.py": b"changed", "b.py": b"two"})))
    renamed = capture(transport(raw=archive({"other.py": b"one", "b.py": b"two"})))
    assert one.manifest_sha256 != changed.manifest_sha256 != renamed.manifest_sha256


def test_captured_value_copies_file_map_and_rejects_mutable_content():
    files = {"a.py": b"original"}
    value = CapturedRepository(IDENTITY, SHA, "synthetic_transport", "b" * 64, "c" * 64, files)
    files["a.py"] = b"later mutation"
    assert value.files["a.py"] == b"original"
    with pytest.raises(CaptureError, match="invalid_captured_value"):
        CapturedRepository(
            IDENTITY,
            SHA,
            "synthetic_transport",
            "b" * 64,
            "c" * 64,
            {"a.py": bytearray(b"mutable")},
        )


def test_matching_cache_skips_archive_after_exact_ref_resolution():
    first = capture()
    port = transport()
    assert capture(port, cached=lambda *_: first) is first
    assert len(port.calls) == 2


def test_wrong_cache_sha_is_refused_without_archive():
    first = CapturedRepository(
        IDENTITY, "b" * 40, "synthetic_transport", "c" * 64, "d" * 64, {"a.py": b"x"}
    )
    port = transport()
    with pytest.raises(CaptureError, match="capture_cache_mismatch"):
        capture(port, cached=lambda *_: first)
    assert len(port.calls) == 2


def test_cache_failure_is_closed_and_never_falls_back_to_refetch():
    def fail(*args):
        raise RuntimeError(TOKEN)

    port = transport()
    with pytest.raises(CaptureError, match="capture_cache_failed") as error:
        capture(port, cached=fail)
    assert TOKEN not in "".join(traceback.format_exception(error.value))
    assert len(port.calls) == 2
