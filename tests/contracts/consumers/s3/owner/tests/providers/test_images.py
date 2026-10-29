"""what_bug_this_catches: changed/unbounded image buffers or unsafe path/URL fallback."""

import hashlib
import json
import struct
import zlib

import pytest

from issue_triage.shared.providers.adapters import prepare_request
from issue_triage.shared.providers.images import ImageError, validate_image
from issue_triage.shared.providers.models import GenerateRequest, ImagePart


def chunk(kind, data):
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def png(raw=b"\0\xff\0\0", width=1, height=1):
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def descriptor(content):
    digest = hashlib.sha256(content).hexdigest()
    return ImagePart(
        type="local_image",
        execution_ref="trusted:buffer-1",
        content_sha256=digest,
        media_type="image/png",
        byte_length=len(content),
        decoded_width=1,
        decoded_height=1,
        rendition_sha256=digest,
        source_generation="g1",
        transform_sha256="a" * 64,
        detail="low",
    )


def test_same_validated_bytes_payload_and_portable_identity_without_file_access(rig, monkeypatch):
    content = png()
    part = descriptor(content)
    buffer = validate_image(part, content)

    def no_open(*_args, **_kwargs):
        raise AssertionError("No image file access")

    monkeypatch.setattr("builtins.open", no_open)
    request = GenerateRequest.model_validate(
        {
            **rig.request.model_dump(mode="json", by_alias=True),
            "messages": [{"role": "user", "content": [part.model_dump(mode="json")]}],
        }
    )
    prepared = prepare_request(
        request,
        config=rig.config,
        context=rig.context(),
        limits=rig.limits,
        images={part.execution_ref: content},
    )
    body = json.loads(prepared.payload_json)
    assert body["input"][0]["content"][0]["image_url"] == buffer.data_url()
    moved = part.model_copy(update={"execution_ref": "moved:buffer-2"})
    moved_request = request.model_copy(
        update={
            "messages": [
                type(request.messages[0]).model_validate(
                    {"role": "user", "content": [moved.model_dump(mode="json")]}
                )
            ]
        }
    )
    again = prepare_request(
        moved_request,
        config=rig.config,
        context=rig.context(),
        limits=rig.limits,
        images={moved.execution_ref: content},
    )
    assert again.request_identity_sha256 == prepared.request_identity_sha256
    assert again.payload_json == prepared.payload_json


@pytest.mark.parametrize(
    "change", ["hash", "width", "length", "crc", "expanded", "pixels", "jpeg", "mutable"]
)
def test_image_validation_has_positive_magic_geometry_hash_and_decompression_bounds(change):
    content = png()
    part = descriptor(content)
    if change == "hash":
        part = part.model_copy(update={"content_sha256": "0" * 64})
    elif change == "width":
        part = part.model_copy(update={"decoded_width": 2})
    elif change == "length":
        part = part.model_copy(update={"byte_length": len(content) + 1})
    elif change == "crc":
        content = content[:-1] + bytes([content[-1] ^ 1])
        part = descriptor(content)
    elif change == "expanded":
        content = png(raw=b"\0" * 10000)
        part = descriptor(content)
    elif change == "pixels":
        content = png(width=1_000_000, height=1_000_000)
        part = descriptor(content)
    elif change == "jpeg":
        part = part.model_copy(update={"media_type": "image/jpeg"})
    else:
        content = bytearray(content)
    with pytest.raises(ImageError):
        validate_image(part, content)
