"""Validate a restricted PNG byte buffer; no file/URL reads or image-price inference."""

import base64
import hashlib
import struct
import zlib
from dataclasses import dataclass, field

from .models import ImagePart


class ImageError(ValueError):
    """Closed diagnostics; paths and content are never interpolated."""


@dataclass(frozen=True)
class ImageBuffer:
    content: bytes = field(repr=False)
    descriptor_sha256: str

    def data_url(self) -> str:
        return "data:image/png;base64," + base64.b64encode(self.content).decode("ascii")


def validate_image(
    part: ImagePart, content: bytes, *, max_bytes=8 * 1024 * 1024, max_pixels=20_000_000
) -> ImageBuffer:
    if type(content) is not bytes or len(content) > max_bytes or len(content) != part.byte_length:
        raise ImageError("invalid_image")
    if part.media_type != "image/png":
        raise ImageError("unsupported_image_decoder")
    if hashlib.sha256(content).hexdigest() != part.content_sha256 or not content.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):
        raise ImageError("invalid_image")
    # This edition supports simple noninterlaced RGB/RGBA PNGs only. Other formats
    # need a separately installed/verified decoder, never a fake metadata assertion.
    chunks = []
    offset = 8
    while offset < len(content):
        if offset + 12 > len(content):
            raise ImageError("invalid_image")
        length = struct.unpack(">I", content[offset : offset + 4])[0]
        tag = content[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(content) or tag not in {b"IHDR", b"IDAT", b"IEND"}:
            raise ImageError("unsupported_or_invalid_png")
        data = content[offset + 8 : offset + 8 + length]
        crc = struct.unpack(">I", content[offset + 8 + length : end])[0]
        if zlib.crc32(tag + data) & 0xFFFFFFFF != crc:
            raise ImageError("invalid_image")
        chunks.append((tag, data))
        offset = end
    if (
        not chunks
        or chunks[0][0] != b"IHDR"
        or len(chunks[0][1]) != 13
        or chunks[-1] != (b"IEND", b"")
    ):
        raise ImageError("invalid_image")
    if any(tag != b"IDAT" for tag, _ in chunks[1:-1]) or len(chunks) < 3:
        raise ImageError("invalid_image")
    width, height, depth, color, compression, filters, interlace = struct.unpack(
        ">IIBBBBB", chunks[0][1]
    )
    if (
        not width
        or not height
        or width * height > max_pixels
        or (depth, color, compression, filters, interlace) not in {(8, 2, 0, 0, 0), (8, 6, 0, 0, 0)}
    ):
        raise ImageError("unsupported_or_invalid_png")
    if (width, height) != (part.decoded_width, part.decoded_height):
        raise ImageError("invalid_image")
    channels = 3 if color == 2 else 4
    row = width * channels + 1
    expected = row * height
    if expected > 64 * 1024 * 1024:
        raise ImageError("invalid_image")
    try:
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(b"".join(data for _, data in chunks[1:-1]), expected + 1)
        if (
            len(decoded) != expected
            or not decoder.eof
            or decoder.unused_data
            or decoder.unconsumed_tail
        ):
            raise ImageError("invalid_image")
        if any(decoded[index] > 4 for index in range(0, expected, row)):
            raise ImageError("invalid_image")
    except zlib.error:
        raise ImageError("invalid_image") from None
    from ..callledger.models import canonical_digest

    return ImageBuffer(content, canonical_digest(part.identity_payload()))
