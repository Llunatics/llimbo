"""File carving engine: recover files from raw bytes by magic signature.

The input is memory-mapped, so multi-gigabyte disk images are scanned
without loading them into RAM. For each recognised file type the scanner
finds a header, then the matching footer:

- JPEG: ``FF D8 FF`` ... ``FF D9``
- PNG:  ``89 50 4E 47`` ... ``IEND`` + CRC
- GIF:  ``GIF87a`` / ``GIF89a`` ... ``00 3B`` (the trailer byte preceded by
  the zero-length sub-block terminator; see README for the caveat)
- PDF:  ``%PDF-`` ... ``%%EOF``
- ZIP:  ``PK 03 04`` ... end-of-central-directory record ``PK 05 06``
  (the record's comment length is honoured, so trailing comments are kept)

A header with no footer before end-of-input (or before ``--max-size``)
is still carved and marked ``truncated`` instead of being dropped, so a
partially overwritten file is never silently lost. A ZIP whose
end-of-central-directory record or archive comment is cut short is
likewise marked ``truncated``.
"""

from __future__ import annotations

import hashlib
import mmap
import os
from dataclasses import dataclass, field

__all__ = [
    "CarvedFile",
    "ScanResult",
    "SIGNATURES",
    "carve",
    "scan_bytes",
    "scan_file",
]

JPEG_HEADER = b"\xff\xd8\xff"
JPEG_FOOTER = b"\xff\xd9"
PNG_HEADER = b"\x89PNG\r\n\x1a\n"
PNG_FOOTER = b"IEND"
GIF87_HEADER = b"GIF87a"
GIF89_HEADER = b"GIF89a"
# GIF trailer: a valid GIF always ends its last data sub-block with a
# zero-length terminator (00) before the 3B trailer byte, so the footer
# is the two-byte pair. A bare 3B appears inside compressed image data
# far too often (1 in 256 bytes) to be a usable footer on its own.
GIF_FOOTER = b"\x00\x3b"
PDF_HEADER = b"%PDF-"
PDF_FOOTER = b"%%EOF"
ZIP_HEADER = b"PK\x03\x04"
ZIP_EOCD = b"PK\x05\x06"


@dataclass(frozen=True)
class FileType:
    """One carvable file type: header, footer, extension."""

    name: str
    headers: tuple[bytes, ...]
    footer: bytes
    footer_extra: int  # bytes after the footer pattern belonging to the file
    extension: str


def _zip_footer_end(data: bytes, footer_pos: int) -> int:
    """End offset of a ZIP archive given its EOCD record position.

    The EOCD record is 22 bytes; bytes 20-21 hold the archive comment
    length, which is part of the file. A truncated record (fewer than
    22 bytes left) ends at the end of the data.
    """
    end = footer_pos + 22
    if len(data) >= footer_pos + 22:
        comment_len = int.from_bytes(data[footer_pos + 20:footer_pos + 22], "little")
        end += comment_len
    return min(end, len(data))


SIGNATURES: tuple[FileType, ...] = (
    FileType("jpeg", (JPEG_HEADER,), JPEG_FOOTER, 0, "jpg"),
    FileType("png", (PNG_HEADER,), PNG_FOOTER, 4, "png"),
    FileType("gif", (GIF87_HEADER, GIF89_HEADER), GIF_FOOTER, 0, "gif"),
    FileType("pdf", (PDF_HEADER,), PDF_FOOTER, 0, "pdf"),
    FileType("zip", (ZIP_HEADER,), ZIP_EOCD, 0, "zip"),
)

_TYPES_BY_NAME = {t.name: t for t in SIGNATURES}


@dataclass
class CarvedFile:
    """One recovered file."""

    file_type: str
    extension: str
    offset: int
    size: int
    status: str  # "complete" or "truncated"
    sha256: str = ""
    data: bytes = field(default=b"", repr=False)


@dataclass
class ScanResult:
    """Outcome of scanning one input."""

    files: list[CarvedFile]
    skipped_too_small: int = 0
    bytes_scanned: int = 0


def _zip_footer_complete(data: bytes, footer_pos: int) -> bool:
    """True if the EOCD record and its full comment are present.

    A record cut short by end-of-input (fewer than 22 bytes left, or a
    comment length running past the data) means the archive itself is
    incomplete, even though the ``PK 05 06`` marker was found.
    """
    if len(data) < footer_pos + 22:
        return False
    comment_len = int.from_bytes(data[footer_pos + 20:footer_pos + 22], "little")
    return footer_pos + 22 + comment_len <= len(data)


def _find_footer(
    ftype: FileType, data: bytes, start: int, limit: int
) -> tuple[int, bool] | None:
    """(end offset, complete?) for the first footer, or None.

    Returns None when no footer starts within ``limit`` — including when
    the footer itself is found but the file's tail (PNG CRC, ZIP comment)
    would run past ``limit``. The caller then cuts the file at ``limit``
    and marks it ``truncated``, so ``--max-size`` is never exceeded.
    """
    pos = data.find(ftype.footer, start, limit)
    if pos == -1:
        return None
    if ftype.name == "zip":
        end = _zip_footer_end(data, pos)
        complete = _zip_footer_complete(data, pos)
    else:
        end = pos + len(ftype.footer) + ftype.footer_extra
        complete = end <= len(data)
    if end > limit:
        return None
    return end, complete


def scan_bytes(
    data: bytes,
    types: tuple[str, ...] | None = None,
    min_size: int = 0,
    max_size: int = 0,
) -> ScanResult:
    """Carve files out of an in-memory byte string.

    ``types`` limits the scan to the named types (default: all).
    ``min_size`` drops carved blobs smaller than that many bytes.
    ``max_size`` caps a single carved file; a file whose footer lies
    beyond the cap is cut at the cap and marked ``truncated``.
    """
    wanted = [t for t in SIGNATURES if types is None or t.name in types]
    if types is not None:
        unknown = sorted(set(types) - set(_TYPES_BY_NAME))
        if unknown:
            raise ValueError(f"unknown file type(s): {', '.join(unknown)}")

    # Collect every header occurrence, then walk them in offset order.
    # Headers inside an already-carved region are skipped, so an embedded
    # thumbnail (JPEG inside JPEG) never becomes a second file.
    hits: list[tuple[int, FileType]] = []
    for ftype in wanted:
        for header in ftype.headers:
            start = 0
            while True:
                pos = data.find(header, start)
                if pos == -1:
                    break
                hits.append((pos, ftype))
                start = pos + 1
    hits.sort(key=lambda h: h[0])

    files: list[CarvedFile] = []
    skipped = 0
    cursor = 0  # first offset not yet consumed by a carved file
    for offset, ftype in hits:
        if offset < cursor:
            continue
        limit = len(data)
        if max_size:
            limit = min(limit, offset + max_size)
        footer = _find_footer(ftype, data, offset + 1, limit)
        if footer is None:
            end = limit
            status = "truncated"
        else:
            end, complete = footer
            status = "complete" if complete else "truncated"
        size = end - offset
        if size < min_size:
            skipped += 1
            cursor = end
            continue
        blob = data[offset:end]
        files.append(
            CarvedFile(
                file_type=ftype.name,
                extension=ftype.extension,
                offset=offset,
                size=size,
                status=status,
                sha256=hashlib.sha256(blob).hexdigest(),
                data=blob,
            )
        )
        cursor = end
    return ScanResult(files=files, skipped_too_small=skipped, bytes_scanned=len(data))


def scan_file(
    path: str,
    types: tuple[str, ...] | None = None,
    min_size: int = 0,
    max_size: int = 0,
) -> ScanResult:
    """Carve files out of a file on disk, via mmap (no full read)."""
    size = os.path.getsize(path)
    if size == 0:
        return ScanResult(files=[], bytes_scanned=0)
    with open(path, "rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            result = scan_bytes(
                mm, types=types, min_size=min_size, max_size=max_size
            )
    return result


def carve(
    path: str,
    out_dir: str,
    types: tuple[str, ...] | None = None,
    min_size: int = 0,
    max_size: int = 0,
    prefix: str = "recovered",
) -> tuple[ScanResult, list[str]]:
    """Scan ``path`` and write every carved file into ``out_dir``.

    Returns the scan result plus the list of written file paths.
    Existing output names get a ``_1``, ``_2`` suffix instead of being
    overwritten. ``prefix`` must be a plain filename (no ``/`` or ``\\``):
    a prefix containing a separator would write outside ``out_dir``.
    """
    if "/" in prefix or "\\" in prefix:
        raise ValueError("prefix must be a plain filename, not a path: "
                         f"{prefix!r}")
    result = scan_file(path, types=types, min_size=min_size, max_size=max_size)
    os.makedirs(out_dir, exist_ok=True)
    written: list[str] = []
    for i, found in enumerate(result.files, start=1):
        base = f"{prefix}-{i:04d}.{found.extension}"
        target = os.path.join(out_dir, base)
        n = 1
        while os.path.exists(target):
            stem, ext = os.path.splitext(base)
            target = os.path.join(out_dir, f"{stem}_{n}{ext}")
            n += 1
        with open(target, "wb") as fh:
            fh.write(found.data)
        written.append(target)
    return result, written
