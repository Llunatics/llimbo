"""Tests for llimbo. Standard library only; run with python -m unittest."""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from llimbo.carver import carve, scan_bytes, scan_file  # noqa: E402

JUNK = b"\x00" * 16


def make_jpeg(payload=b"JFIF-photo-data"):
    return b"\xff\xd8\xff" + payload + b"\xff\xd9"


def make_png(payload=b"PNG-image-data"):
    # Minimal structure: header + fake IHDR chunk + IEND + CRC.
    body = b"\x00\x00\x00\x0dIHDR" + payload + b"\x00\x00\x00\x00IEND\xde\xad\xbe\xef"
    return b"\x89PNG\r\n\x1a\n" + body


def make_gif(payload=b"GIF-image-data"):
    return b"GIF89a" + payload + b"\x3b"


def make_pdf(payload=b"PDF-document-data"):
    return b"%PDF-1.7\n" + payload + b"\n%%EOF"


def make_zip(payload=b"ZIP-entry-data", comment=b"hi"):
    local = b"PK\x03\x04" + payload
    eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, 0, 0, len(comment))
    return local + eocd + comment


def build_image():
    """junk | jpeg | junk | png | junk | pdf | zip | junk | gif | truncated jpeg"""
    parts = [
        (JUNK, None),
        (make_jpeg(), "jpeg"),
        (JUNK, None),
        (make_png(), "png"),
        (JUNK, None),
        (make_pdf(), "pdf"),
        (make_zip(), "zip"),
        (JUNK, None),
        (make_gif(), "gif"),
        (b"\xff\xd8\xff" + b"A" * 50, "jpeg"),  # truncated: no footer
    ]
    blob = b"".join(p for p, _ in parts)
    offsets = []
    pos = 0
    for part, kind in parts:
        if kind:
            offsets.append((kind, pos, len(part)))
        pos += len(part)
    return blob, offsets


class TestScanBytes(unittest.TestCase):
    def test_all_types_found_in_order(self):
        blob, expected = build_image()
        result = scan_bytes(blob)
        self.assertEqual(len(result.files), 6)
        self.assertEqual(result.bytes_scanned, len(blob))
        for found, (kind, offset, size) in zip(result.files, expected):
            self.assertEqual(found.file_type, kind)
            self.assertEqual(found.offset, offset)
            self.assertEqual(found.size, size)
        self.assertEqual([f.status for f in result.files],
                         ["complete"] * 5 + ["truncated"])

    def test_carved_bytes_match_source(self):
        blob, expected = build_image()
        result = scan_bytes(blob)
        for found, (kind, offset, size) in zip(result.files, expected):
            self.assertEqual(found.data, blob[offset:offset + size])

    def test_sha256_reported(self):
        import hashlib
        blob, _ = build_image()
        result = scan_bytes(blob)
        self.assertEqual(result.files[0].sha256,
                         hashlib.sha256(make_jpeg()).hexdigest())

    def test_embedded_header_inside_file_is_skipped(self):
        # First footer wins: the outer JPEG is cut at the thumbnail's
        # FFD9, and the thumbnail header itself never becomes a file.
        inner = b"\xff\xd8\xff" + b"thumb" + b"\xff\xd9"
        blob = b"\xff\xd8\xff" + inner + b"photo" + b"\xff\xd9"
        result = scan_bytes(blob)
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].size, 13)
        self.assertEqual(result.files[0].status, "complete")

    def test_types_filter(self):
        blob, _ = build_image()
        result = scan_bytes(blob, types=("png", "pdf"))
        self.assertEqual([f.file_type for f in result.files], ["png", "pdf"])

    def test_unknown_type_raises(self):
        with self.assertRaises(ValueError):
            scan_bytes(b"abc", types=("bmp",))

    def test_min_size_skips_small(self):
        blob, _ = build_image()
        result = scan_bytes(blob, min_size=10_000)
        self.assertEqual(result.files, [])
        self.assertEqual(result.skipped_too_small, 6)

    def test_max_size_truncates(self):
        blob, _ = build_image()
        result = scan_bytes(blob, max_size=10)
        self.assertTrue(all(f.size <= 10 for f in result.files))
        self.assertTrue(all(f.status == "truncated" for f in result.files))

    def test_empty_input(self):
        result = scan_bytes(b"")
        self.assertEqual(result.files, [])
        self.assertEqual(result.bytes_scanned, 0)

    def test_no_headers(self):
        result = scan_bytes(b"nothing to recover here" * 10)
        self.assertEqual(result.files, [])

    def test_zip_comment_is_kept(self):
        blob = make_zip(comment=b"archive-note")
        result = scan_bytes(blob)
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].size, len(blob))
        self.assertTrue(result.files[0].data.endswith(b"archive-note"))

    def test_zip_without_comment(self):
        blob = make_zip(comment=b"")
        result = scan_bytes(blob)
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].size, len(blob))

    def test_gif87a_header(self):
        blob = b"GIF87a" + b"old-gif-data" + b"\x3b"
        result = scan_bytes(blob)
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].file_type, "gif")


class TestScanFileAndCarve(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.image = os.path.join(self.tmp.name, "disk.dd")
        blob, _ = build_image()
        with open(self.image, "wb") as fh:
            fh.write(blob)

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan_file_matches_scan_bytes(self):
        blob, _ = build_image()
        from_file = scan_file(self.image)
        from_bytes = scan_bytes(blob)
        self.assertEqual(len(from_file.files), len(from_bytes.files))
        for a, b in zip(from_file.files, from_bytes.files):
            self.assertEqual((a.file_type, a.offset, a.size, a.status),
                             (b.file_type, b.offset, b.size, b.status))

    def test_empty_file(self):
        empty = os.path.join(self.tmp.name, "empty.dd")
        open(empty, "wb").close()
        self.assertEqual(scan_file(empty).files, [])

    def test_carve_writes_files(self):
        out = os.path.join(self.tmp.name, "out")
        result, written = carve(self.image, out)
        self.assertEqual(len(written), 6)
        self.assertEqual(
            sorted(os.path.basename(p) for p in written),
            ["recovered-0001.jpg", "recovered-0002.png", "recovered-0003.pdf",
             "recovered-0004.zip", "recovered-0005.gif", "recovered-0006.jpg"],
        )
        for path, found in zip(written, result.files):
            with open(path, "rb") as fh:
                self.assertEqual(fh.read(), found.data)

    def test_carve_never_overwrites(self):
        out = os.path.join(self.tmp.name, "out")
        carve(self.image, out)
        _, written = carve(self.image, out)
        self.assertTrue(all("_1." in os.path.basename(p) for p in written))


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.image = os.path.join(self.tmp.name, "disk.dd")
        blob, _ = build_image()
        with open(self.image, "wb") as fh:
            fh.write(blob)

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "llimbo", *args],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )

    def test_scan_exit_0_and_json_report(self):
        out = os.path.join(self.tmp.name, "out")
        report = os.path.join(self.tmp.name, "report.json")
        proc = self.run_cli("scan", self.image, "-o", out, "--json", report)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("6 file(s) recovered", proc.stdout)
        with open(report, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["recovered"], 6)
        self.assertEqual(data["bytes_scanned"], os.path.getsize(self.image))
        self.assertEqual(len(data["files"]), 6)
        self.assertEqual(data["files"][0]["type"], "jpeg")
        self.assertEqual(data["files"][-1]["status"], "truncated")
        self.assertEqual(len(data["files"][0]["sha256"]), 64)

    def test_scan_nothing_exit_10(self):
        empty = os.path.join(self.tmp.name, "clean.dd")
        with open(empty, "wb") as fh:
            fh.write(b"no files here" * 100)
        proc = self.run_cli("scan", empty, "-o",
                            os.path.join(self.tmp.name, "out"))
        self.assertEqual(proc.returncode, 10)
        self.assertIn("0 file(s) recovered", proc.stdout)

    def test_scan_missing_file_exit_2(self):
        proc = self.run_cli("scan", os.path.join(self.tmp.name, "nope.dd"),
                            "-o", os.path.join(self.tmp.name, "out"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("no such file", proc.stderr)

    def test_scan_unknown_type_exit_2(self):
        proc = self.run_cli("scan", self.image, "-o",
                            os.path.join(self.tmp.name, "out"),
                            "--types", "bmp")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unknown file type", proc.stderr)

    def test_scan_types_filter(self):
        out = os.path.join(self.tmp.name, "out")
        proc = self.run_cli("scan", self.image, "-o", out,
                            "--types", "png", "--quiet")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(os.listdir(out), ["recovered-0001.png"])

    def test_version_flag(self):
        proc = self.run_cli("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("llimbo 1.0.0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
