# llimbo

Recover deleted files from a disk image or raw file by carving on magic bytes.

Point llimbo at a disk image, a memory dump, or any raw blob and it pulls out
the files still buried inside — even when the filesystem metadata is gone.
Standard library only. No dependencies.

## Supported types

| Type | Header | Footer | Notes |
| --- | --- | --- | --- |
| JPEG | `FF D8 FF` | `FF D9` | First footer wins (see Limitations) |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `IEND` + CRC | CRC bytes are kept |
| GIF | `GIF87a` / `GIF89a` | `3B` trailer | Trailer detection is heuristic |
| PDF | `%PDF-` | `%%EOF` | |
| ZIP | `PK 03 04` | End-of-central-directory record | Archive comment is kept |

A header with no footer is still carved — up to end of input or `--max-size` —
and marked `truncated`, so a partially overwritten file is never silently lost.

## Install

```bash
pip install .
```

This installs the `llimbo` command. Or run it without installing:

```bash
python -m llimbo scan disk.dd -o recovered/
```

Requires Python 3.10+.

## Usage

```bash
llimbo scan <image> -o <out-dir> [options]
```

| Option | Default | Description |
| --- | --- | --- |
| `-o, --out-dir` | — (required) | Directory for recovered files (created if needed) |
| `--types` | all | Comma-separated subset, e.g. `jpeg,png` |
| `--min-size SIZE` | 0 | Ignore carved blobs smaller than SIZE |
| `--max-size SIZE` | none | Cap one carved file at SIZE; cut files are `truncated` |
| `--prefix` | `recovered` | Output filename prefix |
| `--json FILE` | — | Write the recovery report as JSON |
| `--quiet` | off | Print only the summary line |

Sizes accept `K`, `M`, `G` suffixes (`64K`, `10M`).

Recovered files are named `<prefix>-0001.jpg`, `<prefix>-0002.png`, and so on,
in scan order. Existing output names get a `_1`, `_2` suffix instead of being
overwritten.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scan complete, at least one file recovered |
| 10 | Scan complete, nothing recovered |
| 2 | Usage or I/O error (missing file, bad type, unwritable report) |

## Example

```bash
$ llimbo scan sd-card.dd -o recovered/ --json report.json
recovered/recovered-0001.jpg: jpeg at offset 1048576, 182344 bytes
recovered/recovered-0002.png: png at offset 2048512, 40960 bytes
recovered/recovered-0003.jpg: jpeg at offset 3097152, 91200 bytes (truncated)
scanned 16777216 bytes: 3 file(s) recovered (2 complete, 1 truncated), 0 skipped as too small
```

The JSON report records, per file: name, type, offset, size, status, and
SHA-256 — enough to verify a recovery without re-scanning the image.

## How it works

1. The input is memory-mapped, so multi-gigabyte images are scanned without
   loading them into RAM.
2. Every header occurrence is collected, then walked in offset order.
3. For each header, the matching footer is located; the bytes between them
   are written out as one file.
4. Headers inside an already-carved region are skipped, so an embedded
   thumbnail (JPEG inside JPEG) never becomes a second file.

## Limitations

- **First footer wins.** A JPEG containing an embedded thumbnail is cut at
  the thumbnail's `FF D9`, not the outer image's. The carved prefix is still
  a valid (if cropped) image.
- **GIF trailer is a single byte.** The first `3B` after the header ends the
  file, so a GIF whose image data happens to contain `3B` early is cut short.
  The other four types use multi-byte footers and do not have this problem.
- **No validation of content.** A carved file has the right magic bytes and
  footer, but llimbo does not decode the payload — a corrupted interior still
  carves as `complete`. Check recovered files with a viewer or decoder.
- **Fragmented files are not reassembled.** Files split across
  non-contiguous blocks carve as separate truncated pieces.
- **No filesystem awareness.** llimbo does not read FAT/ext4/NTFS structures;
  it works purely on raw bytes, which is exactly why it works when the
  filesystem does not.

## Tests

```bash
python -m unittest discover -s tests
```

23 tests, standard library only. Fixtures are built in-memory: a synthetic
disk image with one file of each type, a truncated JPEG, an embedded
thumbnail header, ZIP archive comments, and CLI exit-code checks.
