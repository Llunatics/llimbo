# Audit — llimbo

Audit history for `llimbo` (file carver: JPEG/PNG/GIF/PDF/ZIP from raw
images). No `AUDIT.md` existed before this audit; v1.0.0 was built
2026-11-09 and audited 2026-11-10.

## Round 1 — 2026-11-10 (v1.0.0 → v1.0.1)

Baseline: `python -m unittest discover -s tests` → 23/23 green. No prior
audit rounds; this round is the first adversarial pass.

### Findings fixed

1. **GIF carved far too short (real bug, P1).** The footer was a bare
   `3B` byte. LZW-compressed GIF data contains `3B` constantly, so a
   1.032-byte GIF carved as 66 bytes — and was still reported
   `complete`. Fix: the footer is now the two-byte pair `00 3B`
   (zero-length sub-block terminator + trailer), which a valid GIF
   always ends with. The same 1.032-byte probe now carves whole.
2. **`--max-size` cap violated for ZIP (real bug, P1).** When the EOCD
   record sat inside the cap but the archive comment ran past it, the
   carved size exceeded the cap (128 bytes carved with `--max-size 20`)
   and the file was still reported `complete`. Fix: `_find_footer`
   now returns no footer when the file's tail would run past the
   limit, so the file is cut at the cap and marked `truncated`.
   The same rework also caps the PNG CRC tail past the limit.
3. **ZIP with comment cut at EOF reported `complete` (P2).** A ZIP
   whose EOCD comment claims 100 bytes but only has 10 before EOF was
   marked `complete`. Fix: `_zip_footer_complete()` checks the full
   record + comment are present; otherwise the file is `truncated`.
   A PNG whose `IEND` lacks its 4 CRC bytes is now `truncated` too.
4. **Path traversal via `--prefix` (P2).** `--prefix "../escape"`
   wrote the recovered file outside `--out-dir`. Fix: `carve()`
   rejects any prefix containing `/` or `\` (`ValueError`), and the
   CLI reports it cleanly with exit code 2.
5. **Misleading error when `--out-dir` is an existing file (P2).**
   The failure was reported as `cannot read <image>: File exists`.
   Fix: the CLI creates the output directory up front and reports
   `cannot create <out-dir>: File exists`, exit code 2.
6. **`--types ""` / `" , "` silently wrong (P3).** An empty value
   scanned all types; a whitespace-only value scanned nothing and
   exited 10 ("nothing recovered"). Fix: both are now rejected with
   exit code 2 (`--types must name at least one type`).

### Verified safe (probed, no change)

- `--min-size` skipping a small file does not swallow a following
  large file (re-probed: large PNG after a 9-byte JPEG is found).
- JPEG footer straddling the `--max-size` cap → cut + `truncated`.
- Missing image / directory as image / unknown `--types` → clean
  exit code 2, no traceback.
- Embedded thumbnail header inside a JPEG is still skipped
  (first footer wins, documented).

### Known limitations (documented in README, not fixed)

- First footer wins for every type: a `PK 05 06` or `IEND` pattern
  inside ZIP compressed data / PNG image data cuts that file short.
- GIF trailer detection stays heuristic (`00 3B` can occur in data).
- No content validation, no reassembly of fragmented files.

### Verification

- Suite 23 → 30 tests (7 new regression tests), all green locally.
- Fresh clone post-push: suite green, CLI smoke OK.
- All six original probes re-run after the fix: GIF whole (1.032 B),
  ZIP capped at 20 + `truncated`, ZIP comment-cut `truncated`,
  prefix traversal blocked, out-dir error message correct,
  empty `--types` rejected.

## Verdict

**v1.0.1 solid.** The GIF footer and the `--max-size` cap were genuine
correctness bugs that would have bitten on real disk images; both are
fixed with regression tests. Remaining behaviour is documented
carver-class limitation, not a defect.
