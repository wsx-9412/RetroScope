# RetroScope

Cross-version fork-statement localization and vulnerability-reproduction pipeline.

Given a reference build \(P_r\) (crashes on PoC \(I\)) and a target build \(P_t\)
(same input, no crash), RetroScope:

1. traces both executions (GDB by default),
2. aligns traces and finds the divergence / fork statement,
3. maps fork operands back to input-file offsets,
4. mutates those bytes and checks whether the target reproduces the reference crash.

## Requirements

System packages (Ubuntu 22.04 baseline):

```bash
sudo apt-get install -y gdb gcc g++ make cmake python3 libasan6
```

Python: **standard library only** for the default GDB pipeline
(`run_analysis.sh` without `-pt` / `-full`). No `pip install` is required.

Optional (not needed for the main experiments):

| Tool | Used by | Notes |
|------|---------|--------|
| PolyTracker + `wllvm` | `-pt` / `-full` modes, `polytracker_offsets.py` | Comparison experiment only; `polytracker/` is not required |
| `lldb` | `function_aligner.py` fallback | GDB path works without it |

## Quick start (libtiff example)

```bash
# from the repository root
./run_analysis.sh config_libtiff.py
```

Default mode is GDB-only. Flags:

```bash
./run_analysis.sh config_libtiff.py          # GDB (default)
./run_analysis.sh config_libtiff.py -pt      # PolyTracker only (optional)
./run_analysis.sh config_libtiff.py -full    # GDB + PolyTracker (optional)
./run_analysis.sh config_libtiff.py --force-compile   # rebuild version trees
```

Results are written under `results/` (JSON + per-CVE sweep logs).

## Layout

| Path | Contents |
|------|----------|
| `run_analysis.sh` | Main entry: resolves version pair + PoC, runs the pipeline |
| `config_*.py` | Per-project CVE / command / compile settings |
| `run_fork_analysis.py`, `lcs_trace.py`, `divergence_analyzer.py`, … | Pipeline stages |
| `format_profiles/` | Format-aware / coordinated candidate generation |
| `in/` | PoC corpus (fully tracked in git) |
| `*-versions/` | Per-project source + ASan builds (see below) |
| `build/` | Harness `.c` sources for projects without a CLI (e.g. FreeType) |
| `test_format_profiles.py`, `test_crash_equivalence.py` | Unit tests |
| `poc_run_commands.md` | Per-CVE experiment commands and results (paper log) |
| `paper_workflow.md` | Method write-up |

## Version trees (`*-versions/`)

Each project keeps reference/target trees next to the configs, e.g.
`tiff-versions/tiff-4.0.7` (ref) and `tiff-versions/tiff-4.0.6` (tgt).

- Trees are **not** committed to git (multi-GB ASan artifacts).
- Ship them with a **release archive** of the working tree, or rebuild from
  upstream tarballs using the `build_*.sh` helpers / config `pre_build` steps.
- Prebuilt ASan binaries for the default pairs are included when you archive
  the full folder; `run_analysis.sh` skips compilation if binaries already
  exist (`--force-compile` to rebuild).

Supported projects with a config **and** a version tree in the tree:

`libtiff`, `lame`, `audiofile`, `jasper`, `libxml2`, `giflib`, `binutils`,
`freetype`, `openjpeg`, `libredwg`, `libarchive`, `openexr`, `exiv2`, `pcre2`.

**Known gap:** `libsndfile` has `config_libsndfile.py` and PoCs under
`in/libsndfile/`, but `libsndfile-versions/` is missing (CVEs documented as
BLOCKED in `poc_run_commands.md`).

Removed from the open-source snapshot (no CVE in `poc_run_commands.md`):
`sqlite3`, `libheif`.

## Tests

```bash
python3 -m pytest test_format_profiles.py test_crash_equivalence.py
# expected: 119 passed, 1 skipped
```

## Notes

- **PolyTracker** was a side comparison, not part of the core method. The
  default pipeline never requires it.
- **openexr** rebuild (only if you `--force-compile`) expects Imath/libdeflate
  prefixes under `/tmp/imath-install` and `/tmp/libdeflate-install`; the
  default prebuilt `exrcheck` binaries work without that.
- Paths inside first-party scripts are relative to the repository root
  (`BASE_DIR`); no machine-specific absolute paths are required for the main
  pipeline.
- Experiment narrative and per-CVE tables: see `poc_run_commands.md`.
