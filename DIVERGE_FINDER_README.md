# Diverge Finder - standalone fork-point finder

## Features

This program finds the statement (fork point) that makes two versions of a
program take different execution paths.

### Main features:
1. Run the same program with two different input files and capture the
   function-call traces
2. Compare the two traces to find the function-call fork point
3. Single-step the fork function with GDB (when possible), or analyze the
   source code to find the fork point
4. Output detailed information about the fork point

## Usage

```bash
python3 diverge_finder.py \
    --binary /path/to/binary \
    --input-a /path/to/input_a \
    --input-b /path/to/input_b \
    --args "-arg1 value1 -i {input} output_file" \
    --timeout 300 \
    --gdb-timeout 120 \
    --output /path/to/result.json
```

### Arguments:

- `--binary`: path to the binary under test
- `--input-a`: path to the first input file (reference version)
- `--input-b`: path to the second input file (target version)
- `--args`: program argument template; `{input}` is replaced by the input
  file path
- `--timeout`: program execution timeout in seconds (default 300)
- `--gdb-timeout`: GDB execution timeout in seconds (default 120)
- `-o, --output`: output JSON file path

## Example

### Testing CVE-2022-3597 in libtiff

```bash
cd /home/ws/Desktop/RetroScope

python3 diverge_finder.py \
    --binary tiff-versions/tiff-4.0.8/tools/tiffcrop \
    --input-a in/CVE-2022-3597 \
    --input-b new-in/CVE-2022-3597-4-0-8 \
    --args "-Z 1:4,3:3 -R 90 -H 300 -i {input} /tmp/foo" \
    --timeout 60 \
    --gdb-timeout 60 \
    --output /tmp/result.json
```

### Example output

```
======================================================================
Analysis summary
======================================================================
  last matched function: _TIFFfree
  first differing function after the fork: TIFFFetchStripThing
  function actually analyzed: TIFFFetchStripThing
  fork file: libtiff/tif_dirread.c
  fork line: 3749
  fork description: in TIFFReadDirectory, input A processes the TIFFTAG_STRIPOFFSETS tag while input B processes other tags
  root cause: the TIFF tag order or content differs between the two inputs, diverging the processing path
  output file: /tmp/result.json
```

## Output format

The output JSON file contains the following information:

```json
{
  "binary": "binary file path",
  "input_a": "input file A path",
  "input_b": "input file B path",
  "args": "program arguments",
  "trace_a_length": 816,
  "trace_b_length": 1441,
  "trace_a": ["function-call sequence of trace A"],
  "trace_b": ["function-call sequence of trace B"],
  "divergence_function": "last matched function",
  "next_divergent_function": "first differing function after the fork",
  "analyzed_function": "function actually analyzed",
  "divergence_index_a": 788,
  "divergence_index_b": 788,
  "divergence_result": {
    "diverging_file": "fork file path",
    "diverging_line": 3749,
    "line_text": "content of the fork line",
    "description": "fork description",
    "root_cause": "root cause"
  }
}
```

## How it works

1. **Trace capture**: use the `-finstrument-functions` compile option and the
   `functracer.so` preload library to capture the function-call trace
2. **Fork-point search**: compare the two traces and find the first differing
   function call
3. **Fork analysis**:
   - If GDB works, single-step the fork function to find the statement that
     causes the divergence
   - If GDB fails (the program crashes), analyze the source code to find the
     fork point

## Notes

1. The program must be compiled with the `-finstrument-functions` option
2. If the program uses ASan, GDB may fail because of LeakSanitizer
3. For crashing input files, GDB may not reach the breakpoint; the program
   falls back to source analysis

## Tested CVEs

The program has been tested on the following CVEs:
- CVE-2022-3597
- CVE-2022-3627
- CVE-2022-3598
- etc.
