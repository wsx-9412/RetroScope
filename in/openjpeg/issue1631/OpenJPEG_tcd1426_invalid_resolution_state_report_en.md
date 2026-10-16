# OpenJPEG Bug Report: Invalid Decoded-Resolution State Causes READ SEGV in `opj_tcd_get_decoded_tile_size()`

Hello,

We are reporting a reproducible OpenJPEG decoder crash triggered by a malformed JPEG 2000 codestream.

Reporter attribution:

- OH HAN GUEL
- KANG DAEUN

The crash input and AddressSanitizer log are included with this report.

## Summary

A malformed JPEG 2000 codestream can reliably crash the OpenJPEG tile header decoding path under AddressSanitizer.

The reproduced crash occurs in:

```text
Function:
  opj_tcd_get_decoded_tile_size()

Observed crash location:
  src/lib/openjp2/tcd.c:1426

ASAN classification:
  SEGV

Access type:
  READ memory access
```

The immediate crash is caused by a read through a pointer derived from:

```c
l_tile_comp->resolutions + l_tile_comp->minimum_num_resolutions - 1
```

For the provided reproducer, the crash appears to be caused by an inconsistent decoded-resolution state. The relevant state appears to originate from `opj_j2k_set_decoded_resolution_factor()`, which writes `m_reduce` before validating whether the requested resolution factor is legal. In the harness used for reproduction, the function's failure return value is ignored and decoding continues. Later, `opj_tcd_init_tile()` computes `minimum_num_resolutions` from that state, which can become `0`. This is consistent with `opj_tcd_get_decoded_tile_size()` deriving a `resolutions - 1` pointer and then crashing on a read.

This report does not claim code execution. The confirmed behavior is a reproducible decoder crash / denial-of-service condition under malformed input.

## Affected Component

```text
Project:
  OpenJPEG

Git commit:
  0486b86b87a1c6adacef2d6dab92ff1d2e94ab89

Affected files:
  src/lib/openjp2/j2k.c
  src/lib/openjp2/tcd.c

Observed crash location:
  src/lib/openjp2/tcd.c:1426

Relevant functions:
  opj_j2k_set_decoded_resolution_factor()
  opj_tcd_init_tile()
  opj_tcd_get_decoded_tile_size()

Trigger binary / harness:
  /home/js/ctf_dreamhack/fuzzing/2_fuzz/openjpeg/campaign/bin/tile_header_data_partial_afl_asan

Input type:
  JPEG 2000 codestream
```

## Reproducer

Crash input included with this report:

```text
openjpeg_tcd1426_crash_input.j2k
```

Original path on the test VM:

```text
/home/js/ctf_dreamhack/fuzzing/2_fuzz/openjpeg/campaign/afl_out/tile_header_data_partial_asan_small_run2/default/crashes/id:000000,sig:11,src:000001,time:232453,execs:33544,op:arith8,pos:145,val:-3
```

Metadata:

```text
SHA-256:
  660ce4995e12714ba9ed3b19b310fd3d52a5bff27e42a3bf3690bba976083f2e

Size:
  5476 bytes
```

Reproduction command:

```bash
BIN=/home/js/ctf_dreamhack/fuzzing/2_fuzz/openjpeg/campaign/bin/tile_header_data_partial_afl_asan
CRASH="/home/js/ctf_dreamhack/fuzzing/2_fuzz/openjpeg/campaign/afl_out/tile_header_data_partial_asan_small_run2/default/crashes/id:000000,sig:11,src:000001,time:232453,execs:33544,op:arith8,pos:145,val:-3"

ASAN_OPTIONS=detect_leaks=0:symbolize=1:handle_segv=1:abort_on_error=0 \
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
"$BIN" "$CRASH" 2>&1 | tee /tmp/openjpeg_tcd1426_asan.log
```

Observed ASAN log:

```text
AddressSanitizer:DEADLYSIGNAL
=================================================================
ERROR: AddressSanitizer: SEGV on unknown address 0x615fffffffc8
The signal is caused by a READ memory access.
    #0 opj_tcd_get_decoded_tile_size
       /home/js/ctf_dreamhack/fuzzing/2_fuzz/openjpeg/src/lib/openjp2/tcd.c:1426:37
    #1 opj_j2k_read_tile_header
       /home/js/ctf_dreamhack/fuzzing/2_fuzz/openjpeg/src/lib/openjp2/j2k.c:10097:24
    #2 opj_read_tile_header
       /home/js/ctf_dreamhack/fuzzing/2_fuzz/openjpeg/src/lib/openjp2/openjpeg.c:575:16
    #3 LLVMFuzzerTestOneInput
       /home/js/ctf_dreamhack/fuzzing/2_fuzz/openjpeg/campaign/harnesses/tile_header_data_partial_fuzzer.cpp:344:10
    #4 main
       /home/js/ctf_dreamhack/fuzzing/2_fuzz/openjpeg/campaign/harnesses/tile_header_data_partial_afl_driver.cpp:50:5

SUMMARY: AddressSanitizer: SEGV
/home/js/ctf_dreamhack/fuzzing/2_fuzz/openjpeg/src/lib/openjp2/tcd.c:1426:37
in opj_tcd_get_decoded_tile_size
```

## Validated Reproducer Details

The crash input contains a `COD` marker (`0xFF52`) at offset `136`.

Observed COD payload:

```text
00000001000204040001
```

Important extracted values:

```text
byte_at_145              = 0x02
num decomposition raw    = 2
OpenJPEG numresolutions  = raw + 1 = 3
```

This matches the decoder code:

```c
opj_read_bytes(l_current_ptr, &l_tccp->numresolutions, 1);
++l_tccp->numresolutions;  /* tccp->numresolutions = read() + 1 */
```

The reproduction harness computes a decoded resolution factor from control bytes as:

```c
const OPJ_UINT32 res_factor = (OPJ_UINT32)((ctrl1 >> 4) & 0x03U);
if (res_factor > 0) {
  (void)opj_set_decoded_resolution_factor(codec, res_factor);
}
```

For this reproducer, the harness control byte yields:

```text
res_factor = 3
```

The harness ignores the return value of `opj_set_decoded_resolution_factor()`.

## Root Cause Analysis

### 1. Immediate crash location

The immediate crashing code is:

```c
l_res = l_tile_comp->resolutions + l_tile_comp->minimum_num_resolutions - 1;
...
w = (OPJ_UINT32)(l_res->x1 - l_res->x0);
```

If:

```text
l_tile_comp->minimum_num_resolutions == 0
```

then:

```text
l_res == l_tile_comp->resolutions - 1
```

The subsequent read can dereference an invalid pointer derived before the beginning of the `resolutions` array.

### 2. How `minimum_num_resolutions` is computed

`opj_tcd_init_tile()` sets:

```c
l_tilec->numresolutions = l_tccp->numresolutions;
if (l_tccp->numresolutions < l_cp->m_specific_param.m_dec.m_reduce) {
    l_tilec->minimum_num_resolutions = 1;
} else {
    l_tilec->minimum_num_resolutions =
        l_tccp->numresolutions - l_cp->m_specific_param.m_dec.m_reduce;
}
```

Therefore, if:

```text
l_tccp->numresolutions == l_cp->m_specific_param.m_dec.m_reduce
```

then:

```text
minimum_num_resolutions = 0
```

### 3. Why this sample appears to create that state

The decoded-resolution setter is:

```c
OPJ_BOOL opj_j2k_set_decoded_resolution_factor(opj_j2k_t *p_j2k,
        OPJ_UINT32 res_factor,
        opj_event_mgr_t * p_manager)
{
    p_j2k->m_cp.m_specific_param.m_dec.m_reduce = res_factor;
    ...
    if (res_factor >= max_res) {
        ...
        return OPJ_FALSE;
    }
```

This stores:

```text
m_reduce = res_factor
```

before checking whether `res_factor` is valid for the component.

For the reproducer:

```text
numresolutions = 3
res_factor     = 3
```

The validity check should fail because:

```text
res_factor >= max_res
```

However, `m_reduce` has already been written before the function returns `OPJ_FALSE`. Because the harness ignores that failure and continues decoding:

```c
(void)opj_set_decoded_resolution_factor(codec, res_factor);
```

the decoder can continue with state equivalent to:

```text
m_reduce       = 3
numresolutions = 3
```

Later tile initialization can compute:

```text
minimum_num_resolutions = 3 - 3 = 0
```

This is consistent with the later `resolutions + 0 - 1` pointer derivation and the observed READ SEGV in `opj_tcd_get_decoded_tile_size()`.

### 4. Root-cause statement

The reproduced crash is most likely a state-consistency issue:

```text
opj_j2k_set_decoded_resolution_factor() appears to store an invalid decoded resolution factor in m_reduce before validating it.
If the caller ignores the function's failure return value, the decoder can continue with inconsistent internal state.
Later, opj_tcd_init_tile() computes minimum_num_resolutions from that state, which can become zero.
opj_tcd_get_decoded_tile_size() then derives a resolutions - 1 pointer and crashes on a read.
```

This explanation is strongly supported by the reproducer values, ASAN trace, and source-level control flow. Some exact runtime locals were not directly printed because selected values were optimized out in the current ASAN build.

## Impact / Exploitability Notes

Confirmed:

```text
Malformed JPEG 2000 codestream
  -> failed decoded-resolution setter can leave inconsistent decoder state when ignored by the caller
  -> invalid pointer arithmetic in tile-resolution handling
  -> reproducible READ SEGV in decoder code
```

Current assessment:

```text
DoS / crash: reproduced
Invalid pointer derivation: strongly supported
Arbitrary write: not demonstrated
Heap corruption: not demonstrated
RIP control / RCE: not demonstrated
```

We are not making a strong claim about exploitability. At minimum, this appears to be a reproducible denial-of-service crash under malformed input.

## Suggested Fix

The safest fix appears to be validating `res_factor` before mutating decoder state.

Current order:

```c
p_j2k->m_cp.m_specific_param.m_dec.m_reduce = res_factor;
if (res_factor >= max_res) {
    return OPJ_FALSE;
}
```

Suggested order:

```c
if (res_factor >= max_res) {
    return OPJ_FALSE;
}
p_j2k->m_cp.m_specific_param.m_dec.m_reduce = res_factor;
```

Additional hardening ideas:

```text
Reject zero-result resolution windows before pointer derivation.
Validate minimum_num_resolutions before using it to derive a pointer into resolutions.
Treat a failed opj_set_decoded_resolution_factor() as fatal in callers, or restore the previous state on failure.
Add a regression test using the provided reproducer.
```

Thank you for reviewing this report.

