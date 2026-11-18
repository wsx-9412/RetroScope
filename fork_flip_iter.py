#!/usr/bin/env python3
"""Iterative fork-flip mutation (runs only when a mutation round found no match).

When every mutation stage of a round fails to reproduce the reference crash,
the mutations that CHANGED the target's behavior (fork flips) crossed one
fork guard.  Re-run the fork localization + mutation pipeline on those
flipped inputs: the next guard in the chain becomes the new last fork and can
be flipped in turn, until a mutation reproduces the reference crash.

Round flow (identical to the per-round pipeline in run_analysis.sh):
  1. harvest flip candidates from the round's fork_trace_result.json
     (field-combo flips, single-byte flips, pairwise flips),
  2. for each candidate (deduplicated, capped):
       a. write the flipped input under out/<cve>-flips/,
       b. python3 run_fork_analysis.py --config ... --input flipped
          (reuses the already-built binaries),
       c. python3 trace_fork_offsets.py --trace-json <round>.diverge.json,
       d. check fork_trace_result.json of the flipped input for a match,
  3. candidates that only flipped again become the next round's bases.

Terminates with exit 0 as soon as the target reproduces the reference crash,
or with exit 1 when no flip candidates exist, the round limit is reached, or
a fork location repeats (no progress).
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent

_MAX_ROUNDS = 3
_MAX_CANDIDATES = 3


def _executable_lines(binary, src_file, line_numbers, timeout=90):
    """Which of ``line_numbers`` map to code in ``binary`` (gdb info line)."""
    cmd = ['gdb', '-batch', '-nx', '-q', str(binary)]
    for ln in line_numbers:
        cmd += ['-ex', f'info line {src_file}:{ln}']
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             errors='replace', timeout=timeout)
    except Exception:
        return []
    text = (out.stdout or '') + (out.stderr or '')
    base = os.path.basename(src_file)
    pat = re.compile(
        r'Line\s+(\d+)\s+of\s+"?' + re.escape(base) + r'"?.{0,80}'
        r'starts at address', re.I)
    exec_lines = [int(m.group(1)) for m in pat.finditer(text)]
    return sorted(set(exec_lines))


def _first_hit_line(binary, src_file, lines, args, timeout=120):
    """Break on every line (in order), run, return the first hit's line."""
    cmd = ['gdb', '-batch', '-nx', '-q', str(binary)]
    for ln in lines:
        cmd += ['-ex', f'break {src_file}:{ln}']
    run_cmd = 'run ' + ' '.join(shlex.quote(str(a)) for a in (args or []))
    cmd += ['-ex', run_cmd]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             errors='replace', timeout=timeout)
    except Exception:
        return None
    text = (out.stdout or '') + (out.stderr or '')
    base = os.path.basename(src_file)
    hit_re = re.compile(
        r'Breakpoint\s+(\d+),.*?\bat\s+'
        rf'(?:{re.escape(src_file)}|{re.escape(base)}):(\d+)', re.S)
    m = hit_re.search(text)
    if not m:
        return None
    bp_no = int(m.group(1)) - 1
    if 0 <= bp_no < len(lines):
        return lines[bp_no]
    return None


def _eval_cond(binary, src_file, line, cond, args, timeout=120):
    """GDB: break at the fork statement, evaluate ``cond``, return its value."""
    cmd = ['gdb', '-batch', '-nx', '-q', str(binary),
           '-ex', f'break {src_file}:{line}',
           '-ex', 'run ' + ' '.join(shlex.quote(str(a)) for a in (args or [])),
           '-ex', f'print {cond}']
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             errors='replace', timeout=timeout)
    except Exception:
        return None
    text = (out.stdout or '') + (out.stderr or '')
    m = re.search(r'\$\d+\s*=\s*(.*)', text)
    return m.group(1).strip() if m else None


def _verify_fork_crossing(div, cur_input, changes, workdir, timeout=120):
    """Does the mutated input actually CROSS the located fork point?

    Termination forks (target exits while the reference continues): crossed
    iff the mutated run does NOT execute the fork's exit line but reaches a
    later executable line of the same function.  Condition forks: crossed
    iff the fork condition evaluates differently on the mutated input.
    Returns (crossed, detail).
    """
    binary = div.get('binary_b')
    fork_file = (div.get('root_cause_file_b') or div.get('fork_file')
                 or div.get('root_cause_file'))
    fork_line = div.get('root_cause_line_b') or div.get('root_cause_line')
    args_b = div.get('args_b') or []
    if not (binary and fork_file and fork_line and cur_input):
        return False, 'no fork location in the divergence result'

    data = bytearray(open(cur_input, 'rb').read())
    for off, val in changes:
        if 0 <= off < len(data):
            data[off] = int(val) & 0xff
    from trace_fork_offsets import _scratch_dir
    fd, tmp_path = tempfile.mkstemp(
        suffix=os.path.splitext(cur_input)[1] or '.bin', prefix='flipchk_',
        dir=_scratch_dir())
    os.close(fd)
    try:
        with open(tmp_path, 'wb') as f:
            f.write(bytes(data))
        try:
            from trace_fork_offsets import _replace_input_arg
            margs = [_replace_input_arg(a, tmp_path, cur_input)
                     for a in args_b]
        except Exception:
            margs = [tmp_path if a == cur_input else a for a in args_b]

        if div.get('target_termination_fork'):
            # The fork is the target's exit/abort statement.  Crossed = the
            # mutated run passes it and reaches a later line of the same
            # function; NOT crossed = it still hits the exit, or stops
            # before the fork entirely.
            cand_lines = [fork_line] + list(range(fork_line + 1,
                                                  fork_line + 13))
            exec_lines = _executable_lines(binary, fork_file, cand_lines,
                                           timeout)
            after_lines = [ln for ln in exec_lines
                           if ln != fork_line][:4]
            if not after_lines:
                return True, ('unverifiable (no executable line after the '
                              'exit) — keeping the behavioral flip')
            hit = _first_hit_line(binary, fork_file,
                                  [fork_line] + after_lines, margs, timeout)
            if hit is None:
                return False, (f'stopped before the fork '
                               f'({os.path.basename(fork_file)}:{fork_line} '
                               f'not reached)')
            if hit == fork_line:
                return False, (f'still executes the fork exit '
                               f'{os.path.basename(fork_file)}:{fork_line}')
            return True, (f'passed the fork exit; reached '
                          f'{os.path.basename(fork_file)}:{hit}')

        # Condition fork: the fork statement is a branch; crossed iff its
        # condition evaluates differently than on the original input.
        cond = None
        try:
            from trace_fork_offsets import _fork_condition_expr
            cond = _fork_condition_expr(div.get('fork_statement') or '')
        except Exception:
            cond = None
        if not cond:
            return True, ('unverifiable (no fork condition) — keeping the '
                          'behavioral flip')
        try:
            from trace_fork_offsets import _replace_input_arg
            oargs = [_replace_input_arg(a, cur_input, cur_input)
                     for a in args_b]
        except Exception:
            oargs = args_b
        val_orig = _eval_cond(binary, fork_file, fork_line, cond, oargs,
                              timeout)
        val_mut = _eval_cond(binary, fork_file, fork_line, cond, margs,
                             timeout)
        if val_orig is None or val_mut is None:
            return True, ('fork condition unreadable under GDB — keeping '
                          'the behavioral flip')
        if val_orig != val_mut:
            return True, f'fork condition flipped: {val_orig} -> {val_mut}'
        return False, f'fork condition unchanged ({val_orig})'
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _trace_result_json(input_file):
    return os.path.join(
        os.path.dirname(os.path.abspath(input_file)) or '.',
        'fork_trace_result.json')


def _round_matched(input_file):
    """Did the round on ``input_file`` reproduce the reference crash?"""
    tj = _trace_result_json(input_file)
    if os.path.isfile(tj):
        try:
            with open(tj) as f:
                d = json.load(f)
            if d.get('mutation_any_match'):
                return True
        except Exception:
            pass
    return False


def _parse_pair_key(pair_key):
    """'0x16+0x17' -> [0x16, 0x17]; None when unparseable."""
    try:
        return [int(t, 16) for t in str(pair_key).split('+')]
    except (TypeError, ValueError):
        return None


def harvest_flips(input_file):
    """Collect (changes, source) flip candidates from a round's trace result.

    ``changes`` = [(offset, byte_value), ...] applied to the round's input.
    """
    tj = _trace_result_json(input_file)
    if not os.path.isfile(tj):
        return []
    try:
        with open(tj) as f:
            d = json.load(f)
    except Exception:
        return []
    flips = []
    seen = set()

    def add(changes, src):
        norm = []
        for item in changes or []:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                return
            try:
                norm.append((int(item[0]), int(item[1])))
            except (TypeError, ValueError):
                return
        key = tuple(sorted(norm))
        if not key or key in seen:
            return
        seen.add(key)
        flips.append({'changes': norm, 'source': src})

    fcr = d.get('field_combo_results') or {}
    for f in fcr.get('flips') or []:
        add(f.get('changes'), 'field_combo')

    for off, info in (d.get('crash_results') or {}).items():
        if not isinstance(info, dict):
            continue
        try:
            off = int(off)
        except (TypeError, ValueError):
            continue
        for v in info.get('fork_flip') or []:
            add([(off, v)], 'single_byte')

    for pk, info in (d.get('pairwise_results') or {}).items():
        if not isinstance(info, dict):
            continue
        offs = _parse_pair_key(pk)
        if not offs:
            continue
        for combo in info.get('fork_flip') or []:
            if isinstance(combo, (list, tuple)) and len(combo) == len(offs):
                add(list(zip(offs, combo)), 'pairwise')
    return flips


def _apply_changes(input_file, changes, out_path):
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())
    for off, val in changes:
        if 0 <= off < len(data):
            data[off] = val & 0xff
    with open(out_path, 'wb') as f:
        f.write(bytes(data))


def _matched_changes(trace_json_path, round_input):
    """Byte changes of the FIRST matching mutation in a round's trace result.

    Returns (changes, stage_label) where ``changes`` = [(offset, value), ...]
    relative to ``round_input``, or (None, 'unknown') when no match is
    recorded.  The round's final artifact is diffed against the round input
    for stages whose match dicts do not carry explicit byte changes (P0).
    """
    try:
        with open(trace_json_path) as f:
            d = json.load(f)
    except Exception:
        return None, 'unknown'
    changes = None
    stage = 'unknown'

    def _take(cands, label):
        nonlocal changes, stage
        if changes is None and cands:
            changes = cands
            stage = label

    fc = d.get('field_combo_results') or {}
    _take(fc.get('matches', [None])[0].get('changes') if fc.get('matches')
          else None, 'Step 6g')
    ff = d.get('format_field_results') or {}
    _take(ff.get('matches', [None])[0].get('changes') if ff.get('matches')
          else None, 'Step 6h')
    for off, info in (d.get('crash_results') or {}).items():
        if changes is not None:
            break
        if isinstance(info, dict) and info.get('matches'):
            try:
                bv = next(iter(info['matches']))
                _take([[int(off), int(bv)]], 'Step 6')
            except Exception:
                pass
    for pk, info in (d.get('pairwise_results') or {}).items():
        if changes is not None:
            break
        if isinstance(info, dict) and info.get('matches'):
            offs = _parse_pair_key(pk)
            try:
                va, vb = next(iter(info['matches'])).split(',')
                _take([[offs[0], int(va, 16)], [offs[1], int(vb, 16)]],
                      'Step 6b')
            except Exception:
                pass
    mc = d.get('multi_combo_results') or {}
    if changes is None and mc.get('match'):
        try:
            _take([[int(o), int(v)] for o, v in mc['match'].get('combo')
                   or []], 'Step 6e')
        except Exception:
            pass
    if changes is None:
        em = d.get('extended_mutation_results') or {}
        ms = em.get('matches') or []
        if ms and ms[0].get('saved') and round_input \
                and os.path.isfile(round_input):
            saved = ms[0]['saved']
            if saved and os.path.isfile(saved):
                try:
                    base = open(round_input, 'rb').read()
                    end = open(saved, 'rb').read()
                    ch = [[i, end[i]] for i in range(min(len(base), len(end)))
                          if base[i] != end[i]]
                    _take(ch, f"Step 6f ({ms[0].get('operator')}:"
                             f"{ms[0].get('detail')})")
                except Exception:
                    pass
        if changes is None and ms:
            det = ms[0].get('detail') or ''
            pat = re.findall(r'@(0x[0-9a-fA-F]+)=(\d+)', det)
            if pat:
                _take([[int(o, 16), int(v) & 0xff] for o, v in pat],
                      f"Step 6f ({ms[0].get('operator')}:{ms[0].get('detail')})")
    if changes is None:
        return None, 'unknown'
    return [[int(o), int(v) & 0xff] for o, v in changes], stage


def _chain_json_path(input_file):
    return os.path.join(
        str(BASE), 'results',
        f'{os.path.basename(input_file)}_fork_flip_chain.json')


def _save_chain(chain, input_file):
    """Persist the successful fork-flip mutation chain for the final report."""
    try:
        path = _chain_json_path(input_file)
        with open(path, 'w') as f:
            json.dump({'input': input_file, 'status': 'success',
                       'chain': chain}, f, indent=2)
        print(f'  [flip] chain saved to: {path}')
    except Exception as e:
        print(f'  [flip] could not save chain json: {e}')


def _save_status(status, input_file, note=''):
    """Persist a non-success status for the final report."""
    try:
        path = _chain_json_path(input_file)
        with open(path, 'w') as f:
            json.dump({'input': input_file, 'status': status,
                       'note': note}, f, indent=2)
    except Exception:
        pass


def run_round(config, ref, target, input_file, out_json, extra_args):
    """Run fork localization (divergence analysis) on ``input_file``.

    Returns the diverge JSON path written by lcs_trace.py.
    """
    cmd = [
        sys.executable, '-u', str(BASE / 'run_fork_analysis.py'),
        '--config', config, '--ref', ref, '--target', target,
        '--input', input_file, '--output', out_json,
        '--no-polytracker',
    ]
    cmd += [str(a) for a in extra_args]
    print(f'  [flip-round] run_fork_analysis: {" ".join(cmd)}')
    r = subprocess.run(cmd, cwd=str(BASE))
    if r.returncode != 0:
        print(f'  [!] run_fork_analysis failed (rc={r.returncode})')
    return str(Path(out_json).with_suffix('.diverge.json'))


def run_mutation(diverge_json, timeout):
    """Run the offset-localization + mutation stages on the diverge JSON."""
    cmd = [
        sys.executable, '-u', str(BASE / 'trace_fork_offsets.py'),
        '--trace-json', diverge_json, '--timeout', str(timeout),
    ]
    print(f'  [flip-round] trace_fork_offsets: {" ".join(cmd)}')
    r = subprocess.run(cmd, cwd=str(BASE))
    return r.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config', required=True)
    ap.add_argument('--ref', required=True)
    ap.add_argument('--target', required=True)
    ap.add_argument('--input', required=True)
    ap.add_argument('--trace-json', default=None,
                    help='round-0 diverge JSON (original input), used for '
                         'the format-field resort when round 1 has no flips')
    ap.add_argument('--max-rounds', type=int, default=_MAX_ROUNDS)
    ap.add_argument('--max-candidates', type=int, default=_MAX_CANDIDATES)
    ap.add_argument('--timeout', type=int, default=60)
    ap.add_argument('--out-dir', default=None,
                    help='directory for flipped base inputs '
                         '(default: out/<input-name>-flips/)')
    # Extra arguments passed through to run_fork_analysis.py per round
    # (e.g. --match-level name --refactor-detect --gdb-timeout 300).
    a, unknown = ap.parse_known_args()
    a.extra_args = unknown

    base_input = os.path.abspath(a.input)
    out_root = a.out_dir or os.path.join(
        str(BASE), 'out', f'{os.path.basename(base_input)}-flips')
    os.makedirs(out_root, exist_ok=True)

    print('=' * 60)
    print('  Fork-flip iteration (no match from the mutation stages)')
    print('=' * 60)
    print(f'  config     : {a.config}')
    print(f'  ref        : {a.ref}')
    print(f'  target     : {a.target}')
    print(f'  base input : {base_input}')
    print(f'  max rounds : {a.max_rounds}, max candidates: {a.max_candidates}')

    seen_forks = set()
    cur_input = base_input
    chain = []
    last_diverge_json = getattr(a, 'trace_json', None)
    _t0 = time.time()

    def _final_artifact(chain_steps):
        """Write the ORIGINAL input + every round's cumulative byte changes
        into the main mutation out dir under the legacy naming convention
        (all offsets/values joined), and return its path."""
        try:
            from trace_fork_offsets import _mutation_out_dir
        except Exception:
            _mutation_out_dir = None
        version = None
        if last_diverge_json and os.path.isfile(last_diverge_json):
            try:
                with open(last_diverge_json) as f:
                    version = json.load(f).get('version_b')
            except Exception:
                version = None
        full = []
        for step in chain_steps:
            full += step.get('changes') or []
            full += step.get('match_changes') or []
        name = ':'.join(f'0x{off:x}:-0x{val:02x}' for off, val in full)
        name += f':time:{int(round(time.time() - _t0))}'
        out_dir = (_mutation_out_dir(base_input, version) if _mutation_out_dir
                   else os.path.join(str(BASE), 'out',
                                     os.path.basename(base_input)))
        try:
            data = bytearray(open(base_input, 'rb').read())
            for off, val in full:
                if 0 <= off < len(data):
                    data[off] = int(val) & 0xff
            os.makedirs(out_dir, exist_ok=True)
            path = os.path.join(out_dir, name)
            with open(path, 'wb') as f:
                f.write(bytes(data))
            return path
        except Exception as e:
            print(f'  [flip] could not write the final artifact: {e}')
            return None

    def _report_success(step_extra=None):
        if step_extra:
            chain.append(step_extra)
        print('\n  [flip] SUCCESS: target reproduces the reference crash')
        print('  [flip] mutation chain (offsets/values per round):')
        for step in chain:
            if step.get('source') == 'format-fields':
                mch = step.get('match_changes')
                if mch:
                    mdesc = ' '.join(f'0x{off:x}->0x{val:02x}'
                                     for off, val in mch)
                    print(f"    round {step['round']} format-fields resort: "
                          f"match {mdesc} [{step.get('match_stage')}] -> "
                          f'{os.path.basename(step["input"])}')
                else:
                    print(f"    round {step['round']} format-fields resort -> "
                          f'{os.path.basename(step["input"])}')
                continue
            desc = ' '.join(f'0x{off:x}->0x{val:02x}'
                            for off, val in step.get('changes') or [])
            mch = step.get('match_changes')
            if mch:
                mdesc = ' '.join(f'0x{off:x}->0x{val:02x}'
                                 for off, val in mch)
                print(f"    round {step['round']} cand {step['candidate']}: "
                      f"flip {desc}; match {mdesc} "
                      f"[{step.get('match_stage')}] -> "
                      f'{os.path.basename(step["input"])}')
            else:
                print(f"    round {step['round']} cand {step['candidate']}: "
                      f"flip {desc} -> {os.path.basename(step['input'])}")
        final = _final_artifact(chain)
        if final:
            print(f'  [flip] final artifact (original + all rounds): {final}')
        _save_chain(chain, base_input)
        sys.exit(0)

    def _format_field_resort(base_input_for_resort):
        """Step 6h: the fork-driven chain stalled — rewrite whole format
        header fields as the final resort on the current base input."""
        dj = last_diverge_json
        if not dj or not os.path.isfile(dj):
            return False
        cmd = [sys.executable, '-u', str(BASE / 'trace_fork_offsets.py'),
               '--trace-json', dj, '--only-format-fields',
               '--timeout', str(a.timeout)]
        print(f'  [flip] format-field resort: {" ".join(cmd)}')
        subprocess.run(cmd, cwd=str(BASE))
        return _round_matched(base_input_for_resort)

    def _resort_step(cur, round_no):
        tj = os.path.join(os.path.dirname(os.path.abspath(cur)) or '.',
                          'fork_trace_result.json')
        mch, mstage = _matched_changes(tj, cur)
        return {'round': round_no, 'candidate': -1, 'input': cur,
                'changes': [], 'match_changes': mch,
                'match_stage': mstage, 'source': 'format-fields'}

    for round_no in range(1, a.max_rounds + 1):
        print(f'\n--- Round {round_no}: input {os.path.basename(cur_input)} ---')
        flips = harvest_flips(cur_input)
        if not flips:
            print('  [flip] no fork-flip candidates — trying the '
                  'format-field resort.')
            if _format_field_resort(cur_input):
                _report_success(_resort_step(cur_input, round_no))
            _save_status('no_flips', base_input)
            sys.exit(1)
        print(f'  [flip] {len(flips)} candidate(s):')
        for f in flips:
            desc = ' '.join(f'0x{off:x}->0x{val:02x}' for off, val in f['changes'])
            print(f'    - {desc}  ({f["source"]})')

        # Verify each candidate against the located fork point: the
        # mutation must actually CROSS it (termination fork: the target no
        # longer executes the fork's exit line; condition fork: the fork
        # condition flips).  Behavior-only changes are dropped here.
        if last_diverge_json and os.path.isfile(last_diverge_json):
            try:
                with open(last_diverge_json) as f:
                    _div0 = json.load(f)
            except Exception:
                _div0 = {}
            _fork_desc = (_div0.get('root_cause_file_b')
                          or _div0.get('fork_file') or '?')
            _fork_ln = _div0.get('root_cause_line_b') \
                or _div0.get('root_cause_line')
            print(f'  [flip] verifying candidates against the fork point '
                  f'({os.path.basename(str(_fork_desc))}:{_fork_ln}'
                  f'{", exit" if _div0.get("target_termination_fork") else ""}):')
            verified = []
            for f in flips:
                crossed, detail = _verify_fork_crossing(
                    _div0, cur_input, f['changes'], out_root, a.timeout)
                desc = ' '.join(f'0x{off:x}->0x{val:02x}'
                                for off, val in f['changes'])
                if crossed:
                    verified.append(f)
                print(f'    - {desc}: '
                      f'{"CROSSED" if crossed else "NOT crossed"} ({detail})')
            dropped = len(flips) - len(verified)
            if dropped:
                print(f'  [flip] {dropped} candidate(s) did not cross the '
                      f'fork and were dropped')
            flips = verified
        else:
            print('  [flip] no divergence result to verify against — using '
                  'behavioral flips as-is')

        if not flips:
            print('  [flip] no candidate crossed the fork point — trying '
                  'the format-field resort.')
            if _format_field_resort(cur_input):
                _report_success(_resort_step(cur_input, round_no))
            _save_status('no_flips', base_input)
            sys.exit(1)
        print(f'  [flip] {len(flips)} verified fork-crossing candidate(s)')

        progress = False
        for cand_no, flip in enumerate(flips[:a.max_candidates]):
            name = f'round{round_no}_cand{cand_no}_{os.path.basename(base_input)}'
            flipped = os.path.join(out_root, name)
            _apply_changes(cur_input, flip['changes'], flipped)

            out_json = str(BASE / 'results' / (
                f'{os.path.splitext(os.path.basename(base_input))[0]}'
                f'_flip_r{round_no}c{cand_no}.json'))
            diverge_json = run_round(
                a.config, a.ref, a.target, flipped, out_json, a.extra_args)
            if not os.path.isfile(diverge_json):
                print(f'  [!] no diverge result for {name}; skipping')
                continue
            run_mutation(diverge_json, a.timeout)

            if _round_matched(flipped):
                tj = os.path.join(
                    os.path.dirname(os.path.abspath(flipped)) or '.',
                    'fork_trace_result.json')
                mch, mstage = _matched_changes(tj, flipped)
                _report_success({'round': round_no, 'candidate': cand_no,
                                 'input': flipped,
                                 'changes': flip['changes'],
                                 'match_changes': mch,
                                 'match_stage': mstage})

            # No match: this flipped input becomes the next round's base.
            try:
                with open(diverge_json) as f:
                    div = json.load(f)
                fork_id = (div.get('root_cause_file_b')
                           or div.get('root_cause_file'),
                           div.get('root_cause_line_b')
                           or div.get('root_cause_line'))
            except Exception:
                fork_id = None
            if fork_id and fork_id in seen_forks:
                print(f'  [flip] fork location {fork_id} already seen — no '
                      f'progress; dropping this candidate.')
                continue
            if fork_id:
                seen_forks.add(fork_id)
            chain.append({'round': round_no, 'candidate': cand_no,
                          'input': flipped, 'changes': flip['changes']})
            cur_input = flipped
            last_diverge_json = diverge_json
            progress = True
            break

        if not progress:
            print('  [flip] no candidate produced a further fork — trying '
                  'the format-field resort.')
            if _format_field_resort(cur_input):
                _report_success(_resort_step(cur_input, round_no))
            _save_status('no_progress', base_input)
            sys.exit(1)

    print(f'  [flip] round limit ({a.max_rounds}) reached without a match — '
          f'trying the format-field resort.')
    if _format_field_resort(cur_input):
        _report_success(_resort_step(cur_input, a.max_rounds))
    _save_status('round_limit', base_input)
    sys.exit(1)


if __name__ == '__main__':
    main()
