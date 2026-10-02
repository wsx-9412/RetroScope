#!/usr/bin/env python3
"""Append one summary line per analysis run to results/offset_summary.log.

The line reports how many input-file offsets the pipeline localized for
mutation ("程序找到的需要变异的偏移位置数") over the number of possible
input byte positions, plus the breakdown (fork variables / IFD fields),
mutation counts and match counts.

Usage:
  python3 offset_summary.py --log results/version_sweep/<CVE>/tiff-4.0.9.log
  python3 offset_summary.py --backfill results/version_sweep/CVE-2023-0800
"""
import argparse
import glob
import os
import re
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(BASE, 'results', 'offset_summary.log')


def _hex_tokens(text):
    return {int(h, 16) for h in re.findall(r'0x[0-9a-fA-F]+', text or '')}


def _out_dir_for(cve, version):
    m = re.search(r'(\d+\.\d+(?:\.\d+)*[A-Za-z]*)', version or '')
    if not m:
        return None
    return os.path.join(BASE, 'out', f'{cve}-{m.group(1).replace(".", "-")}')


def parse_log(path):
    with open(path, errors='replace') as f:
        text = f.read()
    lines = text.splitlines()

    cve = ''
    m = re.search(r'^CVE:\s*(\S+)', text, re.M)
    if m:
        cve = m.group(1)
    target = ''
    m = re.search(r'^Target:\s*(\S+)', text, re.M)
    if m:
        target = os.path.basename(m.group(1))
    input_file = ''
    m = re.search(r'^Input:\s*(\S+)', text, re.M)
    if m:
        input_file = m.group(1)
    input_size = None
    for cand in (input_file, os.path.join(BASE, input_file)):
        if cand and os.path.isfile(cand):
            input_size = os.path.getsize(cand)
            break

    dynamic = 0
    m = re.search(r'Dynamic origin trace input offsets:\s*(\d+)', text)
    if m:
        dynamic = int(m.group(1))

    fork_offsets = set()
    for ln in lines:
        if 'Validation candidates (from fork variables) at input file offsets:' in ln:
            fork_offsets |= _hex_tokens(ln)
            break

    ifd_offsets = set()
    for ln in lines:
        if 'all entry fields (tag/type/count/offset):' in ln:
            ifd_offsets |= _hex_tokens(ln)
            break
    m = re.search(r'Step 6a: Directed IFD-region mutation \((\d+) structural fields', text)
    ifd_field_count = int(m.group(1)) if m else 0

    tested = 0
    for m in re.finditer(r'Total (?:pairwise )?mutations tested:\s*(\d+)', text):
        tested += int(m.group(1))

    matches = 0
    out_dir = _out_dir_for(cve, target) if cve and target else None
    if out_dir and os.path.isdir(out_dir):
        for name in os.listdir(out_dir):
            if name.startswith('.') or name.startswith('NO_CRASH_MATCH'):
                continue
            matches += 1

    rc = None
    m = re.search(r'^exit_code=(\d+)\s*$', text, re.M)
    if m:
        rc = int(m.group(1))
    elif 'Analysis completed' in text:
        rc = 0

    union = len(fork_offsets | ifd_offsets)
    return {
        'cve': cve,
        'target': target,
        'input_size': input_size,
        'fork': len(fork_offsets),
        'ifd': len(ifd_offsets),
        'ifd_fields': ifd_field_count,
        'union': union,
        'dynamic': dynamic,
        'tested': tested,
        'matches': matches,
        'rc': rc,
        'run_id': int(os.path.getmtime(path)),
        'completed': time.strftime('%Y-%m-%d %H:%M:%S',
                                   time.localtime(os.path.getmtime(path))),
    }


def format_line(r):
    denom = r['input_size'] if r['input_size'] is not None else '?'
    status = 'ok' if r['rc'] == 0 else ('FAIL' if r['rc'] is not None else 'incomplete')
    return ('{completed}  {cve:<14} {target:<16} '
            'offsets={union}/{denom}  '
            '(fork={fork}, ifd={ifd} [fields={ifd_fields}], union={union})  '
            'dynamic={dynamic}  tested={tested}  matches={matches}  '
            'rc={rc}  {status}  run={run_id}').format(denom=denom, status=status, **r)


def append_entry(out_path, line, run_id):
    seen = False
    if os.path.isfile(out_path):
        with open(out_path, errors='replace') as f:
            seen = f' run={run_id}' in f.read()
    if seen:
        return False
    header = not os.path.isfile(out_path) or os.path.getsize(out_path) == 0
    with open(out_path, 'a') as f:
        if header:
            f.write('# offsets = input-file byte positions the pipeline localized '
                    'for mutation / total input size\n')
        f.write(line + '\n')
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', help='analysis log to summarize')
    ap.add_argument('--backfill', help='directory of *.log files to backfill')
    ap.add_argument('--out', default=DEFAULT_OUT,
                    help='accumulating summary file (default: %(default)s)')
    ap.add_argument('--print-only', action='store_true')
    a = ap.parse_args()

    logs = []
    if a.log:
        logs = [a.log]
    elif a.backfill:
        logs = []
        for p in glob.glob(os.path.join(a.backfill, '*.log')):
            if p.endswith('.first_pass.log'):
                continue
            with open(p, errors='replace') as f:
                if 'exit_code=' not in f.read():
                    continue  # still running / aborted mid-run
            logs.append(p)
        logs.sort(key=os.path.getmtime)
    else:
        ap.error('need --log or --backfill')

    for path in logs:
        r = parse_log(path)
        line = format_line(r)
        if a.print_only:
            print(line)
        else:
            added = append_entry(a.out, line, r['run_id'])
            print(('+ ' if added else '= ') + line)
            sys.stdout.flush()


if __name__ == '__main__':
    main()
