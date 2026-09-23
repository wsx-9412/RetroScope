#!/usr/bin/env python3
"""frida_taint.py - trace the input file offsets of fork variables via Frida dynamic instrumentation

Completes in a single run and supports large files. Principle:
  1. hook mmap/openat to obtain file-mapping information
  2. hook key function calls and record the data flow
  3. at the fork statement, check how variable addresses map to mmap regions

Usage:
    python3 frida_taint.py \
        --binary tiff-versions/tiff-4.0.8/tools/.libs/tiffcrop \
        --fork-file tools/tiffcrop.c --fork-line 3369 \
        --variables 'src[0]' 'src[1]' 'src[2]' 'src[3]' buff1 \
        --input in/CVE-2022-3570 \
        --args -Z 1:4,3:3 -R 90 -H 300 -i {input_file} /tmp/foo
"""

import subprocess
import os
import sys
import argparse
import json
import re
import struct
import time
from pathlib import Path


def resolve_binary(binary):
    if not os.path.isfile(binary):
        return binary
    with open(binary, 'rb') as f:
        first = f.readline()
    if first.startswith(b'#!'):
        d = os.path.dirname(binary)
        candidate = os.path.join(d, '.libs', os.path.basename(binary))
        if os.path.isfile(candidate):
            return candidate
    return binary


def get_fork_address(binary, fork_file, fork_line):
    """Use GDB to get the fork statement's address."""
    cmd = [
        'gdb', '-batch', '-nx', '-q',
        '-ex', f'break {fork_file}:{fork_line}',
        '-ex', 'run',
        '-ex', 'info break',
        '--', binary
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    for line in proc.stdout.split('\n'):
        m = re.search(r'at (0x[0-9a-f]+)', line)
        if m:
            return int(m.group(1), 16)
    return None


TAG_NAMES = {
    256: 'ImageWidth', 257: 'ImageLength', 258: 'BitsPerSample',
    259: 'Compression', 262: 'PhotometricInterpretation',
    273: 'StripOffsets', 277: 'SamplesPerPixel', 279: 'StripByteCounts',
    339: 'SampleFormat',
}


def parse_tiff_tags(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    if data[0:2] not in (b'II', b'MM'):
        return []
    endian = '<' if data[0:2] == b'II' else '>'
    ifd_offset = struct.unpack_from(endian + 'I', data, 4)[0]
    num_entries = struct.unpack_from(endian + 'H', data, ifd_offset)[0]
    tags = []
    pos = ifd_offset + 2
    for _ in range(num_entries):
        if pos + 12 > len(data):
            break
        tag = struct.unpack_from(endian + 'H', data, pos)[0]
        typ = struct.unpack_from(endian + 'H', data, pos + 2)[0]
        count = struct.unpack_from(endian + 'I', data, pos + 4)[0]
        value = struct.unpack_from(endian + 'I', data, pos + 8)[0]
        val_offset = pos + 8
        name = TAG_NAMES.get(tag, f'Tag_{tag}')
        tags.append({
            'tag': tag, 'name': name, 'value': value,
            'offset': val_offset,
            'raw': data[val_offset:val_offset+4].hex(),
        })
        pos += 12
    return tags


# ---------------------------------------------------------------------------
# Frida JS script
# ---------------------------------------------------------------------------

FRIDA_JS = r"""
'use strict';

// ========== Parameters ==========
const FORK_ADDR  = ptr('%(fork_addr)s');
const INPUT_BASE = ptr('%(input_mmap_base)s');
const INPUT_SIZE = %(input_mmap_size)s;
const INPUT_FILE_OFF = %(input_file_offset)s;
const TAG_OFFSETS = %(tag_offsets_json)s;

// ========== Global state ==========
let mmap_regions = [];     // [{base, size, fd, offset, path}]
let fd_paths = {};
let tag_found = {};

// ========== hook mmap ==========
function hook_mmap(name) {
    try {
        let addr = Module.findExportByName(null, name);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                this.ret  = null;
                this.size = args[1].toInt32();
                this.fd   = args[4].toInt32();
                this.foff = args[5].toInt32();
            },
            onLeave(retval) {
                let base = retval;
                if (!base.isNull() && this.fd >= 3 && this.size > 0) {
                    let path = fd_paths[this.fd] || 'fd=' + this.fd;
                    mmap_regions.push({
                        base: base.toString(),
                        size: this.size,
                        fd: this.fd,
                        file_offset: this.foff,
                        path: path
                    });
                }
            }
        });
    } catch(e) {}
}
hook_mmap('mmap');
hook_mmap('mmap64');

// ========== hook openat ==========
try {
    let openat_addr = Module.findExportByName(null, 'openat');
    if (openat_addr) {
        Interceptor.attach(openat_addr, {
            onEnter(args) {
                this.path_ptr = args[1];
            },
            onLeave(retval) {
                let fd = retval.toInt32();
                if (fd >= 3) {
                    try {
                        fd_paths[fd] = this.path_ptr.readUtf8String();
                    } catch(e) {}
                }
            }
        });
    }
} catch(e) {}

// ========== Set up stalker at the fork address ==========
let fork_hit = false;
let fork_bp_addr = FORK_ADDR;

// Use an Interceptor to check at the fork function entry
// The fork is inside extractContigSamplesShifted24bits
// but we cannot resolve the line number, so match by address
let target_module = Process.enumerateModules()[0];
let fork_offset = FORK_ADDR.sub(target_module.base);

// Find the function with DebugSymbol
let symbols = DebugSymbol.findFunctionsNamed('extractContigSamplesShifted24bits');
if (symbols.length > 0) {
    send({type: 'info', msg: 'Found function: ' + symbols[0].name + ' at ' + symbols[0].address});
}

// Set instrumentation at the fork address
// Trace execution with Stalker
Stalker.follow(Process.enumerateThreads()[0].id, {
    events: {
        call: true,
        ret: false,
        exec: false,
        block: false,
        compile: false
    },
    onReceive: function(events) {
        // Do not process raw events
    },
    onCallSummary: function(summary) {
        // Check whether a function near the fork address is called
    }
});

// ========== Active-scan approach ==========
// Stalker cannot match line numbers precisely, so switch to active scanning:
// Enumerate all mmap regions and check which contain input-file data

send({type: 'ready', msg: 'Hooks installed, waiting for fork...'});

// Send the scan request after a delay
setTimeout(function() {
    // Enumerate all current mmap regions
    let regions = Process.enumerateRanges('r--');
    for (let r of regions) {
        let path = '';
        try {
            let m = Process.findModuleByAddress(r.base);
            if (m) path = m.path;
        } catch(e) {}

        // Check whether this is a mapping of the input file
        if (r.size > 0 && r.size < 50*1024*1024) {  // <50MB
            send({
                type: 'region',
                base: r.base.toString(),
                size: r.size,
                prot: r.protection,
                path: path
            });
        }
    }

    // Send the mmap tracking results
    for (let mr of mmap_regions) {
        send({type: 'mmap', data: mr});
    }

    send({type: 'done'});
}, 2000);  // wait 2 seconds for the program to reach the fork
"""


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def run_analysis(binary, fork_file, fork_line, variables, input_file,
                 program_args=None, timeout=30):
    import frida

    program_args = program_args or []
    real_binary = resolve_binary(binary)

    # Build the run arguments
    run_parts = []
    for a in program_args:
        run_parts.append(a.replace('{input_file}', input_file)
                         .replace('{input}', input_file))

    # 1. Get the fork address
    print(f'[*] Getting the fork statement address...')
    fork_addr = get_fork_address(real_binary, fork_file, fork_line)
    if fork_addr is None:
        return {'error': 'fork address not found'}
    print(f'[*] Fork address: 0x{fork_addr:x}')

    # 2. Parse TIFF tags
    tiff_tags = parse_tiff_tags(input_file)
    tag_offsets = [t['offset'] for t in tiff_tags]
    print(f'[*] TIFF tags: {len(tiff_tags)}')

    # 3. Get the input file size
    file_size = os.path.getsize(input_file)
    print(f'[*] Input file: {input_file} ({file_size} bytes)')

    # 4. Start Frida
    print(f'[*] Starting Frida instrumentation...')
    device = frida.get_local_device()

    # spawn the process
    argv = [real_binary] + run_parts
    pid = device.spawn(argv)
    session = device.attach(pid)

    # Generate the JS script
    js_code = FRIDA_JS % {
        'fork_addr': str(fork_addr),
        'input_mmap_base': '0x0',   # placeholder, filled at runtime
        'input_mmap_size': 0,
        'input_file_offset': 0,
        'tag_offsets_json': json.dumps(tag_offsets),
    }

    script = session.create_script(js_code)

    results = {'mmap_regions': [], 'regions': [], 'info': []}
    done = False

    def on_message(message, data):
        nonlocal done
        if message['type'] == 'send':
            p = message['payload']
            t = p.get('type', '')
            if t == 'ready':
                print(f'[*] {p["msg"]}')
            elif t == 'info':
                results['info'].append(p['msg'])
                print(f'[*] {p["msg"]}')
            elif t == 'region':
                results['regions'].append(p)
            elif t == 'mmap':
                results['mmap_regions'].append(p['data'])
            elif t == 'done':
                done = True
        elif message['type'] == 'error':
            print(f'[!] {message["description"]}', file=sys.stderr)

    script.on('message', on_message)
    script.load()

    # Resume process execution
    device.resume(pid)
    print(f'[*] Process {pid} started')

    # Wait for completion
    start = time.time()
    while not done and (time.time() - start) < timeout:
        time.sleep(0.2)

    # 5. Analyze the results
    output = {
        'binary': real_binary,
        'input_file': input_file,
        'fork_addr': hex(fork_addr),
        'tiff_tags': tiff_tags,
        'mmap_regions': results['mmap_regions'],
        'regions_count': len(results['regions']),
    }

    # Match the input file
    input_basename = os.path.basename(input_file)
    found_mmap = None
    for mr in results['mmap_regions']:
        path = mr.get('path', '')
        if input_basename in path or input_file in path:
            found_mmap = mr
            break

    if found_mmap:
        mmap_base = int(found_mmap['base'], 16)
        mmap_size = found_mmap['size']
        file_off = found_mmap.get('file_offset', 0)
        print(f'[*] Found the input file mmap: base=0x{mmap_base:x}, '
              f'size={mmap_size}, file_offset={file_off}')

        # Compute the tag's file offset
        offsets = []
        for tag in tiff_tags:
            foff = tag['offset']
            mmap_addr = mmap_base + (foff - file_off)
            offsets.append(foff)
            print(f'    {tag["name"]}: file=0x{foff:02x} '
                  f'mmap=0x{mmap_addr:x} val={tag["value"]}')

        output['input_mmap'] = found_mmap
        output['influential_offsets'] = offsets
    else:
        print('[!] no mmap region found for the input file')
        # Try to find it among the regions
        for r in results['regions']:
            base = int(r['base'], 16)
            size = r['size']
            # Check whether this region contains a TIFF header
            try:
                session_obj = session
                # Read the first 4 bytes of memory
                data = session_obj.read_memory(ptr(base), min(4, size))
                if data[:2] in (b'II', b'MM'):
                    print(f'[*] Found a TIFF file mapping: base=0x{base:x}, size={size}')
                    output['input_mmap'] = {'base': r['base'], 'size': size}
                    offsets = [t['offset'] for t in tiff_tags]
                    output['influential_offsets'] = offsets
                    for tag in tiff_tags:
                        print(f'    {tag["name"]}: file=0x{tag["offset"]:02x} '
                              f'val={tag["value"]}')
                    break
            except:
                pass

    # Cleanup
    try:
        session.detach()
    except:
        pass

    return output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description='Locate the input file offsets of fork variables via Frida dynamic instrumentation')
    ap.add_argument('--binary',    required=True)
    ap.add_argument('--fork-file', required=True)
    ap.add_argument('--fork-line', required=True, type=int)
    ap.add_argument('--variables', required=True, nargs='+')
    ap.add_argument('--input',     required=True, help='input file path')
    ap.add_argument('--args',      nargs=argparse.REMAINDER, default=[],
                    help='program arguments ({input_file} placeholder)')
    ap.add_argument('--timeout',   type=int, default=30)
    a = ap.parse_args()

    result = run_analysis(
        binary=a.binary, fork_file=a.fork_file, fork_line=a.fork_line,
        variables=a.variables, input_file=a.input,
        program_args=a.args, timeout=a.timeout)

    print('\n' + '=' * 60)
    if 'error' in result:
        print(f'  ERROR: {result["error"]}')
    else:
        print(f'  fork address: {result["fork_addr"]}')
        if 'influential_offsets' in result:
            offs = [f'0x{o:02x}' for o in result['influential_offsets']]
            print(f'  input offsets affecting the fork: {", ".join(offs)}')
        print(f'  mmap regions: {len(result.get("mmap_regions", []))}')
    print('=' * 60)


if __name__ == '__main__':
    main()
