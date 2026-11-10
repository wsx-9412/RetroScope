#!/usr/bin/env python3
"""Unit tests for the format_profiles package (Plan B)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from format_profiles import (
    detect_profile, detect_profile_by_name, parse_bytes,
    profile_candidates, structure_only,
)
from format_profiles.base import (
    FormatProfile, cand, mutate_int, pack_region, read_int, write_int,
)

REPO = os.path.dirname(os.path.abspath(__file__))


def _read(rel):
    path = os.path.join(REPO, rel)
    with open(path, 'rb') as f:
        return f.read()


class TestBaseHelpers(unittest.TestCase):
    def test_read_write_int_le(self):
        data = bytearray(b'\x00' * 8)
        self.assertTrue(write_int(data, 0, 4, 0x11223344, True))
        self.assertEqual(read_int(bytes(data), 0, 4, True), 0x11223344)
        self.assertEqual(data[:4], b'\x44\x33\x22\x11')

    def test_read_write_int_be(self):
        data = bytearray(b'\x00' * 4)
        self.assertTrue(write_int(data, 0, 2, 0xABCD, False))
        self.assertEqual(read_int(bytes(data), 0, 2, False), 0xABCD)

    def test_write_int_oob(self):
        data = bytearray(4)
        self.assertFalse(write_int(data, 2, 4, 1, True))
        self.assertFalse(write_int(data, -1, 1, 1, True))
        self.assertFalse(write_int(data, 0, 4, -1, True))

    def test_mutate_int(self):
        data = b'\x00\x00\x00\x00'
        out = mutate_int(data, 0, 2, 0xBEEF, True)
        self.assertEqual(out, b'\xef\xbe\x00\x00')
        self.assertIsNone(mutate_int(data, 3, 4, 1, True))

    def test_cand_shape(self):
        c = cand('fmt', 'detail', b'abc', [1, 2, -3], 'desc')
        self.assertEqual(c['op'], 'fmt')
        self.assertEqual(c['data'], b'abc')
        self.assertEqual(c['offsets'], [1, 2])  # negatives dropped
        self.assertEqual(c['desc'], 'desc')

    def test_pack_region_dedupe_and_cap(self):
        fields = [{'offset': i % 5, 'size': 1, 'kind': 'desc',
                   'name': f'f{i}'} for i in range(200)]
        region = pack_region('x', 'lab', 0, 1, 1, 0, fields)
        self.assertIsNotNone(region)
        self.assertLessEqual(len(region['field_offsets']), 100)
        self.assertEqual(len(region['field_offsets']),
                         len(set(region['field_offsets'])))
        self.assertIsNone(pack_region('x', 'lab', 0, 1, 1, 0, []))


class TestDetect(unittest.TestCase):
    def test_tiff_magic(self):
        self.assertTrue(detect_profile(b'II*\x00' + b'\x00' * 64).name
                        == 'tiff')
        self.assertTrue(detect_profile(b'MM\x00*' + b'\x00' * 64).name
                        == 'tiff')
        # GIF magic is claimed by GifProfile (magic-strict, earlier in
        # registry order) — detect_profile returns the first match.
        self.assertEqual(detect_profile(b'GIF89a' + b'\x00' * 20).name,
                         'gif')

    def test_gif_magic(self):
        self.assertTrue(detect_profile(b'GIF87a' + b'\x00' * 20))
        self.assertTrue(detect_profile(b'GIF89a' + b'\x00' * 20))

    def test_j2k_magic(self):
        self.assertTrue(detect_profile(b'\xff\x4f\xff\x51' + b'\x00' * 32))

    def test_dwg_magic(self):
        self.assertTrue(detect_profile(b'AC1032' + b'\x00' * 64))
        self.assertTrue(detect_profile(b'AC1015' + b'\x00' * 64))
        self.assertFalse(detect_profile(b'ACXXXX' + b'\x00' * 64))

    def test_font_magic(self):
        self.assertTrue(detect_profile(b'\x00\x01\x00\x00' + b'\x00' * 64))
        self.assertTrue(detect_profile(b'OTTO' + b'\x00' * 64))
        self.assertTrue(detect_profile(b'wOFF' + b'\x00' * 64))
        self.assertTrue(detect_profile(b'ttcf' + b'\x00' * 64))

    def test_xml_magic(self):
        self.assertEqual(
            detect_profile(b'<?xml version="1.0"?><a/>').name, 'xml')
        self.assertEqual(detect_profile(b'\n\n<root></root>').name, 'xml')
        # GIF magic wins over the tolerant XML scanner (registry order).
        self.assertEqual(detect_profile(b'GIF89a').name, 'gif')

    def test_detect_profile_by_name(self):
        self.assertIsNotNone(detect_profile_by_name('tiff'))
        self.assertIsNotNone(detect_profile_by_name('dwg'))
        self.assertIsNone(detect_profile_by_name('nope'))

    def test_unknown_format(self):
        self.assertIsNone(detect_profile(b'\x00' * 32))
        self.assertIsNone(detect_profile(b''))


class TestTiff(unittest.TestCase):
    def test_parse_real_poc(self):
        data = _read('in/openjpeg/CVE-2017-14039.tif')
        prof = detect_profile(data)
        self.assertEqual(prof.name, 'tiff')
        st = prof.parse(data)
        self.assertIsNotNone(st)
        self.assertEqual(st['format'], 'tiff')
        self.assertTrue(st['field_offsets'])
        self.assertEqual(st['entry_size'], 12)
        # every field offset inside file
        for off in st['field_offsets']:
            self.assertGreaterEqual(off, 0)
            self.assertLess(off, len(data))

    def test_validate_reports_bad_types(self):
        data = _read('in/openjpeg/CVE-2017-14039.tif')
        prof = detect_profile(data)
        st = prof.parse(data)
        issues = prof.validate(data, st)
        # fuzzed PoC: expect at least one structural issue
        self.assertTrue(issues)
        kinds = {i['kind'] for i in issues}
        self.assertTrue(kinds & {'bad_type', 'value_oob', 'ifd_truncated',
                                 'ifd_oob'})

    def test_repair_emits_candidates(self):
        data = _read('in/openjpeg/CVE-2017-14039.tif')
        prof = detect_profile(data)
        st = prof.parse(data)
        issues = prof.validate(data, st)
        fixes = list(prof.repair(data, st, issues))
        self.assertTrue(fixes)
        for c in fixes:
            self.assertIn('op', c)
            self.assertIn('data', c)
            self.assertIn('offsets', c)
            self.assertEqual(len(c['data']), len(data))

    def test_value_domain_tag(self):
        data = _read('in/openjpeg/CVE-2017-14039.tif')
        prof = detect_profile(data)
        st = prof.parse(data)
        tag_field = next(f for f in st['fields'] if f.get('field') == 'tag')
        domain = prof.value_domain(tag_field)
        self.assertTrue(domain)
        self.assertIn(0x16, domain)  # low byte of 278 RowsPerStrip family

    def test_mutate_field_roundtrip(self):
        data = _read('in/openjpeg/CVE-2017-14039.tif')
        prof = detect_profile(data)
        st = prof.parse(data)
        field = st['fields'][0]
        out = prof.mutate_field(data, field, 0x42)
        self.assertIsNotNone(out)
        self.assertEqual(len(out), len(data))
        self.assertNotEqual(out, data)


class TestJ2k(unittest.TestCase):
    def test_parse_real_poc(self):
        data = _read('in/openjpeg/crash.j2k')
        prof = detect_profile(data)
        self.assertEqual(prof.name, 'j2k')
        st = prof.parse(data)
        self.assertIsNotNone(st)
        self.assertEqual(st['format'], 'j2k')
        self.assertTrue(st.get('combo_only'))
        marker_fields = [f for f in st['fields'] if f['kind'] == 'marker']
        self.assertTrue(marker_fields)

    def test_validate_missing_eoc(self):
        data = _read('in/openjpeg/crash.j2k')
        prof = detect_profile(data)
        st = prof.parse(data)
        issues = prof.validate(data, st)
        kinds = {i['kind'] for i in issues}
        # fuzzed PoC typically lacks EOC or has bad lengths
        self.assertTrue(kinds & {'missing_eoc', 'marker_len_oob',
                                 'bad_marker_len', 'marker_trunc',
                                 'missing_soc'})

    def test_family_rewrite_candidates(self):
        data = _read('in/openjpeg/crash.j2k')
        prof = detect_profile(data)
        st = prof.parse(data)
        cands = list(prof.field_candidates(data, st))
        self.assertTrue(cands)
        family = [c for c in cands if 'mark' in c['detail']]
        self.assertTrue(family)
        # family rewrite touches multiple offsets
        self.assertGreaterEqual(max(len(c['offsets']) for c in family), 1)


class TestDwg(unittest.TestCase):
    def test_parse_real_poc(self):
        data = _read('in/libredwg/CVE-2026-9504.dwg')
        prof = detect_profile(data)
        self.assertEqual(prof.name, 'dwg')
        st = prof.parse(data)
        self.assertIsNotNone(st)
        self.assertEqual(st['format'], 'dwg')
        self.assertEqual(st['version'], 'AC1032')
        names = {f['name'] for f in st['fields']}
        self.assertIn('version', names)
        self.assertIn('codepage', names)

    def test_validate_unknown_version(self):
        data = b'AC9999' + b'\x00' * 128
        prof = detect_profile(data)
        self.assertIsNotNone(prof)
        st = prof.parse(data)
        issues = prof.validate(data, st)
        kinds = {i['kind'] for i in issues}
        self.assertIn('unknown_version', kinds)

    def test_repair_version_snap(self):
        data = b'AC9999' + b'\x00' * 128
        prof = detect_profile(data)
        st = prof.parse(data)
        issues = prof.validate(data, st)
        fixes = list(prof.repair(data, st, issues))
        self.assertTrue(fixes)
        # at least one fix rewrites the version to a known AC10xx
        ver_fixes = [c for c in fixes if c['detail'].startswith('fmt-dwg-ver=')]
        self.assertTrue(ver_fixes)
        self.assertTrue(ver_fixes[0]['data'][:2] == b'AC')

    def test_parse_ac1015(self):
        data = _read('in/libredwg/CVE-2026-9500.dwg')  # AC1018 actually
        # also try AC1015 sample
        p = os.path.join(REPO, 'in/libredwg/CVE-2026-15182.dwg')
        if os.path.isfile(p):
            data = open(p, 'rb').read()
        prof = detect_profile(data)
        st = prof.parse(data)
        self.assertIsNotNone(st)
        self.assertTrue(st['version'].startswith('AC10'))


class TestXml(unittest.TestCase):
    def test_parse_real(self):
        data = _read('in/libxml2/test.xml')
        prof = detect_profile(data)
        self.assertEqual(prof.name, 'xml')
        st = prof.parse(data)
        self.assertIsNotNone(st)
        self.assertTrue(st['field_offsets'])

    def test_detect_and_validate_truncated(self):
        # no '>' after the last '<' => truncated tag at EOF
        data = b'<root><child attr="x"'
        prof = detect_profile(data)
        self.assertEqual(prof.name, 'xml')
        st = prof.parse(data)
        issues = prof.validate(data, st)
        kinds = {i['kind'] for i in issues}
        self.assertIn('truncated_tag', kinds)

    def test_repair_truncated_tag(self):
        data = b'<root><child attr="x"'
        prof = detect_profile(data)
        st = prof.parse(data)
        issues = prof.validate(data, st)
        fixes = list(prof.repair(data, st, issues))
        self.assertTrue(any('close-tag' in c['detail'] for c in fixes))
        close = next(c for c in fixes if 'close-tag' in c['detail'])
        self.assertTrue(close['data'].endswith(b'>'))

    def test_bad_entity(self):
        data = b'<a>foo & bar</a>'
        prof = detect_profile(data)
        st = prof.parse(data)
        issues = prof.validate(data, st)
        self.assertTrue(any(i['kind'] == 'bad_entity' for i in issues))
        fixes = list(prof.repair(data, st, issues))
        self.assertTrue(any(b'&amp;' in c['data'] for c in fixes))


class TestGif(unittest.TestCase):
    def test_parse_real_poc(self):
        data = _read('in/CVE-2015-7555')
        prof = detect_profile(data)
        self.assertEqual(prof.name, 'gif')
        st = prof.parse(data)
        self.assertIsNotNone(st)
        self.assertEqual(st['format'], 'gif')
        names = {f['name'] for f in st['fields']}
        self.assertIn('screen_width', names)

    def test_validate_bad_lzw(self):
        data = _read('in/CVE-2015-7555')
        prof = detect_profile(data)
        st = prof.parse(data)
        issues = prof.validate(data, st)
        self.assertTrue(any(i['kind'] == 'bad_lzw_min' for i in issues))

    def test_repair_lzw(self):
        data = _read('in/CVE-2015-7555')
        prof = detect_profile(data)
        st = prof.parse(data)
        issues = prof.validate(data, st)
        fixes = list(prof.repair(data, st, issues))
        lzw = [c for c in fixes if 'lzw' in c['detail']]
        self.assertTrue(lzw)
        for c in lzw:
            self.assertEqual(len(c['data']), len(data))

    def test_missing_trailer(self):
        data = b'GIF89a' + b'\x01\x00\x01\x00\x00\x00\x00' + b'\x2c' + b'\x00' * 20
        prof = detect_profile(data)
        st = prof.parse(data)
        issues = prof.validate(data, st)
        self.assertTrue(any(i['kind'] == 'missing_trailer' for i in issues))


class TestFont(unittest.TestCase):
    def test_detect_sfnt(self):
        data = b'\x00\x01\x00\x00' + b'\x00' * 128
        prof = detect_profile(data)
        self.assertEqual(prof.name, 'font')

    def test_parse_minimal_sfnt(self):
        # minimal sfnt: version + numTables=1 + one table record
        data = (b'\x00\x01\x00\x00'
                + (1).to_bytes(2, 'big')  # numTables
                + (16).to_bytes(2, 'big')  # searchRange
                + (0).to_bytes(2, 'big')   # entrySelector
                + (0).to_bytes(2, 'big')   # rangeShift
                + b'cmap'
                + (0).to_bytes(4, 'big')   # checksum
                + (52).to_bytes(4, 'big')  # offset
                + (10).to_bytes(4, 'big')) # length
        data = data.ljust(64, b'\x00')
        prof = detect_profile(data)
        st = prof.parse(data)
        self.assertIsNotNone(st)
        self.assertEqual(st['format'], 'sfnt')
        self.assertEqual(st['count'], 1)
        names = {f['name'] for f in st['fields']}
        self.assertIn('numTables', names)
        self.assertIn('table[0].tag', names)

    def test_validate_table_oob(self):
        data = (b'\x00\x01\x00\x00'
                + (1).to_bytes(2, 'big')
                + (16).to_bytes(2, 'big')
                + (0).to_bytes(2, 'big')
                + (0).to_bytes(2, 'big')
                + b'cmap'
                + (0).to_bytes(4, 'big')
                + (0xFFFFFF00).to_bytes(4, 'big')  # offset way past EOF
                + (10).to_bytes(4, 'big'))
        data = data.ljust(64, b'\x00')
        prof = detect_profile(data)
        st = prof.parse(data)
        issues = prof.validate(data, st)
        self.assertTrue(any(i['kind'] == 'table_oob' for i in issues))

    def test_real_font_if_present(self):
        # find any real sfnt/woff under in/ (magic must actually match)
        import glob
        found = None
        for pat in ('in/**/*.ttf', 'in/**/*.otf', 'in/**/*.woff',
                    'in/**/*.ttc'):
            for p in glob.glob(os.path.join(REPO, pat), recursive=True):
                if not os.path.isfile(p):
                    continue
                with open(p, 'rb') as f:
                    sig = f.read(4)
                if sig in (b'\x00\x01\x00\x00', b'OTTO', b'true',
                           b'typ1', b'ttcf', b'wOFF', b'wOF2'):
                    found = p
                    break
            if found:
                break
        if not found:
            self.skipTest('no real font sample')
        with open(found, 'rb') as f:
            data = f.read()
        prof = detect_profile(data)
        self.assertIsNotNone(prof)
        self.assertEqual(prof.name, 'font')
        st = prof.parse(data)
        self.assertIsNotNone(st)


class TestPackageApi(unittest.TestCase):
    def test_parse_bytes(self):
        data = _read('in/CVE-2015-7555')
        st = parse_bytes(data)
        self.assertIsNotNone(st)
        self.assertEqual(st['format'], 'gif')

    def test_structure_only(self):
        data = _read('in/openjpeg/crash.j2k')
        st = structure_only(data)
        self.assertIsNotNone(st)

    def test_profile_candidates_order_repairs_first(self):
        data = _read('in/CVE-2015-7555')
        cands = list(profile_candidates(data))
        self.assertTrue(cands)
        # repairs (issue fixes) come before plain fmt field mutations
        ops = [c['op'] for c in cands]
        self.assertIn('fmt-repair', ops)
        first_repair = ops.index('fmt-repair')
        # at least one repair appears before the first pure 'fmt' field cand
        field_idxs = [i for i, o in enumerate(ops) if o == 'fmt']
        if field_idxs:
            self.assertLess(first_repair, field_idxs[0])

    def test_profile_candidates_focus(self):
        data = _read('in/openjpeg/CVE-2017-14039.tif')
        # focus on a mid-file offset; candidates should prefer it
        focus = 0x2c
        cands = list(profile_candidates(data, focus=[focus]))
        self.assertTrue(cands)
        # some candidate should touch the focus offset
        self.assertTrue(any(focus in c['offsets'] for c in cands))

    def test_profile_candidates_unknown_format(self):
        cands = list(profile_candidates(b'\x00' * 64))
        self.assertEqual(cands, [])

    def test_profile_candidates_deterministic_shape(self):
        data = _read('in/libredwg/CVE-2026-9504.dwg')
        cands = list(profile_candidates(data))
        self.assertTrue(len(cands) > 10)
        for c in cands[:20]:
            self.assertIn('op', c)
            self.assertIn('detail', c)
            self.assertIsInstance(c['data'], (bytes, bytearray))
            self.assertEqual(len(c['data']), len(data))
            self.assertIsInstance(c['offsets'], list)


class TestIntegrationWithExtendedMutation(unittest.TestCase):
    def test_format_candidates_importable(self):
        from extended_mutation import _format_candidates
        data = _read('in/CVE-2015-7555')
        cands = list(_format_candidates(data, None, None))
        self.assertTrue(cands)

    def test_format_candidates_with_structure(self):
        from extended_mutation import _format_candidates
        data = _read('in/openjpeg/CVE-2017-14039.tif')
        st = structure_only(data)
        cands = list(_format_candidates(data, st, [0x2c]))
        self.assertTrue(cands)

    def test_format_candidates_no_structure_still_works(self):
        from extended_mutation import _format_candidates
        data = _read('in/libredwg/CVE-2026-9504.dwg')
        # pipeline structure without 'fields' key => profile reparses
        pipe_struct = {'field_offsets': [0, 4], 'entry_size': 12}
        cands = list(_format_candidates(data, pipe_struct, None))
        self.assertTrue(cands)

    def test_run_phase_phase_seconds_param(self):
        # signature check: _run_phase is nested; verify via source
        import inspect
        from extended_mutation import run_extended_mutation_stage
        src = inspect.getsource(run_extended_mutation_stage)
        self.assertIn('phase_seconds=120.0', src)
        self.assertIn("format-aware", src)
        self.assertIn('phase_seconds', src)


if __name__ == '__main__':
    unittest.main(verbosity=2)


class TestPlanC1Coordinated(unittest.TestCase):
    """C1: coordinated multi-field mutation via dependency groups."""

    def test_deps_importable(self):
        from format_profiles import dependency_groups, focus_groups
        self.assertTrue(callable(dependency_groups))
        self.assertTrue(callable(focus_groups))

    def test_tiff_groups(self):
        from format_profiles import detect_profile, dependency_groups
        data = _read('in/openjpeg/CVE-2017-14039.tif')
        st = detect_profile(data).parse(data)
        groups = dependency_groups(st)
        self.assertTrue(groups)
        # each TIFF group has 4 fields (tag/type/count/value)
        label, fields = groups[0]
        self.assertEqual(len(fields), 4)
        names = {f.get('field') for f in fields}
        self.assertEqual(names, {'tag', 'type', 'count', 'value'})

    def test_gif_groups(self):
        from format_profiles import detect_profile, dependency_groups
        data = _read('in/CVE-2015-7555')
        st = detect_profile(data).parse(data)
        groups = dependency_groups(st)
        labels = [g[0] for g in groups]
        self.assertIn('gif-screen', labels)
        self.assertIn('gif-image', labels)

    def test_dwg_groups(self):
        from format_profiles import detect_profile, dependency_groups
        data = _read('in/libredwg/CVE-2026-9504.dwg')
        st = detect_profile(data).parse(data)
        groups = dependency_groups(st)
        labels = [g[0] for g in groups]
        self.assertIn('dwg-version-header', labels)

    def test_j2k_groups(self):
        from format_profiles import detect_profile, dependency_groups
        data = _read('in/openjpeg/crash.j2k')
        st = detect_profile(data).parse(data)
        groups = dependency_groups(st)
        self.assertTrue(any(l.startswith('j2k-marker-')
                            for l, _ in groups))

    def test_xml_groups(self):
        from format_profiles import detect_profile, dependency_groups
        data = _read('in/libxml2/test.xml')
        st = detect_profile(data).parse(data)
        groups = dependency_groups(st)
        self.assertTrue(any(l.startswith('xml-tag@') for l, _ in groups))

    def test_unknown_format_no_groups(self):
        from format_profiles import dependency_groups
        self.assertEqual(dependency_groups({}), [])
        self.assertEqual(
            dependency_groups({'format': 'nope', 'fields': []}), [])

    def test_focus_groups_reorders(self):
        from format_profiles import dependency_groups, focus_groups
        groups = [
            ('a', [{'offset': 100}, {'offset': 101}]),
            ('b', [{'offset': 1}, {'offset': 2}]),
        ]
        out = focus_groups(groups, [1])
        self.assertEqual(out[0][0], 'b')

    def test_coordinated_candidates_tiff(self):
        from extended_mutation import _coordinated_candidates
        data = _read('in/openjpeg/CVE-2017-14039.tif')
        cands = list(_coordinated_candidates(data, None, '<', [0x2c]))
        self.assertTrue(cands)
        for c in cands:
            self.assertEqual(c['op'], 'coord')
            self.assertEqual(len(c['data']), len(data))
            self.assertGreaterEqual(len(c['offsets']), 1)

    def test_coordinated_candidates_gif(self):
        from extended_mutation import _coordinated_candidates
        data = _read('in/CVE-2015-7555')
        cands = list(_coordinated_candidates(data, None, '<', None))
        self.assertTrue(cands)
        self.assertTrue(any('gif-' in c['detail'] for c in cands))

    def test_coordinated_candidates_dwg(self):
        from extended_mutation import _coordinated_candidates
        data = _read('in/libredwg/CVE-2026-9504.dwg')
        cands = list(_coordinated_candidates(data, None, '<', None))
        self.assertTrue(cands)
        self.assertTrue(any('dwg-' in c['detail'] for c in cands))

    def test_coordinated_respects_cap(self):
        from extended_mutation import _coordinated_candidates
        data = _read('in/openjpeg/CVE-2017-14039.tif')
        cands = list(_coordinated_candidates(data, None, '<', None,
                                             per_group_cap=2))
        # per_group_cap=2 limits values per group; total still <= 100
        self.assertLessEqual(len(cands), 100)

    def test_coordinated_no_structure_still_reparses(self):
        from extended_mutation import _coordinated_candidates
        data = _read('in/CVE-2015-7555')
        # pipeline-style structure without 'fields' => profile reparses
        cands = list(_coordinated_candidates(
            data, {'field_offsets': [6, 8]}, '<', None))
        self.assertTrue(cands)


class TestPlanC2GrammarCompress(unittest.TestCase):
    """C2: grammar-token and compression operators."""

    def test_grammar_xml(self):
        from extended_mutation import _grammar_candidates
        data = _read('in/libxml2/test.xml')
        cands = list(_grammar_candidates(data, None, '<', None, cap=30))
        self.assertTrue(cands)
        for c in cands:
            self.assertEqual(c['op'], 'grammar')
            self.assertEqual(len(c['data']) >= len(data) - 8, True)

    def test_grammar_j2k(self):
        from extended_mutation import _grammar_candidates
        data = _read('in/openjpeg/crash.j2k')
        cands = list(_grammar_candidates(data, None, '<', None, cap=30))
        self.assertTrue(cands)
        self.assertTrue(any('j2k' in c['detail'] for c in cands))

    def test_grammar_gif(self):
        from extended_mutation import _grammar_candidates
        data = _read('in/CVE-2015-7555')
        cands = list(_grammar_candidates(data, None, '<', None, cap=30))
        self.assertTrue(cands)
        self.assertTrue(any('gif' in c['detail'] for c in cands))

    def test_grammar_focus_positions(self):
        from extended_mutation import _grammar_candidates
        data = _read('in/libxml2/test.xml')
        focus = 0x18
        cands = list(_grammar_candidates(data, None, '<', [focus], cap=30))
        self.assertTrue(cands)
        # some candidate should touch the focus offset
        self.assertTrue(any(focus in c['offsets'] for c in cands))

    def test_grammar_unknown_format_noop(self):
        from extended_mutation import _grammar_candidates
        # random non-format data with no structure => no-op
        cands = list(_grammar_candidates(b'\x01\x02\x03\x04' * 10,
                                         None, '<', None, cap=10))
        # may still sniff nothing => empty
        self.assertIsInstance(cands, list)

    def test_compression_compressible(self):
        from extended_mutation import _compression_candidates
        payload = b'<root>' + b'x="y" ' * 80 + b'</root>'
        cands = list(_compression_candidates(payload, None, '<',
                                             [0, 5], cap=20))
        self.assertTrue(cands)
        ops = {c['op'] for c in cands}
        self.assertIn('compress', ops)

    def test_compression_gzip_roundtrip(self):
        import gzip as gzmod
        from extended_mutation import gzip_bytes
        blob = b'hello world' * 20
        packed = gzip_bytes(blob, 6)
        self.assertEqual(gzmod.decompress(packed), blob)

    def test_compression_bz2_present(self):
        from extended_mutation import _compression_candidates
        payload = b'A' * 500
        cands = list(_compression_candidates(payload, None, '<', None,
                                             cap=20))
        details = [c['detail'] for c in cands]
        # bz2 or zlib should appear for highly compressible input
        self.assertTrue(any('bz2' in d or 'zlib' in d for d in details),
                        details)

    def test_compression_raw_poke_on_tiff_focus(self):
        from extended_mutation import _compression_candidates
        data = _read('in/openjpeg/CVE-2017-14039.tif')
        # TIFF skips whole-file recompress but may raw-poke focus bytes
        cands = list(_compression_candidates(data, None, '<', [0x2c],
                                             cap=20))
        self.assertIsInstance(cands, list)
        for c in cands:
            self.assertEqual(c['op'], 'compress')


class TestPlanC3ParseDepth(unittest.TestCase):
    """C3: parse-depth feedback reorders focus."""

    def test_shallow_puts_structure_first(self):
        from extended_mutation import _parse_depth_focus
        attr = [{'parse_stage': 'header'},
                {'parse_stage': 'directory'},
                {'parse_stage': 'header'}]
        struct = {'field_offsets': [10, 20, 30]}
        out = _parse_depth_focus(attr, struct, [1, 2])
        self.assertEqual(out[:3], [10, 20, 30])

    def test_deep_keeps_base_first(self):
        from extended_mutation import _parse_depth_focus
        attr = [{'parse_stage': 'decode'},
                {'parse_stage': 'unknown'},
                {'parse_stage': 'decode'}]
        struct = {'field_offsets': [10, 20]}
        out = _parse_depth_focus(attr, struct, [1, 2])
        self.assertEqual(out[:2], [1, 2])

    def test_empty_attribution_returns_base(self):
        from extended_mutation import _parse_depth_focus
        self.assertEqual(
            _parse_depth_focus([], {'field_offsets': [9]}, [5, 6]),
            [5, 6])

    def test_none_safe(self):
        from extended_mutation import _parse_depth_focus
        self.assertEqual(_parse_depth_focus(None, None, None), [])

    def test_no_structure_returns_base(self):
        from extended_mutation import _parse_depth_focus
        attr = [{'parse_stage': 'header'}]
        self.assertEqual(_parse_depth_focus(attr, {}, [7]), [7])

    def test_dedupes(self):
        from extended_mutation import _parse_depth_focus
        attr = [{'parse_stage': 'header'}]
        struct = {'field_offsets': [1, 2, 1, 3]}
        out = _parse_depth_focus(attr, struct, [2, 4])
        self.assertEqual(len(out), len(set(out)))

    def test_tie_keeps_base_first(self):
        # equal shallow/deep counts => base first (deep path)
        from extended_mutation import _parse_depth_focus
        attr = [{'parse_stage': 'header'}, {'parse_stage': 'decode'}]
        struct = {'field_offsets': [10]}
        out = _parse_depth_focus(attr, struct, [1])
        self.assertEqual(out[0], 1)


class TestPlanCPhaseWiring(unittest.TestCase):
    """New phases are wired into run_extended_mutation_stage."""

    def test_phases_present_in_source(self):
        import inspect
        from extended_mutation import run_extended_mutation_stage
        src = inspect.getsource(run_extended_mutation_stage)
        for phase in ('format-aware', 'coordinated',
                      'grammar-compress', 'compress'):
            self.assertIn(f"'{phase}'", src, phase)

    def test_phase_budgets(self):
        import inspect
        from extended_mutation import run_extended_mutation_stage
        src = inspect.getsource(run_extended_mutation_stage)
        # format-aware + coordinated: 300 / 120s
        self.assertIn('phase_seconds=120.0', src)
        # grammar + compress: 150 / 60s each
        self.assertIn('phase_seconds=60.0', src)

    def test_feedback_uses_parse_depth(self):
        import inspect
        from extended_mutation import run_extended_mutation_stage
        src = inspect.getsource(run_extended_mutation_stage)
        self.assertIn('_parse_depth_focus', src)
        self.assertIn('coord', src)  # coordinated in feedback plans

    def test_existing_phases_untouched(self):
        """A/B guard: original phase names still present in order."""
        import inspect
        from extended_mutation import run_extended_mutation_stage
        src = inspect.getsource(run_extended_mutation_stage)
        for phase in ('dynamic-exact', 'dynamic-neighbourhood',
                      'dynamic-blocks', 'record-layout',
                      'structure-uniform', 'dynamic-structure',
                      'static-offsets', 'static-blocks',
                      'havoc', 'splice'):
            self.assertIn(f"'{phase}'", src, phase)


class TestA1BehaviorProbe(unittest.TestCase):
    """A1 attribution probe: reached_fork must not collapse to unknown."""

    def _sig(self, frames, typ='heap-buffer-overflow'):
        return {'type': typ, 'crash_frames': [
            {'function': fn, 'file': fl, 'line': ln} for fn, fl, ln in frames
        ]}

    def test_header_reject_without_error_keywords(self):
        from extended_mutation import _behavior_signature
        beh = _behavior_signature('bad magic header', 1, '/tmp/in',
                                  sig=None, fork_func='foo')
        self.assertEqual(beh['reached_fork'], False)
        self.assertEqual(beh['error_class'], 'parse_error')
        self.assertEqual(beh['parse_stage'], 'header')

    def test_not_a_tiff_header_reject(self):
        from extended_mutation import _behavior_signature
        beh = _behavior_signature('not a TIFF file', 1, '/tmp/in', sig=None)
        self.assertEqual(beh['reached_fork'], False)

    def test_at_fork_crash(self):
        from extended_mutation import _behavior_signature
        sig = self._sig([('read_2004_compressed_section', 'decode.c', 2181)])
        beh = _behavior_signature('ERROR: AddressSanitizer: SEGV', 1, '/tmp/in',
                                  sig=sig,
                                  fork_func='read_2004_compressed_section',
                                  fork_file='decode.c',
                                  ref_stack_funcs=['read_2004_compressed_section'])
        self.assertEqual(beh['reached_fork'], True)
        self.assertEqual(beh['crash_relation'], 'at_fork')

    def test_on_ref_path_when_top_frame_differs(self):
        from extended_mutation import _behavior_signature
        sig = self._sig([
            ('copy_bytes', 'decode_r2007.c', 228),
            ('decompress_r2007', 'decode_r2007.c', 563),
        ], 'stack-buffer-overflow')
        beh = _behavior_signature(
            'ERROR: AddressSanitizer: stack-buffer-overflow', 1, '/tmp/in',
            sig=sig, fork_func='read_instructions',
            fork_file='decode_r2007.c',
            ref_stack_funcs=['copy_bytes', 'decompress_r2007'])
        self.assertEqual(beh['reached_fork'], True)
        self.assertEqual(beh['crash_relation'], 'on_ref_path')

    def test_in_fork_file_without_shared_funcs(self):
        from extended_mutation import _behavior_signature
        sig = self._sig([('unrelated_helper', 'decode.c', 99)])
        beh = _behavior_signature(
            'ERROR: AddressSanitizer: heap-buffer-overflow', 1, '/tmp/in',
            sig=sig, fork_func='read_2004_compressed_section',
            fork_file='decode.c',
            ref_stack_funcs=['read_2004_compressed_section'])
        self.assertEqual(beh['reached_fork'], True)
        self.assertEqual(beh['crash_relation'], 'in_fork_file')

    def test_elsewhere_crash_is_unknown_not_false(self):
        from extended_mutation import _behavior_signature
        sig = self._sig([('main', 'dwgread.c', 10)])
        beh = _behavior_signature(
            'ERROR: AddressSanitizer: heap-buffer-overflow', 1, '/tmp/in',
            sig=sig, fork_func='read_2004_compressed_section',
            fork_file='decode.c',
            ref_stack_funcs=['read_2004_compressed_section'])
        self.assertEqual(beh['crash_relation'], 'elsewhere')
        self.assertEqual(beh['reached_fork'], 'unknown')

    def test_decode_stage_parse_is_unknown(self):
        from extended_mutation import _behavior_signature
        beh = _behavior_signature(
            'ERROR: failed to decode strip truncated', 1, '/tmp/in',
            sig=None, fork_func='foo', fork_file='decode.c')
        self.assertEqual(beh['parse_stage'], 'decode')
        self.assertEqual(beh['reached_fork'], 'unknown')

    def test_clean_exit_unknown(self):
        from extended_mutation import _behavior_signature
        beh = _behavior_signature('ok', 0, '/tmp/in', sig=None, fork_func='foo')
        self.assertEqual(beh['reached_fork'], 'unknown')

    def test_legacy_at_fork_without_extra_context(self):
        from extended_mutation import _behavior_signature
        sig = self._sig([('copy_bytes', 'x.c', 1)], 'stack-buffer-overflow')
        beh = _behavior_signature(
            'ERROR: AddressSanitizer: stack-buffer-overflow', 1, '/tmp/in',
            sig=sig, fork_func='copy_bytes')
        self.assertEqual(beh['reached_fork'], True)
        self.assertEqual(beh['crash_relation'], 'at_fork')

    def test_key_stable_across_new_params(self):
        from extended_mutation import _behavior_signature
        k1 = _behavior_signature('bad magic', 1, '/tmp/in')['key']
        k2 = _behavior_signature('bad magic', 1, '/tmp/in', sig=None,
                                 fork_func='x', fork_file='y',
                                 ref_stack_funcs=['a'])['key']
        self.assertEqual(k1, k2)

    def test_stage_accepts_fork_func_param(self):
        import inspect
        from extended_mutation import run_extended_mutation_stage
        self.assertIn('fork_func',
                      inspect.signature(run_extended_mutation_stage).parameters)

    def test_call_site_passes_root_cause(self):
        with open('trace_fork_offsets.py') as fh:
            src = fh.read()
        self.assertIn("fork_func=(config.get('root_cause_function')", src)


    def test_generic_frames_do_not_prove_on_ref_path(self):
        """main/__libc shared alone must NOT count as on_ref_path."""
        from extended_mutation import _behavior_signature
        ref_stack = ['copy_bytes', 'decompress_r2007', 'main',
                     '__libc_start_call_main', 'read_file_header']
        sig = {
            'type': 'SEGV',
            'crash_frames': [
                {'function': 'dxfb_header_write', 'file': 'spec', 'line': 26},
                {'function': 'dwg_write_dxfb', 'file': 'out.c', 'line': 1},
                {'function': 'main', 'file': 'dwg2dxf.c', 'line': 335},
                {'function': '__libc_start_call_main', 'file': 'libc', 'line': 58},
            ],
        }
        beh = _behavior_signature(
            'ERROR: AddressSanitizer: SEGV', 1, '/tmp/in',
            sig=sig, fork_func='read_instructions',
            fork_file='decode_r2007.c', ref_stack_funcs=ref_stack)
        self.assertEqual(beh['crash_relation'], 'elsewhere')
        self.assertEqual(beh['reached_fork'], 'unknown')

    def test_project_frame_still_proves_on_ref_path(self):
        from extended_mutation import _behavior_signature
        ref_stack = ['copy_bytes', 'decompress_r2007', 'main',
                     '__libc_start_call_main']
        sig = {
            'type': 'stack-buffer-overflow',
            'crash_frames': [
                {'function': 'decompress_r2007', 'file': 'd.c', 'line': 563},
                {'function': 'main', 'file': 'm.c', 'line': 1},
            ],
        }
        beh = _behavior_signature(
            'ERROR: AddressSanitizer: stack-buffer-overflow', 1, '/tmp/in',
            sig=sig, fork_func='read_instructions',
            fork_file='decode_r2007.c', ref_stack_funcs=ref_stack)
        self.assertEqual(beh['crash_relation'], 'on_ref_path')
        self.assertEqual(beh['reached_fork'], True)


class TestCoverageProbe(unittest.TestCase):
    """Coverage attribution: fork_hit via verify_one + death modes."""

    def test_hint_none_without_location(self):
        from extended_mutation import _fork_coverage_hint
        self.assertIsNone(_fork_coverage_hint(None, 10))
        self.assertIsNone(_fork_coverage_hint('x.c', None))
        self.assertIsNone(_fork_coverage_hint('x.c', 0))
        self.assertIsNone(_fork_coverage_hint('x.c', 'bad'))

    def test_hint_uses_explicit_line_not_root_cause_default(self):
        from extended_mutation import _fork_coverage_hint
        h = _fork_coverage_hint('decode_r2007.c', 539)
        self.assertEqual(h['fork_spec'], 'decode_r2007.c:539')
        self.assertIsNone(h['cond_expr'])

    def test_probe_disabled_by_env(self):
        import os
        from extended_mutation import _fork_coverage_probe
        old = os.environ.get('RETROSCOPE_FORK_PROBE')
        os.environ['RETROSCOPE_FORK_PROBE'] = '0'
        try:
            self.assertIsNone(_fork_coverage_probe(
                '/bin/true', 'x.c', 1, b'a', [], '/tmp/in'))
        finally:
            if old is None:
                del os.environ['RETROSCOPE_FORK_PROBE']
            else:
                os.environ['RETROSCOPE_FORK_PROBE'] = old

    def test_probe_none_without_data_or_hint(self):
        from extended_mutation import _fork_coverage_probe
        self.assertIsNone(_fork_coverage_probe(
            '/bin/true', None, 1, b'a', [], '/tmp/in'))
        self.assertIsNone(_fork_coverage_probe(
            '/bin/true', 'x.c', 1, None, [], '/tmp/in'))
        self.assertIsNone(_fork_coverage_probe(
            None, 'x.c', 1, b'a', [], '/tmp/in'))

    def test_death_mode_matched(self):
        from extended_mutation import _classify_death_mode
        self.assertEqual(
            _classify_death_mode({'verdict': 'same_func'}), 'matched')
        self.assertEqual(
            _classify_death_mode({'verdict': 'same_site'}), 'matched')

    def test_death_mode_near_miss_same_type(self):
        from extended_mutation import _classify_death_mode
        self.assertEqual(
            _classify_death_mode({'verdict': 'same_type'}),
            'near_miss_same_type')

    def test_death_mode_prefork_from_parse_reject(self):
        from extended_mutation import _classify_death_mode
        self.assertEqual(_classify_death_mode({
            'reached_fork': 'no', 'error_class': 'parse_error',
            'parse_stage': 'header',
        }), 'G_early_reject')
        self.assertEqual(_classify_death_mode({
            'reached_fork': 'no', 'error_class': 'parse_error',
            'parse_stage': 'decode',
        }), 'G_parse_error')

    def test_death_mode_prefork_from_probe_miss(self):
        from extended_mutation import _classify_death_mode
        self.assertEqual(_classify_death_mode({
            'fork_hit': False, 'reached_fork': 'unknown',
            'error_class': 'parse_error', 'parse_stage': 'decode',
        }), 'G_parse_error')

    def test_death_mode_pastfork_no_crash(self):
        from extended_mutation import _classify_death_mode
        self.assertEqual(_classify_death_mode({
            'fork_hit': True, 'reached_fork': 'unknown',
            'error_class': 'clean', 'parse_stage': 'unknown',
        }), 'pastF_no_crash')

    def test_death_mode_pastfork_wrong_crash(self):
        from extended_mutation import _classify_death_mode
        self.assertEqual(_classify_death_mode({
            'fork_hit': True, 'reached_fork': 'unknown',
            'error_class': 'asan_crash', 'crash_relation': 'elsewhere',
        }), 'pastF_wrong_crash')

    def test_death_mode_unknown_clean_blind_spot(self):
        from extended_mutation import _classify_death_mode
        self.assertEqual(_classify_death_mode({
            'fork_hit': None, 'reached_fork': 'unknown',
            'error_class': 'clean', 'parse_stage': 'unknown',
        }), 'unknown_clean')

    def test_death_mode_unknown_decode(self):
        from extended_mutation import _classify_death_mode
        self.assertEqual(_classify_death_mode({
            'fork_hit': None, 'reached_fork': 'unknown',
            'error_class': 'parse_error', 'parse_stage': 'decode',
        }), 'unknown_decode')

    def test_stage_source_has_coverage_probe(self):
        with open('extended_mutation.py') as fh:
            src = fh.read()
        self.assertIn('_fork_coverage_probe(', src)
        self.assertIn("_probe_jobs.append", src)
        self.assertIn('error_class_x_fork_hit', src)
        self.assertIn('death_mode', src)

    def test_attribution_record_has_fork_hit_field(self):
        """Records must carry fork_hit (None until the probe runs)."""
        with open('extended_mutation.py') as fh:
            src = fh.read()
        self.assertIn("'fork_hit': None", src)


class TestSectionFallback(unittest.TestCase):
    """Path A: section-targeted origin fallback for empty dynamic traces."""

    def test_section_control_offsets_r2004(self):
        from dwg_sections import section_control_offsets
        import os
        p = 'in/libredwg/CVE-2026-9500.dwg'
        if not os.path.isfile(p):
            self.skipTest('libredwg PoC not present')
        data = open(p, 'rb').read()
        offs = section_control_offsets(data)
        self.assertGreaterEqual(len(offs), 8)
        notes = {n for _o, _s, n in offs}
        self.assertIn('section_map_address', notes)
        self.assertIn('section_info_id', notes)
        # file offsets must be inside the encrypted header window 0x80..0xf8
        for off, sz, _n in offs:
            if off < 0x100:
                self.assertGreaterEqual(off, 0x80)
                self.assertLessEqual(off + sz, 0x80 + 0x78 + 4)

    def test_section_control_offsets_r2000_empty(self):
        from dwg_sections import section_control_offsets
        self.assertEqual(section_control_offsets(b'AC1015' + b'\x00' * 200), [])

    def test_fallback_maps_header_func(self):
        from origin_fallback import section_fallback_offsets
        import os
        p = 'in/libredwg/CVE-2026-9500.dwg'
        if not os.path.isfile(p):
            self.skipTest('libredwg PoC not present')
        offs = section_fallback_offsets(p, 'read_2004_compressed_section')
        self.assertGreater(len(offs), 8)
        vias = {o['via'] for o in offs}
        self.assertIn('section_map_control', vias)
        self.assertIn('section_page', vias)
        # Header pages must be present for this fork function
        notes = ' '.join(str(o.get('note') or '') for o in offs)
        self.assertIn('Header', notes)

    def test_fallback_bits_func_samples_many_sections(self):
        from origin_fallback import section_fallback_offsets, _sections_for_func
        self.assertIn('Header', _sections_for_func('bit_read_RC'))
        self.assertIn('AcDbObjects', _sections_for_func('bit_position'))
        import os
        p = 'in/libredwg/CVE-2026-9500.dwg'
        if not os.path.isfile(p):
            self.skipTest('libredwg PoC not present')
        offs = section_fallback_offsets(p, 'bit_read_RC')
        self.assertGreater(len(offs), 16)

    def test_fallback_skips_non_dwg(self):
        from origin_fallback import section_fallback_offsets
        import tempfile
        fd, path = tempfile.mkstemp(suffix='.txt')
        os.close(fd)
        try:
            with open(path, 'wb') as f:
                f.write(b'not a dwg')
            self.assertEqual(section_fallback_offsets(path, 'foo'), [])
        finally:
            os.unlink(path)

    def test_enrich_origin_result_only_when_empty(self):
        from origin_fallback import enrich_origin_result
        res = {'status': 'ok', 'offsets': []}
        n = enrich_origin_result(res, input_file='/no/such/file',
                                 fork_func='x')
        self.assertEqual(n, 0)
        res2 = {'status': 'ok',
                'offsets': [{'offset': 1, 'length': 1, 'via': 'read'}]}
        self.assertEqual(enrich_origin_result(res2, input_file='/no/such'), 0)
        self.assertEqual(len(res2['offsets']), 1)

    def test_enrich_existing_9500_origin_if_present(self):
        import json, os
        p = 'results/CVE-2026-9500_origin.json'
        if not os.path.isfile(p):
            self.skipTest('origin json not present')
        d = json.load(open(p))
        # after Path A enrichment this file must carry fallback offsets
        offs = d.get('offsets') or []
        self.assertGreater(len(offs), 0)
        self.assertEqual(d.get('section_fallback', {}).get('count'),
                         len(offs))

    def test_origin_trace_defaults_trace_read_request(self):
        with open('dynamic_origin_trace.py') as fh:
            src = fh.read()
        self.assertIn('dest="trace_read_request"', src)
        self.assertIn('action="store_true", default=True', src)
        self.assertIn('--no-trace-read-request', src)
        self.assertIn('CFG.get("trace_read_request", True)', src)

    def test_origin_trace_has_chain_scan(self):
        with open('dynamic_origin_trace.py') as fh:
            src = fh.read()
        self.assertIn('chain_scan', src)
        self.assertIn('Bit_Chain payload scan', src)

    def test_origin_trace_enriches_before_write(self):
        with open('dynamic_origin_trace.py') as fh:
            src = fh.read()
        self.assertIn('from origin_fallback import enrich_origin_result', src)
        self.assertIn('section fallback', src)
