"""XML markup profile (tolerant linear scan)."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .base import (
    FIELD_CAP, FormatProfile, cand, mutate_bytes, pack_region,
)


class XmlProfile(FormatProfile):
    name = 'xml'

    @classmethod
    def detect(cls, data: bytes) -> bool:
        if not data:
            return False
        head = data[:512].lstrip(b'\xef\xbb\xbf \t\r\n')
        return head.startswith(b'<')

    def parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        if not self.detect(data):
            return None
        fields: List[Dict[str, Any]] = []
        seen = set()

        def add(off: int, size: int, kind: str, name: str):
            if off in seen or not (0 <= off < len(data)):
                return
            seen.add(off)
            fields.append({'offset': off, 'size': size, 'kind': kind,
                           'name': name})

        n = len(data)
        i = 0
        while i < n and len(fields) < FIELD_CAP:
            lt = data.find(b'<', i)
            if lt < 0:
                break
            if data.startswith(b'<!--', lt):
                add(lt, 1, 'markup', 'comment')
                end = data.find(b'-->', lt)
                i = end + 3 if end >= 0 else n
            elif data.startswith(b'<![CDATA[', lt):
                add(lt, 1, 'markup', 'cdata')
                end = data.find(b']]', lt)
                i = end + 2 if end >= 0 else n
            elif data.startswith(b'<?', lt):
                add(lt, 1, 'markup', 'pi')
                end = data.find(b'?>', lt)
                i = end + 2 if end >= 0 else n
            elif data.startswith(b'<!', lt):
                add(lt, 1, 'markup', 'decl')
                if data[lt:lt + 9].upper() == b'<!DOCTYPE':
                    lb = data.find(b'[', lt)
                    gt = data.find(b'>', lt)
                    if lb != -1 and (gt == -1 or lb < gt):
                        i = lb + 1
                    else:
                        i = gt + 1 if gt >= 0 else n
                else:
                    end = -1
                    resync = lt + 2
                    j = lt + 1
                    while j < n:
                        c = data[j]
                        if c in (0x22, 0x27):
                            q = c
                            j += 1
                            while j < n and data[j] != q:
                                j += 1
                        elif c == 0x3e:
                            end = j
                            break
                        elif c == 0x3c:
                            resync = j
                            break
                        j += 1
                    i = end + 1 if end >= 0 else resync
            else:
                add(lt, 1, 'markup', 'open')
                k = lt + 1
                if k < n and data[k] == 0x2f:
                    k += 1
                name_start = k
                while k < n and data[k] not in b' \t\r\n/>':
                    k += 1
                if k > name_start:
                    add(name_start, 1, 'name', 'element')
                end = lt + 1
                while end < n and data[end] != 0x3e:
                    if data[end] in (0x22, 0x27):
                        quote = data[end]
                        end += 1
                        while end < n and data[end] != quote:
                            end += 1
                    end += 1
                if end < n:
                    add(end, 1, 'markup', 'close')
                i = end + 1 if end < n else n
        for m in re.finditer(
                rb'([A-Za-z_][\w.:-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\')',
                data):
            if len(fields) >= FIELD_CAP:
                break
            add(m.start(1), 1, 'name', 'attribute')
            if m.group(2):
                add(m.start(2), 1, 'attr', 'value')
            elif m.group(3):
                add(m.start(3), 1, 'attr', 'value')
        return pack_region('xml', 'XML element/attribute marks',
                           None, None, None, None, fields)

    def validate(self, data: bytes,
                 structure: Dict[str, Any]) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        if not data:
            return [{'kind': 'empty', 'offset': 0, 'size': 0,
                     'msg': 'empty file'}]
        head = data[:512].lstrip(b'\xef\xbb\xbf \t\r\n')
        if not head.startswith(b'<'):
            issues.append({'kind': 'no_root', 'offset': 0, 'size': 1,
                           'msg': 'does not start with markup'})
        # Unclosed quotes in the first 4KB — a classic malformed-PoC shape.
        window = data[:4096]
        for quote in (0x22, 0x27):
            if window.count(bytes([quote])) % 2 == 1:
                issues.append({'kind': 'unbalanced_quote', 'offset': 0,
                               'size': 1,
                               'msg': f'unbalanced {chr(quote)!r} quote '
                                      f'in header'})
                break
        # Unterminated comment / CDATA / DOCTYPE at EOF.
        if b'<!--' in window and b'-->' not in data:
            issues.append({'kind': 'unterminated_comment',
                           'offset': data.find(b'<!--'), 'size': 4,
                           'msg': 'unterminated comment'})
        if b'<![' in window and b']]>' not in data:
            issues.append({'kind': 'unterminated_cdata',
                           'offset': data.find(b'<!['), 'size': 4,
                           'msg': 'unterminated CDATA'})
        # Bare '&' that is not a valid entity reference (common PoC bait).
        for m in re.finditer(rb'&(?!(?:#\d+|#x[0-9a-fA-F]+|'
                             rb'[A-Za-z][\w.-]*);)', data[:8192]):
            issues.append({'kind': 'bad_entity', 'offset': m.start(),
                           'size': 1, 'msg': 'bare & not an entity'})
            break
        # Truncated tag at EOF: '<foo' with no '>'.
        last_lt = data.rfind(b'<')
        if last_lt >= 0 and b'>' not in data[last_lt:]:
            issues.append({'kind': 'truncated_tag', 'offset': last_lt,
                           'size': 1, 'msg': 'tag truncated at EOF'})
        return issues

    def repair(self, data: bytes, structure: Dict[str, Any],
               issues: Sequence[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
        for issue in issues:
            kind = issue.get('kind')
            off = issue.get('offset')
            if not isinstance(off, int):
                off = 0
            if kind == 'unterminated_comment':
                yield cand('fmt-repair', 'fmt-xml-close-comment',
                           data + b'-->', [len(data)],
                           desc='close unterminated comment')
            elif kind == 'unterminated_cdata':
                yield cand('fmt-repair', 'fmt-xml-close-cdata',
                           data + b']]>', [len(data)],
                           desc='close unterminated CDATA')
            elif kind == 'truncated_tag':
                yield cand('fmt-repair', 'fmt-xml-close-tag',
                           data + b'>', [len(data)],
                           desc='close truncated tag')
            elif kind == 'bad_entity':
                # Terminate the bare '&' as a literal ampersand entity.
                new = data[:off] + b'&amp;' + data[off + 1:]
                yield cand('fmt-repair', f'fmt-xml-amp@{off:#x}', new,
                           [off], desc='escape bare ampersand')
            elif kind == 'unbalanced_quote':
                # Close the header with a quote+'>'
                yield cand('fmt-repair', 'fmt-xml-close-quote',
                           data + b'"', [len(data)],
                           desc='close unbalanced attribute quote')
            elif kind == 'no_root':
                yield cand('fmt-repair', 'fmt-xml-wrap',
                           b'<r>' + data + b'</r>', [0],
                           desc='wrap content in a root element')
            elif kind == 'empty':
                yield cand('fmt-repair', 'fmt-xml-empty',
                           b'<a/>', [0], desc='minimal XML document')

    def value_domain(self, field: Dict[str, Any]) -> List[int]:
        kind = field.get('kind')
        if kind == 'markup':
            return [0x00, 0x20, 0x21, 0x22, 0x23, 0x27, 0x2d, 0x2f,
                    0x3c, 0x3d, 0x3e, 0x3f, 0xff]
        if kind == 'name':
            return [0x00, 0x20, 0x2d, 0x2e, 0x2f, 0x3a, 0x5f, 0x61,
                    0x2d, 0xff]
        if kind == 'attr':
            return [0x00, 0x22, 0x27, 0x26, 0x2f, 0x3c, 0x3e, 0xff]
        return super().value_domain(field)
