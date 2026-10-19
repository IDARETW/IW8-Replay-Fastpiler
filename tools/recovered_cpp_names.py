"""One spelling policy for unnamed C++ symbols and their linker aliases.

Stable catalog IDs remain unchanged. Names are derived from pinned native
identity, so users never enter addresses to bind renamed declarations.
"""
from __future__ import annotations

import re

FUNCTION_PLACEHOLDER = re.compile(
    r'(?:j_)?(?:sub|nullsub|fn|func)_(?P<suffix>(?:0x)?[0-9a-fA-F]{1,16}(?:_\d+)?)')
DATA_PLACEHOLDER = re.compile(
    r'(?:byte|word|dword|qword|tbyte|oword|xmmword|ymmword|zmmword|unk|off|flt|dbl|asc|'
    r'stru|tbl|jpt|def|loc|locret|sym|gl)_(?:0x)?[0-9a-fA-F]{1,16}(?:_\d+)?')
COUNTER_PLACEHOLDER = re.compile(r'(?:j_)?nullsub_\d+(?:_\d+)?')
# Tokenize quoted literals/comments separately. Names embedded in strings,
# diagnostics and comments do not denote references and must stay untouched.
TOKENS = re.compile(
    r'//(?:\\\r?\n|[^\n])*|/\*.*?\*/|'
    r'(?:u8|u|U|L)?R"(?P<raw_delimiter>[^ ()\\\t\v\f\r\n]{0,16})'
    r'\(.*?\)(?P=raw_delimiter)"|'
    r'(?:u8|u|U|L)?"(?:\\.|[^"\\])*"|'
    r'(?:u8|u|U|L)?\'(?:\\.|[^\'\\])*\'|(?P<identifier>[A-Za-z_]\w*)', re.S)


def code_text(source: str) -> str:
    """Exclude decompiler comments and quoted literals from operation checks."""
    return TOKENS.sub(lambda match: match[0] if match['identifier'] is not None else ' ', source)


def count_jumpouts(source: str) -> int:
    return len(re.findall(r'\bJUMPOUT\s*\(', code_text(source)))


def rename_identifier(source: str, old_name: str, new_name: str) -> str:
    """Bind a declaration and its references without changing literal contents."""
    return TOKENS.sub(lambda match: new_name if match['identifier'] == old_name else match[0], source)


def is_generated_name(name: str) -> bool:
    return bool(FUNCTION_PLACEHOLDER.fullmatch(name or '') or DATA_PLACEHOLDER.fullmatch(name or ''))


def function_name(rva: int, image_base: int) -> str:
    return f'func_{image_base + rva:X}'


def global_name(rva: int, image_base: int) -> str:
    return f'gl_{image_base + rva:X}'


def automatic_aliases(catalog: dict) -> dict[str, int]:
    base = catalog.get('image_base')
    if not isinstance(base, int):
        return {}
    result = {function_name(row['rva'], base): row['rva'] for row in catalog.get('functions', [])
              if not row.get('quarantined')}
    for row in catalog.get('symbols', []):
        # A code label is not itself a proven callable function.
        result[global_name(row['rva'], base)] = row['rva']
    return result


class CppNames:
    def __init__(self, rows, symbols, image_base):
        self.image_base = image_base
        self.by_token = {}
        self.by_address = {}
        self.by_export_token = {}
        for row in rows:
            if row.get('quarantined'):
                continue
            is_function = row.get('kind', 'function') == 'function'
            preferred = (symbols.get(row['id']) if is_function else
                         global_name(row['rva'], image_base))
            if not preferred or (is_function and FUNCTION_PLACEHOLDER.fullmatch(preferred)):
                preferred = function_name(row['rva'], image_base)
            self.by_address[(is_function, image_base + row['rva'])] = preferred
            export_name = row.get('decompiler_name')
            if is_function and export_name:
                key = export_name
                if key in self.by_export_token:
                    raise ValueError('Ambiguous decompiler function token: ' + export_name)
                self.by_export_token[key] = preferred
            for token in {row['id'], row.get('name', ''), *row.get('aliases', [])} - {''}:
                self.by_token.setdefault(token, set()).add((is_function, preferred))

    def token(self, token: str, use_export_names=False, reference_names=None, allow_counter_aliases=True):
        function = bool(FUNCTION_PLACEHOLDER.fullmatch(token))
        data = bool(DATA_PLACEHOLDER.fullmatch(token))
        if not function and not data:
            return token
        reference = (reference_names or {}).get(token)
        if reference:
            rva, kind = reference['rva'], reference['kind']
            if type(rva) is not int or not 0 <= rva < 0x100000000 or kind not in ('function', 'data-global'):
                raise ValueError('Invalid recovered token identity: ' + token)
            is_function = kind == 'function'
            return self.by_address.get((is_function, self.image_base + rva)) or (
                function_name(rva, self.image_base) if is_function else global_name(rva, self.image_base))
        if COUNTER_PLACEHOLDER.fullmatch(token) and not allow_counter_aliases:
            return 'func_unresolved_' + token
        if function and use_export_names:
            target = self.by_export_token.get(token)
            if target:
                return target
            if COUNTER_PLACEHOLDER.fullmatch(token):
                # A counter is not an address. Never bind it to a reused old
                # alias or silently interpret its digits as a VA.
                return 'func_unresolved_' + token
        known = self.by_token.get(token, set())
        if len(known) == 1:
            return next(iter(known))[1]
        if COUNTER_PLACEHOLDER.fullmatch(token):
            return 'func_unresolved_' + token
        suffix = FUNCTION_PLACEHOLDER.fullmatch(token)['suffix'] if function else token.split('_', 1)[1]
        address_text = suffix.split('_', 1)[0]
        address = int(address_text, 16)
        target = self.by_address.get((function, address))
        if target:
            return target
        # An unindexed reference keeps its address-bearing suffix. This is a
        # spelling change, never evidence of a callable ABI or data layout.
        return ('func_' if function else 'gl_') + suffix

    def rewrite(self, source: str, use_export_names=False, reference_names=None, allow_counter_aliases=True):
        return TOKENS.sub(lambda match: self.token(match[0], use_export_names, reference_names, allow_counter_aliases)
                          if match['identifier'] is not None else match[0], source)
