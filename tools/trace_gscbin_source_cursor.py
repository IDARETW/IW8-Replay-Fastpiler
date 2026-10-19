"""Emulate Replay 1.20's ScriptFile source cursor for diagnostic comparison.

The opcode operand widths and source-token rules come from the pinned native
0x1322350 and 0x13254f0 functions. This traces only; it never rewrites assets.
"""
import argparse
import json
from pathlib import Path
import struct
import zlib

NO_DATA = {1, 3, 20, 22, 40, 48, 52, 68, 69, 70, 71, 81, 82, 91,
           99, 104, 107, 113, 116, 140, 142, 147, 161, 185, 186, 187, 188}
TOKEN_IN_CODE = {4, 7, 8, 24, 37, 44, 56, 60, 76, 109, 123, 141}
TWO_SOURCE_CODE4 = {5, 23, 101, 138}
CODE2 = {11, 14, 25, 27, 28, 29, 30, 31, 32, 33, 34, 50, 80, 85,
         102, 114, 126, 127, 128, 129, 130, 131}
CODE3 = {35, 51, 79, 132, 137, 152, 169, 170, 171, 172}
CODE4 = {41, 53, 72, 73, 110, 112, 134, 148, 173, 174, 175, 176}
SOURCE_STRING_CODE4 = {95, 122}
TWO_SOURCE_CODE3 = {96, 117, 146, 150}
SOURCE_TOKEN_CODE3 = {177, 178, 179, 180}
SOURCE_TOKEN_CODE4 = {181, 182, 183, 184}


def trace(path, limit, inline_limit=0xE2C0, *, strict=False):
    """Trace source consumption, optionally requiring a complete native walk.

    Diagnostic callers may stop partway through the bytecode. Publication
    callers must request strict mode: both buffers and every function extent
    must be consumed exactly, using the compiler's instruction boundaries.
    Canonical tokens embedded in bytecode are reported separately from source
    tokens so callers can check their target-build meaning.
    """
    blob = path.read_bytes()
    if len(blob) < 16:
        raise ValueError("Truncated GSCBIN header")
    magic, compressed_len, plain_len, code_len = struct.unpack_from("<4I", blob)
    if magic != 0x435347 or 16 + compressed_len + code_len != len(blob):
        raise ValueError("Invalid GSCBIN")
    source = zlib.decompress(blob[16:16 + compressed_len])
    code = blob[16 + compressed_len:]
    if len(source) != plain_len:
        raise ValueError("Invalid source size")
    instruction_ends = None
    if strict:
        from workstation_asset_codecs import _script_instructions, inspect_gscbin
        inspect_gscbin(blob)
        if type(limit) is not int or limit < len(code):
            raise ValueError("Strict GSC source tracing requires the complete bytecode")
        instruction_ends = {start: stop for start, _op, stop in _script_instructions(code)}
        if not instruction_ends:
            raise ValueError("GSC source has no complete function body")
    src = 0
    pc = 1
    end = 1
    events = []

    def string():
        nonlocal src
        start = src
        stop = source.find(b"\0", start)
        if stop < 0:
            raise ValueError("Unterminated source string")
        src = stop + 1
        return {"source_offset": hex(start),
                "string": source[start:stop].decode("utf-8", "replace")}

    def token():
        nonlocal src
        start = src
        if src + 4 > len(source):
            raise ValueError("Truncated GSC source token")
        value = struct.unpack_from("<I", source, src)[0]
        src += 4
        result = {"source_offset": hex(start), "id": hex(value)}
        if not value:
            result.update(string())
        return result

    while pc < min(len(code), limit):
        if pc == end:
            if src + 4 > len(source):
                raise ValueError("Truncated GSC function source header")
            size = struct.unpack_from("<I", source, src)[0]
            src += 4
            name = token()
            end += size
            if strict and (size == 0 or end > len(code) or
                           (end != len(code) and end not in instruction_ends)):
                raise ValueError("GSC function extent is not a complete instruction boundary")
            events.append({"function_at": hex(pc), "size": hex(size), "name": name})
        op_pc = pc
        opcode = code[pc]
        pc += 1
        record = {"pc": hex(op_pc), "opcode": hex(opcode), "source_before": hex(src)}
        if opcode in NO_DATA:
            pc += 1
        elif opcode in TOKEN_IN_CODE:
            value = struct.unpack_from("<I", code, pc)[0]
            pc += 4
            if value > inline_limit:
                record["token"] = token()
            else:
                record["canonical_token"] = {"id": hex(value), "bytecode_offset": hex(pc - 4)}
        elif opcode in TWO_SOURCE_CODE4:
            record["first"] = token()
            record["second"] = token()
            pc += 4
        elif opcode in CODE2:
            pc += 2
        elif opcode == 19:
            pc += 12
        elif opcode in CODE3:
            pc += 3
        elif opcode in CODE4:
            pc += 4
        elif opcode == 86:
            count = struct.unpack_from('<H', code, pc)[0]
            pc += 2
            record['cases'] = []
            for _ in range(count):
                value = struct.unpack_from('<I', code, pc)[0]
                # Replay 1.20 ProcessScriptFile compares the case dword with
                # 0x80000 and skips the source-name scan on JAE.
                if value < 0x80000:
                    record['cases'].append(string())
                pc += 7
        elif opcode in SOURCE_STRING_CODE4:
            record["string"] = string()
            pc += 4
        elif opcode in TWO_SOURCE_CODE3:
            record["first"] = token()
            record["second"] = token()
            pc += 3
        elif opcode == 98:
            record["string"] = string()
            pc += 1
        elif opcode == 160:
            pc += 5
        elif opcode == 145:
            # The pinned native handler scans two strings from the source
            # cursor, then advances the bytecode cursor by eight bytes.
            record["first_string"] = string()
            record["second_string"] = string()
            pc += 8
        elif opcode in (166, 189):
            count = code[pc]
            pc += 1 + count
        elif opcode in SOURCE_TOKEN_CODE3:
            record["token"] = token()
            pc += 3
        elif opcode in SOURCE_TOKEN_CODE4:
            record["token"] = token()
            pc += 4
        record["source_after"] = hex(src)
        record["next_pc"] = hex(pc)
        if strict and instruction_ends.get(op_pc) != pc:
            raise ValueError("GSC source cursor differs from the compiler instruction boundary")
        events.append(record)
        if pc > end:
            if strict:
                raise ValueError("GSC instruction crosses the declared function extent")
            record["crossed_function_end"] = hex(end)
            break
    if strict and (pc != len(code) or end != len(code) or src != len(source)):
        raise ValueError("GSC source cursor did not consume both buffers and the final function exactly")
    return events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--limit", type=lambda value: int(value, 0), default=0x200)
    parser.add_argument("--inline-limit", type=lambda value: int(value, 0), default=0xE2C0)
    args = parser.parse_args()
    print(json.dumps(trace(args.path, args.limit, args.inline_limit), indent=2))


if __name__ == "__main__":
    main()
