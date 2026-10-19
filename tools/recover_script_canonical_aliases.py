"""Recover named-to-opaque exports from corresponding IW8 GSCBIN functions.

Only paired runs between unchanged export-name anchors are candidates.  The
generated evidence retains both normalized bodies; reviewed entries can be
used by the native canonical-string compatibility table.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re

FUNCTION = re.compile(r"// Params ([^\n]+)\n// Size: (0x[0-9a-f]+)\nfunction (\w+)\([^)]*\)\ngscasm \{(.*?)^\}", re.S | re.M)
LINE = re.compile(r"^\.([0-9a-f.]+): ([0-9a-f]{4}) (.*)$", re.M)


def functions(path):
    return [dict(locals=int(count), size=int(size, 16), name=name, body=body)
            for count, size, name, body in FUNCTION.findall(path.read_text())]


def normalized(function, aliases):
    rows = [(int(at.split('.')[-1], 16), operation.strip())
            for at, _, operation in LINE.findall(function["body"])]
    positions = {at: index for index, (at, _) in enumerate(rows)}
    positions[function["size"]] = len(rows)
    locals_by_name = {}
    for _, operation in rows:
        created = re.match(r"(?:IW_SetNewLocalVariableFieldCached\w*|IW_CreateLocalVar)\s+(var\d+)", operation)
        if created and created[1] not in locals_by_name:
            locals_by_name[created[1]] = "local" + str(len(locals_by_name))
    result = []
    for _, operation in rows:
        if operation.startswith("SafeCreateLocalVariables"):
            # The older compiler reserves unused trailing local slots.  Every
            # referenced source variable is compared in the remaining body.
            operation = "SafeCreateLocalVariables"
        operation = re.sub(r"(?:IW_)?EvalLocalVariableCached\w*\s+\(-?\d+\)\s+(var\d+)", r"EvalLocalVariable \1", operation)
        operation = re.sub(r"IW_SetLocalVariableCached\w*\s+(var\d+)", r"SetLocalVariable \1", operation)
        operation = re.sub(r"Jump \.([0-9a-f]{8}) \(delta:[^)]+\)",
                           lambda m: "Jump instruction_" + str(positions.get(int(m[1], 16), "unresolved")), operation)
        operation = re.sub(r"\bref_([0-9a-f]+)\b", lambda m: aliases.get(int(m[1], 16), m[0]), operation)
        # Locals created after the argument declarations have shifted physical
        # indexes when unused argument slots are removed. Preserve argument
        # indexes and compare each created local by its declaration order.
        operation = re.sub(r"\b(var\d+)\b", lambda m: locals_by_name.get(m[1], m[1]), operation)
        operation = re.sub(r"(local\d+) \(-?\d+\)", r"\1", operation)
        operation = re.sub(r"\s+", " ", operation)
        result.append(operation)
    return result


def recover(old, new):
    a, b = functions(old), functions(new)
    candidates = []
    matcher = difflib.SequenceMatcher(None, [f["name"] for f in a], [f["name"] for f in b], autojunk=False)
    for operation, i, j, k, l in matcher.get_opcodes():
        if operation != "replace" or j-i != l-k:
            continue
        for before, after in zip(a[i:j], b[k:l]):
            if before["name"].startswith("ref_") or not after["name"].startswith("ref_"):
                continue
            token = int(after["name"][4:], 16)
            if 0xE2C0 < token <= 0x1472F:
                candidates.append((before, after, token))
    aliases = {token: before["name"] for before, _, token in candidates}
    result = []
    for before, after, token in candidates:
        first, second = normalized(before, aliases), normalized(after, aliases)
        result.append(dict(name=before["name"], token=hex(token), native_name=after["name"],
                           old_size=before["size"], new_size=after["size"],
                           old_local_slots=before["locals"], new_local_slots=after["locals"],
                           normalized_bodies_equal=first == second,
                           old_normalized=first, new_normalized=second))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = dict(inputs=[dict(path=str(p.resolve()), sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in (args.old, args.new)],
                  aliases=recover(args.old, args.new))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    for item in result["aliases"]:
        print(item["token"], item["name"], "equal" if item["normalized_bodies_equal"] else "needs review")


if __name__ == "__main__":
    main()
