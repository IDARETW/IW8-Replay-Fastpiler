"""Extract exact names for typed reference-only XAsset roots from a native trace."""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(body_path: Path, trace_path: Path, indices: list[int]) -> dict:
    body = body_path.read_bytes()
    events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()
              if line.strip()]
    roots = []
    for index in indices:
        begin = [row for row in events if row.get("kind") == "xasset_begin" and
                 row.get("xasset_index") == index]
        strings = [row for row in events if row.get("kind") == "string_call" and
                   row.get("xasset_index") == index]
        loads = [row for row in events if row.get("kind") == "load_stream_call" and
                 row.get("xasset_index") == index and row.get("at_start") is True]
        if len(begin) != 1 or not strings or len(loads) != 1:
            raise ValueError(f"reference root {index} lacks an exact root/string trace")
        root_start = begin[0]["serialized_input_cursor"]
        root_size = loads[0]["size"]
        name_start = strings[0]["serialized_input_cursor"]
        if (begin[0].get("pointer_token") != 0xFFFFFFFFFFFFFFFD or
                name_start != root_start + root_size or
                struct.unpack_from("<Q", body, root_start)[0] != 0xFFFFFFFFFFFFFFFE):
            raise ValueError(f"reference root {index} does not own the traced inline name")
        name_end = body.find(b"\0", name_start, min(len(body), name_start + 4096))
        if name_end < 0:
            raise ValueError(f"reference root {index} name is not bounded")
        name = body[name_start:name_end].decode("utf-8")
        roots.append(dict(index=index, type_id=begin[0]["type_id"], name=name,
                          pointer_token=begin[0]["pointer_token"], root_size=root_size,
                          root_physical=root_start, name_physical=name_start,
                          disposition="reference-only-row-required-for-consumer-table-edge"))
    return dict(schema="replay120-reference-root-identities-v1",
                body_path=str(body_path.resolve()), body_sha256=sha(body_path),
                trace_path=str(trace_path.resolve()), trace_sha256=sha(trace_path),
                reference_count=len(roots), references=roots)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--body", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--indices", type=int, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = extract(args.body, args.trace, args.indices)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()),
                      "references": result["reference_count"]}, indent=2))


if __name__ == "__main__":
    main()
