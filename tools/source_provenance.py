"""Check all compiler-reported C++ inputs before linking or deployment."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def validate_inputs(inputs):
    # Deduplicate only inside this validation boundary. Never carry hashes
    # across calls: callers revalidate after producing or staging artifacts.
    actual_by_path = {}
    for item in inputs:
        path = Path(item['path'])
        # Build publication is the final provenance gate. Rehash the bytes
        # themselves: on Windows, restoring a file's size and mtime can leave
        # both unchanged after an in-place rewrite, so stat-keyed digest caches
        # can accept content that no longer matches the pinned build input.
        key = str(path.resolve())
        actual = actual_by_path.get(key)
        if actual is None:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            actual_by_path[key] = actual
        if actual != item['sha256']:
            raise ValueError(f'Compilation input changed; rebuild: {path}')


def parse_dependencies(text: str) -> list[Path]:
    prefix, separator, text = text.partition(":")
    if not separator or prefix.strip() != "replay_deps":
        raise ValueError("Unexpected compiler dependency target")
    text = text.replace("\\\r\n", "").replace("\\\n", "")
    words, word = [], []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and (text[index + 1].isspace() or text[index + 1] in "\\#:"):
            index += 1
            word.append(text[index])
        elif char.isspace():
            if word: words.append("".join(word)); word = []
        else:
            word.append(char)
        index += 1
    if word: words.append("".join(word))
    if not words: raise ValueError("Empty compiler dependency list")
    return sorted({Path(word.replace("$$", "$" )).resolve() for word in words})


def snapshots(paths: list[Path]) -> list[dict]:
    return [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in paths]


def validate_record(record: dict, root: Path = ROOT) -> None:
    for path, expected in ((root / record["source"], record["source_sha256"]),
                           (root / record["object"], record["object_sha256"])):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"Prepared source/object changed: {path}")
    dependencies = record.get("dependencies")
    if Path(record["source"]).suffix == ".cpp":
        if not dependencies:
            raise ValueError(f"C++ header provenance missing; recompile: {record['source']}")
        if (root / record["source"]).resolve() not in {Path(item["path"]).resolve() for item in dependencies}:
            raise ValueError(f"Dependency list omits its C++ source: {record['source']}")
    for dependency in dependencies or []:
        path = Path(dependency["path"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != dependency["sha256"]:
            raise ValueError(f"C++ compilation input changed; recompile: {path}")


def validate_report(report: dict) -> None:
    compiler_inputs = []
    if report.get('backend_version', 1) >= 2:
        if not report.get('backend_inputs') or not report.get('recovery_inputs'):
            raise ValueError('Backend/recovery provenance is missing')
        validate_inputs(report['backend_inputs'] + report['recovery_inputs'])
    callbacks = [row['compilation'] for row in report.get('protected_callback_thunks', [])]
    for record in report["cpp"] + report["assembly"] + [report["native_assembly"]] + callbacks:
        validate_record(record)
        if report.get('backend_version', 1) >= 2:
            if not record.get('compiler'):
                raise ValueError('Compiler identity is missing')
            compiler_inputs.append(record['compiler'])
    if compiler_inputs:
        validate_inputs(compiler_inputs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    validate_report(json.loads((args.build / "build-report.json").read_text()))
    print("Prepared source, object and C++ header hashes verified")
