import json
import argparse
import struct
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "type16-asset981.dxbc"


def read_chunks(data: bytes):
    count = struct.unpack_from("<I", data, 28)[0]
    out = []
    for index in range(count):
        offset = struct.unpack_from("<I", data, 32 + index * 4)[0]
        tag = data[offset:offset + 4]
        size = struct.unpack_from("<I", data, offset + 4)[0]
        payload = data[offset + 8:offset + 8 + size]
        out.append((tag, payload))
    return out


def write_container(template: bytes, chunks):
    header = bytearray(template[:24])
    payload_start = 32 + 4 * len(chunks)
    offsets = []
    payload = bytearray()
    for tag, content in chunks:
        offsets.append(payload_start + len(payload))
        payload.extend(tag)
        payload.extend(struct.pack("<I", len(content)))
        payload.extend(content)
    total = payload_start + len(payload)
    directory = struct.pack("<II", total, len(chunks)) + b"".join(struct.pack("<I", x) for x in offsets)
    return bytes(header) + directory + bytes(payload)


def mutate_token(data: bytes, *, version=None, token_count_delta=0):
    chunks = read_chunks(data)
    for index, (tag, payload) in enumerate(chunks):
        if tag not in (b"SHDR", b"SHEX"):
            continue
        changed = bytearray(payload)
        if version is not None:
            struct.pack_into("<I", changed, 0, version)
        if token_count_delta:
            count = struct.unpack_from("<I", changed, 4)[0]
            struct.pack_into("<I", changed, 4, count + token_count_delta)
        chunks[index] = (tag, bytes(changed))
        break
    return write_container(data, chunks)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=Path, default=ROOT / "build" / "cmd_Decompiler-dxbc-prototype.exe")
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    parser.add_argument("--receipt-output", type=Path, default=ROOT / "fixtures" / "strict-container-test-receipt-v1.json")
    args = parser.parse_args()
    cli = args.cli.resolve(strict=True)
    original = args.fixture.resolve(strict=True).read_bytes()
    chunks = read_chunks(original)
    code = next(chunk for chunk in chunks if chunk[0] in (b"SHDR", b"SHEX"))
    no_code = [(b"NONE" if tag in (b"SHDR", b"SHEX") else tag, payload) for tag, payload in chunks]
    duplicate_code = chunks + [(b"SHEX", code[1])]
    cases = [
        ("missing shader token chunk", write_container(original, no_code)),
        ("duplicate shader token chunk", write_container(original, duplicate_code)),
        ("shader token count mismatch", mutate_token(original, token_count_delta=1)),
        # Shader model 4.0, stage otherwise valid.
        ("unsupported shader model", mutate_token(original, version=(1 << 16) | (4 << 4))),
        # Geometry stage 2 is not part of the Replay shader type mapping.
        ("unsupported shader stage", mutate_token(original, version=(2 << 16) | (5 << 4))),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix="dxbc-cli-container-") as td:
        base = Path(td)
        for index, (label, data) in enumerate(cases):
            source = base / f"bad-{index}.dxbc"
            source.write_bytes(data)
            result = subprocess.run([str(cli), "-d", "-V", str(source)], capture_output=True, text=True)
            asm = source.with_suffix(".asm")
            accepted = result.returncode == 0 or asm.exists()
            if accepted:
                raise AssertionError(f"{label}: invalid container accepted or output emitted: {result.stdout} {result.stderr}")
            results.append({"case": label, "returncode": result.returncode, "rejected": True,
                            "diagnostic": (result.stdout + result.stderr).strip()[-1000:]})
    receipt = {"schema": "replay120-dxbc-cli-strict-container-tests-v1", "status": "pass",
               "cases": len(results), "passed": len(results), "results": results}
    out = args.receipt_output.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in receipt.items() if k != "results"}, indent=2))


if __name__ == "__main__":
    main()
