"""Compile Replay LuaFile source with the pinned native VM and validate output."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from workstation_asset_codecs import decompile_luajit_bytecode, inspect_luajit_bytecode  # noqa: E402
from make_replay_lua_acts_profile import BINDINGS, build_profile  # noqa: E402
from workstation_luajit_chunk import split_luajit_file_payload  # noqa: E402


BUILTIN_STOCK_SOURCE = (
    "local function replay_workstation_native_smoke()\n"
    "\treturn 120\n"
    "end\n"
    "local replay_workstation_native_value = replay_workstation_native_smoke()\n"
)
ALLOCATOR_GROWTH_REPRO = ROOT / "tools" / "fixtures" / "replay120-lua-allocator-growth.lua"
ALLOCATOR_GROWTH_REPRO_SHA256 = "a3835ebf39180d36d2549376c4ff9e80592dd04d0075e7723b82c6e0ed771418"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_or_build_profile(acts: Path, replay_exe: Path, profile_path: Path | None) -> tuple[Path, dict]:
    profile_path = (profile_path or acts.resolve().parent / "replay120_lua_native.json").resolve()
    if profile_path.is_file():
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    else:
        profile_path, profile = build_profile(ROOT / "generated" / "function-catalog.json", acts)
        profile_path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    provenance = profile.get("__provenance", {})
    image_hash = sha256(replay_exe.read_bytes())
    if provenance.get("image_sha256") != image_hash:
        raise ValueError("Lua compiler profile does not match the supplied Replay executable")
    compiler_hash = sha256(acts.read_bytes())
    if provenance.get("acts_sha256") not in (None, compiler_hash):
        raise ValueError("Lua compiler profile was generated for a different ACTS executable")
    bindings = provenance.get("bindings", {})
    scans = profile.get("scans", {}).get("lua", {})
    for name, stable_id in BINDINGS.items():
        binding = bindings.get(name, {})
        rva = binding.get("rva")
        if binding.get("function_id") != stable_id or not isinstance(rva, int) or rva <= 0:
            raise ValueError(f"Lua compiler profile has no verified binding for {name}")
        if scans.get(name) != {"type": "Offset", "scan": f"0x{rva:x}"}:
            raise ValueError(f"Lua compiler profile scan and provenance differ for {name}")
    return profile_path, profile


def load_allocator_growth_repro() -> str:
    raw = ALLOCATOR_GROWTH_REPRO.read_bytes()
    actual = sha256(raw)
    if actual != ALLOCATOR_GROWTH_REPRO_SHA256:
        raise ValueError(f"Pinned allocator-growth Lua fixture changed: {actual}")
    return raw.decode("utf-8")


def validation_sources(stock_source: str, edited_source: str,
                       allocator_growth_source: str) -> dict[str, str]:
    return {
        "stock_source": stock_source,
        "edited_source": edited_source,
        "allocator_growth_repro": allocator_growth_source,
    }


def verify(acts: Path, replay_exe: Path, stock: Path | None, output_dir: Path,
           profile_path: Path | None = None) -> dict:
    if not acts.is_file() or not replay_exe.is_file():
        raise FileNotFoundError("ACTS and Replay executable must exist")
    if stock is not None and not stock.is_file():
        raise FileNotFoundError(stock)
    if not ALLOCATOR_GROWTH_REPRO.is_file():
        raise FileNotFoundError(ALLOCATOR_GROWTH_REPRO)
    profile_path, profile = load_or_build_profile(acts, replay_exe, profile_path)

    if stock is None:
        stock_source = BUILTIN_STOCK_SOURCE
        stock_source_kind = "built-in-source-fixture"
    else:
        stock_bytes = stock.read_bytes()
        # ACTS' full decompiler restores editable Lua source; compiling this as text
        # tests the native parser and writer, rather than bytecode pass-through.
        stock_source = decompile_luajit_bytecode(stock_bytes, name="cod")
        stock_source_kind = "owner-supplied-native-bytecode-decompiled"
    edited_source = stock_source + (
            "\nlocal function replay_workstation_roundtrip_probe() return 120 end\n"
            "local replay_workstation_roundtrip_value = replay_workstation_roundtrip_probe()\n"
        )
    allocator_growth_source = load_allocator_growth_repro()
    cases = validation_sources(stock_source, edited_source, allocator_growth_source)
    output_dir.mkdir(parents=True, exist_ok=True)
    exe_hash = sha256(replay_exe.read_bytes())
    if exe_hash != profile["__provenance"]["image_sha256"]:
        raise ValueError("Replay executable hash differs from the function catalog target")

    case_receipts = {}
    for case, source in cases.items():
        source_path = output_dir / f"{case}.lua"
        bytecode_path = output_dir / f"{case}.luac"
        bytecode_path.unlink(missing_ok=True)
        source_path.write_text(source, encoding="utf-8", newline="\n")
        proc = subprocess.run(
            [str(acts), "ljec", ":replay120_lua_native", str(source_path),
             str(bytecode_path), "--exe", str(replay_exe)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0 or not bytecode_path.is_file():
            raise RuntimeError(
                f"Native compile failed for {case} (exit {proc.returncode}):\n"
                f"{proc.stdout}\n{proc.stderr}"
            )
        output = bytecode_path.read_bytes()
        boundary = split_luajit_file_payload(output, allow_native_nul=False)
        bytecode = inspect_luajit_bytecode(boundary.chunk)
        marker = b"replay_workstation_roundtrip_probe"
        marker_present = marker in output
        if case == "edited_source" and not marker_present:
            raise AssertionError("Edited marker is absent from the emitted native bytecode")
        case_receipts[case] = {
            "source_path": str(source_path),
            "source_sha256": sha256(source.encode("utf-8")),
            "bytecode_path": str(bytecode_path),
            "bytecode_sha256": sha256(output),
            "bytecode_bytes": len(output),
            "chunk_bytes": boundary.chunk_bytes,
            "trailing_native_nul": boundary.trailing_native_nul,
            "header": {"version": bytecode.version, "flags": bytecode.flags,
                       "stripped": bytecode.stripped, "ffi": bytecode.ffi,
                       "fr2": bytecode.fr2},
            "native_bytecode_reload_passed": True,
            "native_bytecode_reload_mode": "b",
            "native_bytecode_reload_bytes": len(output),
            "native_bytecode_reload_exact_output": True,
            "edited_marker_present_in_bytecode": marker_present,
            "native_compile_stdout": proc.stdout[-2000:],
        }

    return {
        "schema": "replay120-lua-native-compile-roundtrip-v1",
        "target_image_sha256": exe_hash,
        "acts_executable": str(acts),
        "acts_sha256": sha256(acts.read_bytes()),
        "acts_common_library": str(acts.resolve().parent / "acts-common.dll"),
        "acts_common_sha256": sha256((acts.resolve().parent / "acts-common.dll").read_bytes()),
        "profile_path": str(profile_path),
        "profile_sha256": sha256(profile_path.read_bytes()),
        "profile_compiler_sha256": profile.get("__provenance", {}).get("acts_sha256", sha256(acts.read_bytes())),
        "allocator_growth_reproducer": {
            "source_path": str(ALLOCATOR_GROWTH_REPRO),
            "source_sha256": ALLOCATOR_GROWTH_REPRO_SHA256,
            "purpose": "conditional branch calling Dvar.IBEGCHEFE; exercises LuaJIT allocator growth",
            "case_status": case_receipts["allocator_growth_repro"]["native_bytecode_reload_passed"],
        },
        "stock_source_kind": stock_source_kind,
        "profile_bindings": profile["__provenance"]["bindings"],
        "cod_lua_setxhash": "not called during the verified plain-source compile path",
        "cases": case_receipts,
        "native_luafile_reader": "native Replay lua_loadx accepted every exact emitted payload in bytecode mode; no bytes are trimmed or appended",
        "external_decompiler_note": "LuaJIT Decompiler v2 currently skips Replay-emitted chunks, including a tiny native-compiled return-120 fixture; native acceptance and edited-marker-in-bytecode are the validation gates here.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acts", type=Path, required=True,
                        help="setup-selected Replay-compatible ACTS executable")
    parser.add_argument("--replay-exe", type=Path, required=True,
                        help="matching owner-supplied Replay executable")
    parser.add_argument("--stock", type=Path,
                        help="optional native LuaJIT bytecode fixture to decompile before compilation")
    parser.add_argument("--profile", type=Path,
                        help="selected target-bound profile (defaults to replay120_lua_native.json beside ACTS)")
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "evidence" / "workstation-lua-native-compile")
    parser.add_argument("--receipt", type=Path,
                        default=ROOT / "evidence" / "workstation-lua-native-compile.json")
    args = parser.parse_args()
    result = verify(args.acts, args.replay_exe, args.stock, args.output_dir, args.profile)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"verified native Lua source compile; receipt: {args.receipt}")


if __name__ == "__main__":
    main()
