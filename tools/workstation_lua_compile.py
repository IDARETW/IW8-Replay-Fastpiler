"""Compile canonical Replay LuaFile chunks with exact target-VM validation.

The image/shader codec module is immutable while existing drafts pin it. Keep
the corrected Lua writer separate and reuse its parsing/tool helpers; do not
alter another asset family's compiler identity to correct Lua serialization.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

from workstation_asset_codecs import (
    DEFAULT_REPLAY_ACTS, DEFAULT_REPLAY_EXECUTABLE, DEFAULT_REPLAY_LUA_PROFILE_NAME,
    REPLAY_LUA_IMAGE_SHA256, _asset_stem, _codec_tool, inspect_luajit_bytecode,
)
from verify_replay_lua_native_compile import load_or_build_profile
from workstation_luajit_chunk import split_luajit_file_payload


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compiler_module_identity() -> dict:
    path = Path(__file__).resolve()
    return {"lua_compiler_module_path": str(path), "lua_compiler_module_sha256": _sha(path.read_bytes())}


def compile_luajit_source_with_receipt(
        source: str, *, acts_exe: Path | None = None,
        replay_executable: Path | None = None, profile_path: Path | None = None,
        profile_name: str = DEFAULT_REPLAY_LUA_PROFILE_NAME,
        asset_name: str = "asset", strip: bool = False) -> tuple[bytes, dict]:
    if not isinstance(source, str) or not source.strip():
        raise ValueError("Lua source must be nonempty text")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", profile_name) is None:
        raise ValueError("Lua compiler profile name must be a plain file stem")
    acts = _codec_tool(acts_exe, "REPLAY_ACTS", DEFAULT_REPLAY_ACTS).resolve(strict=True)
    replay = _codec_tool(replay_executable, "REPLAY_EXECUTABLE", DEFAULT_REPLAY_EXECUTABLE).resolve(strict=True)
    adjacent = acts.with_name(f"{profile_name}.json")
    profile_path = Path(profile_path or os.environ.get("REPLAY_ACTS_PROFILE") or adjacent).resolve(strict=True)
    if profile_path != adjacent:
        raise ValueError("ACTS loads its Lua compiler profile beside the executable; configured profile path must match that adjacent file")
    profile_path, profile = load_or_build_profile(acts, replay, profile_path)
    provenance = profile["__provenance"]
    if provenance["image_sha256"] != REPLAY_LUA_IMAGE_SHA256:
        raise ValueError("Lua compiler profile/executable do not match the pinned Replay image")
    common = acts.with_name("acts-common.dll").resolve(strict=True)
    inputs = {path: _sha(path.read_bytes()) for path in (acts, common, replay, profile_path)}
    module_identity = compiler_module_identity()
    with tempfile.TemporaryDirectory(prefix="replay-lua-compile-") as temporary:
        root = Path(temporary)
        source_path = root / f"{_asset_stem(asset_name)}.lua"
        output_path = source_path.with_suffix(".luac")
        source_path.write_text(source, encoding="utf-8", newline="\n")
        command = [str(acts), "--noUpdater", "ljec", f":{profile_name}",
                   source_path.name, output_path.name, "--exe", str(replay)]
        if strip:
            command.append("--strip")
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120, check=False)
        if result.returncode or not output_path.is_file():
            detail = (result.stderr or result.stdout).strip()[-4000:]
            raise RuntimeError(f"Replay Lua compile failed ({result.returncode}): {detail}")
        payload = output_path.read_bytes()
    # Accept precisely the bytes passed to LuaFile.byteLength. Replay's native
    # LuaFile child stores the one outer NUL that ACTS adds
    # after the LuaJIT zero-length-prototype marker. Accept only that exact
    # established wrapper; the parser rejects every other trailing byte.
    boundary = split_luajit_file_payload(payload, allow_native_nul=True)
    if not boundary.trailing_native_nul:
        raise ValueError("ACTS LuaFile output lacks Replay's required native terminator")
    info = inspect_luajit_bytecode(boundary.chunk)
    if any(_sha(path.read_bytes()) != digest for path, digest in inputs.items()) or compiler_module_identity() != module_identity:
        raise RuntimeError("Lua compiler inputs changed during native bytecode compilation")
    bindings = provenance["bindings"]
    required = {"lua_newstate", "lua_loadx", "lj_cf_string_dump", "writer_buf"}
    if strip:
        required.add("lua_pushboolean")
    compiler = dict(
        name="ACTS Replay ljec", path=str(acts), sha256=inputs[acts],
        common_library_path=str(common), common_library_sha256=inputs[common],
        profile_name=profile_name, profile_path=str(profile_path), profile_sha256=inputs[profile_path],
        profile_database_sha256=provenance.get("database_sha256"),
        profile_catalog_sha256=provenance.get("catalog_sha256") or provenance.get("compiler_catalog_sha256"),
        replay_executable_path=str(replay), replay_executable_sha256=inputs[replay],
        dump_options=dict(strip=strip, compressed=False),
        api_bindings={name: dict(bindings[name]) for name in sorted(required)},
        **module_identity)
    receipt = dict(
        schema="replay120-luajit-compile-receipt-v2", status="target-lua-loadx-reload-pass",
        asset_name=asset_name,
        source=dict(sha256=_sha(source.encode("utf-8")), utf8_bytes=len(source.encode("utf-8"))),
        compiler=compiler,
        result=dict(native_payload_sha256=_sha(payload), native_payload_bytes=len(payload),
                    chunk_bytes=boundary.chunk_bytes,
                    trailing_native_nul=boundary.trailing_native_nul,
                    lua_version=info.version, flags=info.flags, stripped=info.stripped,
                    ffi=info.ffi, fr2=info.fr2, native_lua_loadx_reload="pass",
                    native_lua_loadx_reload_exact_output=True, native_lua_loadx_reload_bytes=len(payload)),
        diagnostics=dict(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
    return payload, receipt
