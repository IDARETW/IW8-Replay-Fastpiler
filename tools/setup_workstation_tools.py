"""Install pinned public codec tools and derive Replay Lua bindings from owner files.

This is intentionally separate from the frozen workstation codec/fastfile
modules. Public releases are downloaded from upstream GitHub release URLs and
verified before installation. Game executables, IDA databases, Oodle, SAB
authoring code, and ACTS binaries are never downloaded by this script.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import struct
import tempfile
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools" / "workstation_toolchain_manifest.json"
EXPECTED_REPLAY_SHA256 = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
EXPECTED_SQLITE_SHA256 = "819e2c6e7f046e0d03f2acd72cb0e7ba51cc7b33cbe51df68ec3a7ef7b36d8d4"
LUA_BINDINGS = {
    "lua_newstate": "lua_newstate",
    "lua_loadx": "lua_loadx",
    "lj_cf_string_dump": "sub_1420A4830",
    "writer_buf": "sub_1420A5EB0",
}
OPTIONAL_LUA_BINDING = ("lua_tolstring", "lua_tolstring")
REDIRECT_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_manifest(path: Path = MANIFEST) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or data.get("platform") != "windows-x64":
        raise ValueError("Unsupported workstation toolchain manifest")
    seen = set()
    for item in data.get("tools", []):
        if item.get("id") in seen:
            raise ValueError("Duplicate tool id in manifest")
        seen.add(item.get("id"))
        parsed = urlparse(item.get("url", ""))
        if parsed.scheme != "https" or parsed.hostname != "github.com":
            raise ValueError(f"Tool URL is not an upstream GitHub release URL: {item.get('id')}")
    return data


def _digest_matches(path: Path, expected: str | None) -> bool:
    return expected is None or sha256(path).casefold() == expected.casefold()


def _download(url: str, destination: Path, expected_sha256: str) -> None:
    if urlparse(url).hostname != "github.com":
        raise ValueError("Refusing a download URL outside the pinned GitHub release origin")
    request = Request(url, headers={"User-Agent": "replay-workstation-tool-setup/1"})
    with urlopen(request, timeout=90) as response, destination.open("wb") as output:
        final_host = (urlparse(response.geturl()).hostname or "").casefold()
        if final_host not in REDIRECT_HOSTS:
            raise ValueError(f"Unexpected release download redirect host: {final_host}")
        shutil.copyfileobj(response, output)
    actual = sha256(destination)
    if actual.casefold() != expected_sha256.casefold():
        destination.unlink(missing_ok=True)
        raise ValueError(f"Release asset SHA-256 mismatch: expected {expected_sha256}, got {actual}")


def _safe_member_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"Unsafe path in release archive: {name!r}")
    if "\\" in name or ":" in name:
        raise ValueError(f"Unsafe path in release archive: {name!r}")
    return path.as_posix()


def _verify_file(path: Path, expected: str | None) -> None:
    if not path.is_file():
        raise FileNotFoundError(path)
    if not _digest_matches(path, expected):
        raise ValueError(f"Pinned file hash mismatch: {path}")


def _install_file(item: dict, root: Path, work: Path) -> dict:
    target = root / item["install_path"]
    expected = item["sha256"]
    if target.exists():
        _verify_file(target, expected)
        return {"id": item["id"], "path": str(target), "sha256": sha256(target), "status": "already-verified"}
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = work / f"{item['id']}.download"
    _download(item["url"], temporary, expected)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary.replace(target)
    _verify_file(target, expected)
    return {"id": item["id"], "path": str(target), "sha256": sha256(target), "status": "installed"}


def _install_zip(item: dict, root: Path, work: Path) -> dict:
    if "members" in item:
        expected_members = item["members"]
    else:
        expected_members = [{"name": item["member"], "sha256": item.get("member_sha256")}]
    by_name = {member["name"]: member for member in expected_members}
    if "install_dir" in item:
        install_dir = root / item["install_dir"]
    else:
        install_dir = root / Path(item["install_path"]).parent
    if install_dir.exists():
        for basename, expectation in by_name.items():
            existing = install_dir / basename
            if existing.is_file() and _digest_matches(existing, expectation.get("sha256")):
                continue
            raise FileExistsError(f"Install target exists but is not the pinned release; refusing overwrite: {existing}")
        return {"id": item["id"], "path": str(install_dir), "status": "already-verified",
                "files": {name: sha256(install_dir / name) for name in by_name}}

    archive = work / f"{item['id']}.zip"
    _download(item["url"], archive, item["archive_sha256"])
    with zipfile.ZipFile(archive) as zf:
        members = {}
        for info in zf.infolist():
            name = _safe_member_name(info.filename)
            if info.is_dir():
                continue
            # Do not accept symlinks or special-file entries from archives.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f"Refusing archive symlink: {name}")
            basename = PurePosixPath(name).name
            if basename in by_name:
                if basename in members:
                    raise ValueError(f"Duplicate required archive member: {basename}")
                members[basename] = (info, name)
        missing = set(by_name) - set(members)
        if missing:
            raise ValueError(f"Release archive is missing required files: {sorted(missing)}")
        stage = work / f"{item['id']}-stage"
        stage.mkdir()
        for basename, expectation in by_name.items():
            info, archive_name = members[basename]
            data = zf.read(info)
            actual = hashlib.sha256(data).hexdigest()
            if expectation.get("sha256") and actual.casefold() != expectation["sha256"].casefold():
                raise ValueError(f"Release member SHA-256 mismatch for {basename}: {actual}")
            (stage / basename).write_bytes(data)

    install_dir.parent.mkdir(parents=True, exist_ok=True)
    stage.replace(install_dir)
    return {"id": item["id"], "path": str(install_dir), "status": "installed",
            "files": {name: sha256(install_dir / name) for name in by_name}}


def install_public_tools(root: Path = ROOT, manifest_path: Path = MANIFEST) -> dict:
    manifest = load_manifest(manifest_path)
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".replay-tool-setup-", dir=root) as temp:
        work = Path(temp)
        outcomes = []
        for item in manifest["tools"]:
            if item.get("install_default") is False:
                continue
            if item["kind"] == "file":
                outcomes.append(_install_file(item, root, work))
            elif item["kind"] in ("zip-member", "zip-members"):
                outcomes.append(_install_zip(item, root, work))
            else:
                raise ValueError(f"Unsupported manifest artifact kind: {item['kind']}")
    return {"schema": 1, "manifest_sha256": sha256(manifest_path), "installed": outcomes,
            "owner_supplied": [item["id"] for item in manifest.get("owner_supplied", [])],
            "acts_source_bootstrap": manifest.get("source_built", [])}


def pe_image_base(executable: Path) -> int:
    with executable.open("rb") as stream:
        head = stream.read(0x40)
        if len(head) < 0x40 or head[:2] != b"MZ":
            raise ValueError("Replay executable has no DOS MZ header")
        pe_at = struct.unpack_from("<I", head, 0x3C)[0]
        stream.seek(pe_at)
        coff = stream.read(24)
        if len(coff) != 24 or coff[:4] != b"PE\0\0":
            raise ValueError("Replay executable has an invalid PE signature")
        optional_size = struct.unpack_from("<H", coff, 20)[0]
        optional = stream.read(optional_size)
    if len(optional) < 32 or struct.unpack_from("<H", optional)[0] != 0x20B:
        raise ValueError("Replay executable is not a PE32+ image")
    return struct.unpack_from("<Q", optional, 24)[0]


def build_lua_catalog_and_profile(replay_exe: Path, sqlite_path: Path, acts_exe: Path,
                                  output_dir: Path) -> dict:
    replay_exe, sqlite_path, acts_exe = map(lambda p: Path(p).resolve(), (replay_exe, sqlite_path, acts_exe))
    for path in (replay_exe, sqlite_path, acts_exe):
        if not path.is_file():
            raise FileNotFoundError(path)
    image_hash, database_hash = sha256(replay_exe), sha256(sqlite_path)
    if image_hash != EXPECTED_REPLAY_SHA256:
        raise ValueError("Owner Replay executable hash is not the pinned Replay 1.20 image")
    if database_hash != EXPECTED_SQLITE_SHA256:
        raise ValueError("Owner Replay SQLite hash is not the pinned matching analysis database")
    base = pe_image_base(replay_exe)
    uri = sqlite_path.as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        rows = db.execute("SELECT id,name,address,mangled_function FROM functions ORDER BY id").fetchall()
    functions_by_name: dict[str, list[dict]] = {}
    functions = []
    for row_id, name, address, mangled in rows:
        address_value = int(address, 0) if isinstance(address, str) else int(address)
        rva = address_value - base
        if not 0 < rva < 0x80000000:
            continue
        identity = "fn_" + hashlib.sha256(f"{image_hash}:{rva:08x}".encode("ascii")).hexdigest()[:16]
        aliases = sorted({name, mangled} - {None, ""})
        item = {"id": identity, "database_id": row_id, "name": name, "rva": rva, "aliases": aliases}
        functions.append(item)
        for candidate in aliases:
            functions_by_name.setdefault(candidate, []).append(item)
    if not functions:
        raise ValueError("Owner SQLite database has no in-image function rows")

    scans, bound = {}, {}
    for acts_name, catalog_name in LUA_BINDINGS.items():
        matches = functions_by_name.get(catalog_name, [])
        if len(matches) != 1:
            raise ValueError(f"SQLite function name must resolve uniquely: {catalog_name} ({len(matches)} matches)")
        match = matches[0]
        scans[acts_name] = {"type": "Offset", "scan": f"0x{match['rva']:x}"}
        bound[acts_name] = {"catalog_name": catalog_name, "function_id": match["id"], "rva": match["rva"]}
    optional = functions_by_name.get(OPTIONAL_LUA_BINDING[1], [])
    if len(optional) == 1:
        match = optional[0]
        scans[OPTIONAL_LUA_BINDING[0]] = {"type": "Offset", "scan": f"0x{match['rva']:x}"}
        bound[OPTIONAL_LUA_BINDING[0]] = {"catalog_name": match["name"], "function_id": match["id"],
                                         "rva": match["rva"], "purpose": "optional diagnostic error extraction"}

    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    catalog = {"schema": 1, "image_sha256": image_hash, "database_sha256": database_hash,
               "image_base": base, "function_count": len(functions), "functions": functions,
               "source": "owner-supplied Replay EXE PE headers plus owner-supplied SQLite functions table"}
    catalog_path = output_dir / "replay120-compiler-function-catalog.json"
    catalog_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    profile = {"scans": {"lua": scans}, "__provenance": {
        "target": "Call of Duty: Modern Warfare 2019 Replay 1.20",
        "image_sha256": image_hash, "database_sha256": database_hash,
        "compiler_catalog_sha256": sha256(catalog_path),
        "acts_sha256": sha256(acts_exe), "bindings": bound,
        "addresses_derived_from": "SQLite function names/addresses minus PE ImageBase",
        "manual_rvas": False, "local_analysis_evidence_required": False,
    }}
    profile_path = output_dir / "replay120_lua_native.json"
    profile_path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    return {"catalog": str(catalog_path), "catalog_sha256": sha256(catalog_path),
            "profile": str(profile_path), "profile_sha256": sha256(profile_path),
            "image_sha256": image_hash, "database_sha256": database_hash, "bindings": bound}


def validate_owner_config(path: Path) -> dict:
    config = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    manifest = load_manifest()
    expectations = {item["id"]: item for item in manifest["owner_supplied"]}
    checked = {}
    for key, item in expectations.items():
        value = config.get(key)
        required = key in ("replay_executable", "replay_sqlite")
        if not value:
            if required:
                raise ValueError(f"Owner config is missing required path: {key}")
            checked[key] = {"status": "not-configured"}
            continue
        target = Path(value).expanduser().resolve(strict=True)
        actual = sha256(target)
        if item.get("sha256") and actual.casefold() != item["sha256"].casefold():
            raise ValueError(f"Owner-supplied {key} identity hash mismatch: {target}")
        if item.get("filename") and target.name.casefold() != item["filename"].casefold():
            raise ValueError(f"Owner-supplied {key} must be named {item['filename']}")
        checked[key] = {"path": str(target), "sha256": actual, "status": "verified"}
    return checked


def select_dxbc_tool(root: Path = ROOT, *, use_source_built: bool | None = None,
                     manifest_path: Path = MANIFEST) -> dict:
    """Resolve the configured DXBC CLI and bind setup config to its verified bytes.

    New setups follow the source-built default declared by the manifest. The
    pinned public release remains available only through explicit legacy
    selection; neither path overwrites the other executable.
    """
    root = Path(root).resolve(strict=True)
    manifest_path = Path(manifest_path).resolve(strict=True)
    manifest = load_manifest(manifest_path)
    source_rows = [item for item in manifest.get("source_built", [])
                   if item.get("id") == "dxbc_decompiler_source"]
    if use_source_built is None:
        if len(source_rows) != 1 or not isinstance(source_rows[0].get("install_default"), bool):
            raise ValueError("toolchain manifest must declare one source-built DXBC default policy")
        use_source_built = source_rows[0]["install_default"]
    if not use_source_built:
        rows = [item for item in manifest.get("tools", []) if item.get("id") == "dxbc_decompiler"]
        if len(rows) != 1:
            raise ValueError("toolchain manifest must identify exactly one public DXBC CLI")
        row = rows[0]
        members = [item for item in row.get("members", []) if item.get("name") == "cmd_Decompiler.exe"]
        if len(members) != 1:
            raise ValueError("public DXBC tool must pin exactly one cmd_Decompiler.exe")
        relative = PurePosixPath(row.get("install_dir", "")) / "cmd_Decompiler.exe"
        if relative.is_absolute() or "\\" in str(relative) or ":" in str(relative) or ".." in relative.parts:
            raise ValueError("public DXBC tool path is unsafe")
        target = (root / Path(*relative.parts)).resolve(strict=True)
        if not target.is_relative_to(root) or target.name != "cmd_Decompiler.exe":
            raise ValueError("public DXBC tool path escapes the workstation root")
        expected = members[0].get("sha256")
        _verify_file(target, expected)
        return {"id": "dxbc", "selection": "public", "path": str(target),
                "sha256": sha256(target), "expected_sha256": expected,
                "source_package_manifest_sha256": None}

    rows = source_rows
    if len(rows) != 1:
        raise ValueError("toolchain manifest must identify exactly one source-built DXBC CLI")
    row = rows[0]
    relative = PurePosixPath(row.get("install_dir", ""))
    receipt_name = row.get("receipt")
    executable_name = row.get("executable")
    if (relative.is_absolute() or not relative.parts or "\\" in str(relative) or ":" in str(relative) or
            any(part in ("", ".", "..") for part in relative.parts) or row.get("install_default") is not True or
            not isinstance(receipt_name, str) or receipt_name != "bootstrap-receipt.json" or
            executable_name != "cmd_Decompiler.exe"):
        raise ValueError("source-built DXBC paths differ from the reviewed toolchain layout")
    install_dir = (root / Path(*relative.parts)).resolve(strict=True)
    if not install_dir.is_relative_to(root):
        raise ValueError("source-built DXBC installation escapes the workstation root")
    receipt_path = install_dir / receipt_name
    executable = install_dir / executable_name
    if not receipt_path.is_file() or receipt_path.is_symlink() or not executable.is_file() or executable.is_symlink():
        raise FileNotFoundError("source-built DXBC executable or receipt is missing or linked")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    expected_package = row.get("source_package_manifest_sha256")
    if (receipt.get("schema") != "replay120-dxbc-source-bootstrap-v1" or
            receipt.get("status") != "pass" or
            receipt.get("source_package_manifest_sha256") != expected_package or
            receipt.get("executable") != executable_name or
            not re.fullmatch(r"[0-9a-fA-F]{64}", str(receipt.get("output_sha256", "")))):
        raise ValueError("source-built DXBC bootstrap receipt does not match the pinned manifest")
    source_package = PurePosixPath(row.get("source_package", ""))
    if (source_package.is_absolute() or not source_package.parts or "\\" in str(source_package) or
            ":" in str(source_package) or any(part in ("", ".", "..") for part in source_package.parts)):
        raise ValueError("source-built DXBC package path is unsafe")
    package_manifest = root / Path(*source_package.parts) / "source-package-manifest.json"
    package_manifest = package_manifest.resolve(strict=True) if package_manifest.exists() else package_manifest
    if (not package_manifest.is_relative_to(root) or not package_manifest.is_file() or
            package_manifest.is_symlink() or sha256(package_manifest) != expected_package):
        raise ValueError("source-built DXBC source package no longer matches the pinned manifest")
    package = json.loads(package_manifest.read_text(encoding="utf-8"))
    if receipt.get("source_patch_sha256") != package.get("source_patch", {}).get("sha256"):
        raise ValueError("source-built DXBC receipt patch pin differs from the source package")
    _verify_file(executable, receipt["output_sha256"])
    return {"id": "dxbc", "selection": "source-built", "path": str(executable),
            "sha256": sha256(executable), "expected_sha256": receipt["output_sha256"],
            "source_package_manifest_sha256": expected_package,
            "bootstrap_receipt_sha256": sha256(receipt_path)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="workstation checkout root")
    parser.add_argument("--install-public", action="store_true", help="download and install pinned GitHub releases")
    parser.add_argument("--owner-config", type=Path, help="validate owner-supplied Replay EXE/SQLite/DLL paths")
    parser.add_argument("--acts", type=Path, help="built Replay-compatible ACTS CLI, for native Lua profile generation")
    parser.add_argument("--generate-lua-profile", action="store_true",
                        help="derive a minimal function catalog/profile from owner EXE+SQLite, without local generated evidence")
    parser.add_argument("--profile-output", type=Path, help="profile/catalog directory; defaults to --acts parent")
    parser.add_argument("--receipt", type=Path, help="write setup receipt here")
    parser.add_argument("--select-dxbc", action="store_true",
                        help="resolve the DXBC CLI and its verified hash for workstation configuration")
    parser.add_argument("--use-public-dxbc", action="store_true",
                        help="select the pinned public DXBC release as an explicit legacy fallback")
    args = parser.parse_args()
    if args.use_public_dxbc and not args.select_dxbc:
        parser.error("--use-public-dxbc requires --select-dxbc")
    result = {"schema": 1, "manifest_sha256": sha256(MANIFEST), "public_tools": None,
              "owner_inputs": None, "lua_profile": None, "dxbc_selection": None}
    if args.install_public:
        result["public_tools"] = install_public_tools(args.root)
    if args.owner_config:
        result["owner_inputs"] = validate_owner_config(args.owner_config)
    if args.generate_lua_profile:
        if not args.owner_config or not args.acts:
            parser.error("--generate-lua-profile requires --owner-config and --acts")
        owner = json.loads(args.owner_config.read_text(encoding="utf-8-sig"))
        output_dir = args.profile_output or args.acts.resolve().parent
        result["lua_profile"] = build_lua_catalog_and_profile(
            Path(owner["replay_executable"]), Path(owner["replay_sqlite"]), args.acts, output_dir)
    if args.select_dxbc:
        result["dxbc_selection"] = select_dxbc_tool(
            args.root, use_source_built=False if args.use_public_dxbc else None,
            manifest_path=MANIFEST)
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
