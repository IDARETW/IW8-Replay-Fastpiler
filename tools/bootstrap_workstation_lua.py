"""Build the pinned LuaJIT decompiler source for unattended asset editing."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


REPOSITORY = "https://github.com/marsinator358/luajit-decompiler-v2.git"
COMMIT = "6a8a0cec48fdf175dddaca5d3fbfe3aa59b5550a"
ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_CONSOLE = "\t\tDWORD consoleProcessId;\n\t\tGetWindowThreadProcessId(window, &consoleProcessId);"
HEADLESS_CONSOLE = "\t\tDWORD consoleProcessId = 0;\n\t\tGetWindowThreadProcessId(window, &consoleProcessId);"
ORIGINAL_MODE = "\t\tisCommandLine = consoleProcessId != GetCurrentProcessId();"
HEADLESS_MODE = "\t\tisCommandLine = !window || argc > 1 || consoleProcessId != GetCurrentProcessId();"
BUILD_SOURCE = '''set_project("replay-luajit-decompiler-v2")
set_languages("cxx20")
target("luajit-decompiler-v2")
    set_kind("binary")
    add_files("main.cpp", "ast/*.cpp", "bytecode/*.cpp", "lua/*.cpp")
    add_defines("_CRT_SECURE_NO_WARNINGS")
    add_cxxflags("/J", "/utf-8", {force = true})
    add_links("user32", "comdlg32")
'''


def run(command, cwd=None):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(map(str, command))}\n"
                           + (result.stderr or result.stdout)[-6000:])
    return result.stdout.strip()


def patch_headless(source: str) -> str:
    """Keep the upstream decompiler unchanged except for unattended CLI exit."""
    if ORIGINAL_CONSOLE in source and ORIGINAL_MODE in source:
        return source.replace(ORIGINAL_CONSOLE, HEADLESS_CONSOLE, 1).replace(ORIGINAL_MODE, HEADLESS_MODE, 1)
    if HEADLESS_CONSOLE in source and HEADLESS_MODE in source:
        return source
    raise ValueError("Pinned Lua decompiler console initialization changed")


def bootstrap(destination: Path) -> dict:
    git, xmake = shutil.which("git"), shutil.which("xmake")
    if not git or not xmake:
        raise RuntimeError("Git, Xmake and Visual Studio x64 C++ tools are required for the Lua decompiler")
    destination = destination.resolve()
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        run([git, "clone", "--no-checkout", REPOSITORY, str(destination)])
        run([git, "checkout", "--detach", COMMIT], destination)
    if not (destination / ".git").exists():
        raise ValueError("Lua tool destination exists but is not a Git checkout")
    if run([git, "remote", "get-url", "origin"], destination).rstrip("/") != REPOSITORY.rstrip("/"):
        raise ValueError("Lua tool checkout origin differs from the pinned source")
    if run([git, "rev-parse", "HEAD"], destination) != COMMIT:
        raise ValueError("Lua tool checkout is not at the pinned source commit")
    changes = run([git, "diff", "--name-only", "HEAD"], destination).splitlines()
    if set(changes) - {"main.cpp"}:
        raise ValueError("Refusing to build a Lua tool checkout with unrelated tracked edits")
    source_path = destination / "main.cpp"
    source = source_path.read_text(encoding="utf-8")
    original = run([git, "show", f"{COMMIT}:main.cpp"], destination) + "\n"
    expected = patch_headless(original)
    if source not in (original, expected):
        raise ValueError("Lua tool main.cpp differs from the reviewed source and CLI patch")
    if source != expected:
        source_path.write_text(expected, encoding="utf-8", newline="\n")
    build_path = destination / "xmake.lua"
    if build_path.exists() and build_path.read_text(encoding="utf-8") != BUILD_SOURCE:
        raise ValueError("Refusing to overwrite an unrelated Lua tool build definition")
    if not build_path.exists():
        build_path.write_text(BUILD_SOURCE, encoding="utf-8", newline="\n")
    run([xmake, "f", "-p", "windows", "-a", "x64", "-m", "release", "--yes"], destination)
    run([xmake, "build", "--yes", "luajit-decompiler-v2"], destination)
    executable = destination / "build/windows/x64/release/luajit-decompiler-v2.exe"
    if not executable.is_file():
        raise RuntimeError("Lua decompiler build did not produce its expected executable")
    source_files = sorted(p for p in destination.rglob("*") if p.is_file()
                          and p.suffix in (".cpp", ".h") and "build" not in p.relative_to(destination).parts
                          and ".git" not in p.relative_to(destination).parts)
    receipt = {"schema": 1, "repository": REPOSITORY, "commit": COMMIT,
               "purpose": "Replay standard LuaJIT v2 source editing",
               "patch": "Initialize console PID; arguments/no console select unattended CLI mode",
               "executable": str(executable), "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
               "source_sha256": {p.relative_to(destination).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in source_files},
               "license": str(destination / "LICENSE")}
    receipt_path = destination / "replay-workstation-lua-bootstrap.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    receipt["receipt"] = str(receipt_path)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(bootstrap(args.destination), indent=2))


if __name__ == "__main__":
    main()
