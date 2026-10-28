# *WIP MW2019 1.20.4-replay asset/executable recompiler and relinker meant for experimental use cases*

# Replay Recompiler

A Windows x64 toolchain for rebuilding the Modern Warfare 2019 Replay 1.20 executable from recovered assembly, initialized data, and C/C++ replacements.

The compiler builds a new PE executable. It places replacements in their original logical positions, expands the layout when necessary, and resolves code, data, imports, relocations, and unwind metadata. The browser-based workstation provides a source editor, symbol browser, asset tools, and build history.

This repository is a compiler and workstation boilerplate. `src/` and the source binding lists start empty. Recovery reconstructs the supplied image; game behavior changes are added only when you author and bind replacements. Game executables, game assets, and analysis databases are supplied separately.

## Supported target

The included analysis profile is for this exact executable:

```text
File:    game_dx12_ship_replay.exe
SHA-256: 68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0
```

Other Replay or retail versions need their own analysis and compatibility work. Setup checks the executable and database identities before recovery.

## Requirements

- Windows x64 and PowerShell 7.
- 64-bit Python 3.12 or newer.
- LLVM, including `clang.exe`, `clang++.exe`, and `llvm-readobj.exe`.
- Visual Studio C++ x64 build tools and a Windows SDK, including `ml64.exe`.
- Git. The optional asset-tool setup also uses CMake and builds third-party tools from source.
- Your matching Replay executable, game installation, and SQLite analysis database.

## SQLite analysis database

The `.sqlite` input is an IDA analysis export created with [Diaphora](https://github.com/joxeankoret/diaphora). The database used for this target uses Diaphora's 3.4 schema. It contains function names, addresses, analysis results, and the identity of the analyzed executable. Supply the exported `.sqlite` file to `-SQLite`.

To create an export:

1. Open the supported executable in IDA and let analysis finish.
2. Run Diaphora in IDA. If it is not installed as a plugin, use **File > Script file** to run Diaphora's `diaphora.py`.
3. Set **Export IDA database to SQLite** to the output `.sqlite` path. Leave **SQLite database to diff against** empty and keep the full executable address range.
4. Complete the export, then pass that file to the setup command below.

[source_catalog.py](tools/source_catalog.py) reads `processor` and `md5sum` from the `program` table and `id`, `name`, `address`, `mangled_function`, and `rva` from `functions`. The database must identify the same executable: setup checks the `pc64` processor, input MD5, and function addresses. Additional `replay_*` tables are project extensions; they are not required for a standard Diaphora export.

The SQLite export supplies analysis metadata. Setup also needs the original executable and the included target-specific analysis files to recover compiler inputs.

## 1. Prepare the workspace

Download or clone this repository, then open PowerShell in its root directory. The examples below use `C:\Games\Replay` for the game and `C:\Analysis` for the database; substitute your own paths.

For the compiler and source editor:

```powershell
.\setup-workstation.ps1 `
    -GameRoot 'C:\Games\Replay' `
    -SQLite 'C:\Analysis\game_dx12_ship_replay.exe.sqlite' `
    -SkipAssetTools
```

Setup creates `.venv`, installs the pinned Python packages and editor files, validates the supplied inputs, and recovers the compiler inputs locally. The first recovery can take several minutes. Your paths are saved in the Git-ignored `replay-project.local.json`.

## 2. Build and verify

Activate the environment created by setup, then build without deployment:

```powershell
.\.venv\Scripts\Activate.ps1
.\build.ps1 -NoDeploy -NoProxy
```

A successful build creates:

```text
build/
  game_dx12_ship_replay_recompiled.exe
  build-report.json
  verification-report.json
  relocation-audit.json
```

The build script runs compiler checks, verifies the rebuilt image, and audits relocations. It stops on unsupported metadata, unresolved symbols, or stale source inputs.

To reuse unchanged, hash-checked assembly objects while recompiling C++:

```powershell
.\build.ps1 -CppOnly -NoDeploy -NoProxy
```

New helpers and globals can use appended sections with `-Grow`. A larger replacement shifts following code and data through the linkerâ€™s address map.

## 3. Use the workstation

```powershell
.\start-workstation.ps1
```

Open **http://127.0.0.1:8126** in your browser.

1. Open **Game source** to browse functions, symbols, and authored files.
2. Edit and save the selected source.
3. Open **Builds & output**, choose **Engine source only**, and select **Compile game**.
4. Review the job log and output files from that page.

Workstation builds publish their verified files under `output/` by default. [WORKSTATION.md](WORKSTATION.md) documents source editing, build profiles, asset support, and output locations.

## C++ replacements

Add authored C++ under `src/`. `source-units.json` starts with no replacements or imports and associates each replacement symbol with a stable function identity once you bind it. Compiler objects supply its size and unwind information; numeric function addresses are not entered in the source-unit map.

Search the recovered catalog with:

```powershell
python tools/source_catalog.py list Dvar_RegisterInt
```

For a new replacement, create the source under `src/`, then bind its symbol using the functionâ€™s unique catalog ID:

```powershell
python tools/source_catalog.py bind <function-id> `
    --source src/MyReplacement.cpp --symbol MyReplacement
```

An `extern "C"` dependency on existing native code is registered with:

```powershell
python tools/source_catalog.py bind-import <function-or-symbol-id> --symbol NativeDependency
```

The workstation provides the same association workflow through its source editor.

## Windows C++ recovery and VS Code

[CPP-RECOVERY.md](CPP-RECOVERY.md) describes selective IDA/RetDec recovery,
experimental Striga lifting, differential tests, promotion, and external source
editing. Open `ReplayCpp.code-workspace` after the setup above. Its build task
compiles and links on Windows and runs the generic image and relocation checks.

`src/recovered/` contains three unbound utility examples and a shared vector
layout header. They are reference candidates, excluded from the top-level build
until explicitly promoted. Source binding lists remain empty. Recovering LLVM IR
does not by itself recover clean C++ or prove the original ABI.

## Optional asset tools

Omit `-SkipAssetTools` to install the pinned GSC and texture tools and build the configured ACTS reader, Lua tools, and DXBC CLI:

```powershell
.\setup-workstation.ps1 `
    -GameRoot 'C:\Games\Replay' `
    -SQLite 'C:\Analysis\game_dx12_ship_replay.exe.sqlite'
```

Asset editing depends on the supported native reader and writer for each type. Cross-version frontend packages, additional script sources, sound-bank generators, and ZoneTool sources are separate inputs where required. See [WORKSTATION.md](WORKSTATION.md) for those workflows.

## Deployment and runtime testing

The commands above build without copying files into the game installation. To use the existing proxy build/deployment integration, configure its source explicitly:

```powershell
.\build.ps1 -ProxySource 'C:\Projects\mw120rproxy'
```

That route requires XMake and a compatible proxy source checkout. It builds and checks the proxy before deployment and refuses to replace runtime files while the game is running. A separately built proxy can be supplied with `-CompilerProxy` instead.

Successful compilation and offline verification do not prove every game mode or asset works at runtime. Test the resulting executable with its matching proxy and required assets.

## Project layout

| Path | Purpose |
| --- | --- |
| `src/` | Empty directory for your C/C++ replacements |
| `tools/` | Recovery, compilation, linking, verification, and asset utilities |
| `tools/native/` | C++ PE linker and its Python bridgeâ€™s format contract |
| `workstation/` | Local server, source management, and browser UI |
| `analysis/replay120/` | Instruction-boundary and reference metadata for the supported target |
| `source-workstation/` | Empty manifests for editor-managed source associations |
| `tests/` | Synthetic, compiler, source-management, and UI regression tests |
| `third_party/` | Selected tool sources, patches, and their existing notices |

[Architecture](docs/ARCHITECTURE.md) explains recovery and linking. [Contributing](CONTRIBUTING.md) covers changes and checks. [Third-party notices](THIRD_PARTY_NOTICES.md) describe the bundled and downloaded tools.

## License

A project-wide license for the recompilerâ€™s original code has not been selected for this repository draft. Third-party files retain their existing licenses and notices.
