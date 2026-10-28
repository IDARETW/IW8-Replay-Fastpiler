# Editable Replay C++ on Windows

Open `ReplayCpp.code-workspace` in VS Code. Compilation, COFF generation,
Replay PE linking and game execution run on Windows. The optional rev.ng
adapter runs only recovery/analysis in WSL; ordinary builds do not require WSL.

The pinned Replay executable is AMD64 with PE linker version 14.16 and a
dominant Rich-header build of 27031. These identify MSVC 19.16 / v141
(Visual Studio 2017 15.9) as the likely main toolchain. This is a toolchain
inference, not proof that every linked component used the same compiler.
The target executable must be supplied locally; no executable or lifted game
code is bundled with this repository.

Recovery proceeds per function: select its stable identity and native spans,
retain assembly and decompiler/IR references, reconstruct readable C++ with an
explicit ABI and data layout, compare it with the native instructions, then
register the replacement in the existing Windows relinker. Unrecovered
functions retain their assembly implementation. Lifted IR does not restore
the original C++ class design, names, templates or source formatting.

## Recover and inspect

```powershell
python tools/cpp_recovery.py pilot
python tools/cpp_recovery.py recover fn_2a385ed3a736c866
python tools/cpp_recovery.py recover fn_2a385ed3a736c866 --backend retdec
python tools/cpp_recovery.py inspect <record.json>
```

Each attempt has a separate folder under `analysis/cpp-recovery/<function-id>`.
`native.asm` contains the selected native instructions. IDA output remains
reference text. RetDec produces candidate C and lifted `.ll`/`.bc`; its output
is not automatically installed as a replacement. `inspect` verifies artifact
hashes. These IR files are lifted machine-code representations, not the
original compiler's IR. Tool-specific LLVM versions remain separate.

`python tools/setup_cpp_recovery.py` installs RetDec v5.0 and its required
OpenSSL runtime into `.toolchains`, using pinned archive hashes. It requires
7-Zip. No global environment changes are made; existing differing files stop
installation. Static library signature databases are omitted because selective
recovery disables that analysis. The full-image DSM output pass is disabled;
the selected assembly listing is already retained.

For optional rev.ng, configure `cpp_recovery.revng.distro` and
`cpp_recovery.revng.executable` in `replay-project.local.json`. The executable
must be an absolute Linux path inside the selected WSL distribution. Run
`recover <id> --backend revng`. This adapter does not use rev.ng's Linux ELF
recompiler. Missing WSL or an unsupported backend yields a blocked record.
Model/type import and rev.ng output require separate validation on that host.

## Striga experiment

`python tools/evaluate_striga.py` evaluates the pinned Striga commit
`f2fbb7d15cb32f6d3571b4fc41a27d62ee2bc819` in the local
`.toolchains/striga-source` and `.toolchains/striga-py314` directories. This
experiment uses Striga 0.1.1, llvm-nanobind 21.1.6.3 and icicle-emu 0.0.11;
the Python packages stay isolated from the compiler's ordinary dependencies.
The installed Windows wheels run with Python 3.14. All IR-to-object compilation
uses Windows Clang with the Microsoft x64 target.

The evaluator restricts control flow to the selected function's proven native
spans. It retains raw and optimized IR and records the upstream source hashes.
For `I_stricmp`, an explicit RCX/RDX argument and 32-bit EAX return wrapper
compiled to Windows COFF and passed 648 native instruction comparisons.
`I_stristr` lifted to IR but still needs external-call ABI bindings.
`Vec3Normalize` stopped at the unsupported `movss` instruction.

Results are in `analysis/cpp-recovery/striga-evaluation/report.json`. This is an
experimental analysis path: it does not emit editable C++ or install a lifted
replacement. The registered C++ utilities below remain the tested build inputs.

## Validate and promote

Edit candidate C++ separately from backend output. The three utility examples
are in `src/recovered/`. Their shared vector header records the complete
three-float layout and compile-time offset/size/alignment checks.

```powershell
python tools/test_cpp_recovery_pilot.py
python tools/cpp_recovery.py validate src/recovered/I_stricmp.cpp --symbol I_stricmp
python tools/cpp_recovery.py promote fn_2a385ed3a736c866 src/recovered/I_stricmp.cpp --evidence analysis/cpp-recovery/pilot-tests/I_stricmp.json
```

Promotion requires explicit ABI review and passing differential evidence for
the exact function, image, source and recorded local headers. It uses the
existing source workspace to install a managed C++ replacement. Compilation
alone does not establish behavioral equivalence. The vector source retains a
full XMM0 return; the function's recovered display name is not an ABI authority.

The differential harness executes original Replay instructions and actual
Windows COFF code in Unicorn. It checks returns, memory, caller stack,
nonvolatile GPR/SIMD registers and vector MXCSR effects. Substring tests compare
the ordered signed arguments to the same modeled locale callback on both
sides. They do not prove a real locale runtime or live-game behavior.

## Edit an installed function in VS Code

1. Run **Replay: begin external edit**, selecting its stable ID. The result
   identifies the authored file and an immutable revision ticket.
2. Edit and save that file in VS Code.
3. Run **Replay: register current external edit** with the file selected.
4. Run **Replay: build and verify on Windows** or press Ctrl+Shift+B.

Registration compiles a Windows object and checks included-header hashes. It
advances matching source-unit and cached revisions under the compiler lock.
The original revision remains in history. Metadata conflicts, compiler errors,
or edits made during compilation stop registration without replacing either
source version. A ticket can be consumed once. For a concurrent managed-editor
change, resolve the versions first and begin a fresh edit session.

The build task emits `build-cpp-recovery/game_dx12_ship_replay_recompiled.exe`
and runs source/recovery regressions, the existing image verifier and relocation
audit. It never deploys. This boilerplate does not bundle the game-specific
material, script, or archive-conversion checks used by owner profiles.
Subsequent builds can
use `python tools/cpp_recovery.py build --skip-assembly` when that directory has
a valid assembly cache. **Replay: launch verified isolated build** stages a
separate runtime directory under the game installation and launches it with
private player settings and independent DLL/INI copies. It validates the build
and current source/header hashes, including a matching passing post-link
quality report, first; no root executable or DLL is replaced.
Its prerequisite task builds the owner-supplied proxy from configured
`proxy_source`, runs its scanner and compiled-image tests, and freezes the DLL
and validators locally. This DLL supplies Replay's existing native GDI bootstrap
compatibility repair. Launching without it can fail before game initialization;
the stage command rejects a missing or changed proxy instead of launching.
`python tools/run_recovered_cpp.py --stage-only` prepares without launching.
The build report's relocation and unwind gates remain
mandatory. Source breakpoints depend on custom-linker debug information and
are not provided by the compilation database.

Run `python tools/cpp_recovery.py workspace` after changing source membership.
`compile_commands.json` uses recorded build commands where available and the
same target/default options for new translation units.
