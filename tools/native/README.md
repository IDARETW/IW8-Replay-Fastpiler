# Replay C++ source linker

`replay_linker.cpp` builds into a build-owned `replay-linker.dll`. It includes
`replay_link_stages.hpp`; both files are covered by the compiler dependency and
source-hash receipts. The DLL is a build tool, not a game runtime dependency.

The default `tools/build.py --link-backend native` route uses C++ for:

- COMDAT selection, including associative unwind metadata, exact matches,
  largest/newest selection and cycle rejection.
- Common-global coalescing, alignment and strong-definition precedence.
- Replacement placement, original entry alignment, growth insertions and new
  code/writable/BSS allocation.
- Iterative short-branch relaxation, including LOOP/JCXZ successors without
  modifying flags or counter semantics.
- COFF symbol resolution, weak fallbacks, selected definitions, unnamed native
  bindings, emitted interior labels and AMD64 relocations.
- Initialized-data and typed metadata references, signed/scaled switch tables,
  unwind-prologue offset changes, runtime-function selection and overlap checks.
- Loader base-relocation tables, exception-directory rebuilding, directory
  placement, debug-directory retirement and fresh PE32+ serialization.

Python remains the compilation coordinator and recovery/catalog adapter. It
reads the manifest and COFF records, derives proven replacement ownership,
checks source provenance, invokes Clang/MASM, prepares proxy signatures and
passes binary records to the C++ linker. It also consumes link receipts for
existing reports and verification tools. No manual RVA or function-extent file
is introduced by this rewrite.

The relocation ABI remains version 1. `replay_linker_stages_abi()` identifies
the additional version-1 stage interface. All stage records use little-endian
integers and length-prefixed byte/string arrays. C++ owns a returned allocation
until the bridge calls `replay_linker_release`; failures reset its output pointer
and length and return a bounded error message. Unknown stages, truncated arrays,
unrepresentable references and unsupported metadata fail the build.

The native linker never reads the original executable. It uses compiled objects
and recovered initialized-data sources to construct a fresh image. An original
certificate table with file offsets is rejected rather than treated as RVA data.

## Differential validation

The former Python code is retained as an explicitly selected reference backend:

```powershell
python tools/build.py --link-backend python --output scratch/python-control
python tools/build.py --compare-link-backends --output scratch/cpp-control
```

`--compare-link-backends` checks C++ selection/allocation, layout events, section
placement, resolved targets, relocation bytes/counters/loader sites, initialized
references, switch tables, unwind offsets, loader-table bytes and both provisional
and final PE images against Python. A mismatch is an error, never a fallback.
The link report records the DLL/compiler/input hashes and stage-call receipts.

Focused tests:

```powershell
python -m unittest discover -s tests -p test_native_link_stages.py -v
python -m unittest discover -s tests -p test_native_linker.py -v
python -m unittest discover -s tests -p test_replay_linker_relocation_contract.py -v
```

Use the workspace's configured Python dependency environment. Validate a full
build with `tools/verify.py --build <directory>` and
`tools/audit_relocations.py --build <directory>` before deployment. Static,
emulation, Windows image mapping and live game tests are separate gates.
