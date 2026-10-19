# Compiler architecture

## Inputs and recovery

The supported target is identified by its executable hash. The analysis seeds contain instruction boundaries, data classifications, and reference locations. They do not contain executable sections or recovered game assembly.

Recovery reads the supplied executable and produces assembly, initialized data, function identities, and reference records under `generated/` and the local recovery directories. The SQLite analysis database supplies names and aliases for matching addresses. Unknown names remain usable through stable function identities.

The supplied executable and database are read as inputs. They are not included in the repository.

## C++ source association

`source-units.json` starts empty. It maps an authored source and symbol to a recovered function ID after a binding is added. It also records aliases used to call existing native functions and access globals. Managed editor revisions are recorded under `source-workstation/`.

Clang emits AMD64 COFF objects. The compiler reads their sections, symbols, relocations, alignment, and unwind records. Target-specific structures and calling conventions remain part of each replacement's implementation.

## Linking

Python coordinates recovery, compilation, source checks, and reports. The default linker backend is C++, built from `tools/native/replay_linker.cpp` and `replay_link_stages.hpp`. The Python backend remains available for differential checks.

Replacements retain their original logical positions. When a replacement exceeds its native span, the linker expands that position and moves following content. It resolves the resulting address changes in instructions and initialized data. New functions and globals can use available or appended sections.

The linker handles COFF selection, short-branch relaxation, code/data references, imports, exports, base relocations, exception metadata, and PE serialization. Unsupported cases fail the build. The link stage consumes recovered inputs and objects rather than copying the original executable as its output.

The native linker builds into a local `replay-linker.dll`. That DLL is a compiler tool, not a runtime dependency of the resulting game.

## Verification

The main verification tools compare retained native instructions, data, references, and metadata with the supplied target. Regression checks also execute selected compiled routines and original instructions under emulation and use Windows image-mapping and unwind APIs where applicable.

Build reports record input, source, header, object, and output hashes. Workstation workers check their saved inputs before publishing output. Editing a dependency after compilation invalidates that build's source checks.

Offline checks establish the properties they exercise. Game startup, rendering, networking, gameplay, and asset compatibility also require runtime testing.

## Local files

Generated code, recovered data, local settings, databases, tool installations, and build outputs are kept outside the tracked source set. Setup and the workstation create them as needed.

The source export manifest records the prepared repository files by hash. It supports review of a source package; it is not a signature or a replacement for build verification.
