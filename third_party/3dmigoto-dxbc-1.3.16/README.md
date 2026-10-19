# 3Dmigoto DXBC assembler source subset

This source-only package is derived from `bo3b/3Dmigoto` release tag `1.3.16`, commit `cbc4993ca67b6d639e06c578d4e3dc8b3780243f`.

`D3D_Shaders/Assembler.cpp` includes the reviewed Replay SM5 operand/index and declaration fixes. `source-fix.patch` records the changes against the pinned upstream file. `portable_dxbc_cli.cpp` is a small command-line adapter for the existing workstation routes (`-d -V` and `--copy-reflection <reference> -a`). The source builds only that adapter, the upstream assembler, and signature parser; it does not bundle a compiler DLL.

Retain `LICENSE.GPL.txt`, `LICENSE.MIT.txt`, `COPYING.txt`, and `AUTHORS.txt` with source or binary redistribution. Build with the Windows x64 C++ toolchain and SDK `d3dcompiler.lib`; runtime DXBC API calls use the system D3D compiler runtime. The build uses `/MT` and does not replace the separately pinned 3Dmigoto release.
