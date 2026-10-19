# Third-party notices

Third-party components keep their own licenses. No project-wide license is assigned to them by this repository.

| Component | Included or obtained during setup | License information |
| --- | --- | --- |
| 3Dmigoto DXBC CLI source package | Selected source and patch included under `third_party/3dmigoto-dxbc-1.3.16/` | Retained `COPYING.txt`, MIT/GPL license files, and authors list in that directory |
| ACTS | A patch and pinned source manifest are included; setup obtains and builds the selected source | `third_party/acts-patches/manifest.json` identifies the source and the license files retained by the bootstrap |
| Monaco Editor | Setup downloads the pinned editor package | MIT; installed package retains its notices |
| LuaJIT decompiler | Setup obtains and builds its pinned source | Source and license information are retained by its bootstrap |
| GSC string transforms | Optional setup obtains the pinned source | The manifest records its MIT license and source identity |
| Python packages | Installed from `requirements.txt` | Each package retains its own license |
| GSC and texture command-line tools | Optional setup downloads the selected tools | Source URLs, versions, and hashes are recorded in `tools/workstation_toolchain_manifest.json`; upstream licenses apply |

The toolchain manifests describe the exact selected sources and downloads. Game files and analysis databases are separate user inputs and are not supplied under any of these tool licenses.
