# Replay workstation

The workstation provides a local source editor, symbol browser, asset editor, and verified build queue. The repository starts with empty source manifests and no selected executable replacements.

## Setup

Run `setup-workstation.ps1` with the matching Replay executable and Diaphora SQLite export, as described in [README.md](README.md). Add `-SkipAssetTools` for compiler-only setup. Optional asset setup installs the pinned tools and keeps game assets in the supplied game directory.

Start the server with:

```powershell
.\start-workstation.ps1
```

Open **http://127.0.0.1:8126**. Local paths are stored in `replay-project.local.json`, which is excluded from Git.

## Source editing

**Game source** lists recovered functions and globals. Names and aliases come from the matching SQLite analysis export. Functions without descriptive names remain accessible by their catalog identity.

Use the source editor to create a C/C++ replacement or edit recovered assembly. Saved revisions are stored under `src/` and `source-workstation/`, with their identities and hashes recorded in the corresponding manifests. **Authored files** lists files you have added to those directories.

`source-units.json` holds explicit replacement and import bindings. Both editor-managed manifests start empty. The compiler checks source revisions, native function identities, object relocations, and unwind metadata before linking.

## Assets

**Assets** reads fastfiles from the configured game directory. Select a zone and extract it into the local cache to inspect supported assets. The editor exposes actions supported by the selected reader and writer. Saving an edit stages it in the cache; it does not replace the game file immediately.

Asset compilation uses the configured tools and validates their identities. Some asset types require additional tools or formats that are not supported. Unsupported operations stop with an error.

## Builds

Under **Builds & output**, select:

- **Engine source only** to rebuild recovered code and your selected source replacements.
- **Engine source and saved asset edits** to also package staged asset edits.

Choose **Compile game** and review the job log. Each job records its source, configuration, tools, and output hashes. The build queue serializes compiler work and rejects changed inputs before publishing results under `output/`.

A successful job includes PE verification, relocation auditing, and source provenance checks. It does not launch the game or overwrite the installation. Copy verified output into an appropriate test installation when ready.

## Local data

Generated assembly and initialized data are recovered from the supplied executable. Caches, tool installations, editor revisions, logs, and build outputs stay local. See [.gitignore](.gitignore) for the excluded paths and [Architecture](docs/ARCHITECTURE.md) for the recovery and link stages.
