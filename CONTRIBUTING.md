# Contributing

Keep compiler changes specific to the supported target and retain the associated input identity. Preserve calling conventions, layouts, reference ownership, and unwind behavior when changing native replacements.

## Checks

Use the environment created by setup. For changes to export packaging and source associations:

```powershell
python -m unittest discover -s tests -p "test_workstation_export*.py" -v
```

For native linker changes:

```powershell
python -m unittest discover -s tests -p "test_native_link*.py" -v
python -m unittest discover -s tests -p "test_replay_linker_relocation_contract.py" -v
```

A full compiler change also needs a fresh build, image verification, and relocation audit using the matching target inputs. Report which checks ran and whether the resulting game was tested.

## Written content

Write comments and documentation for readers who understand the code but do not know private conversations or local experiments. Explain requirements, purpose, and non-obvious behavior in plain language. Avoid excessive tips, tooltips, reminders, and explanations of routine programming concepts. See [AGENTS.md](AGENTS.md) for the project writing guidance.

## Repository contents

Keep game executables, game assets, analysis databases, personal paths, credentials, caches, and generated build outputs out of commits. Retain third-party source notices and pinned tool identities when updating dependencies.
