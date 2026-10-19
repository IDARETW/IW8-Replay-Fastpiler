"""Prove a byte-identical decoded-body -> unsigned IWC -> Replay reader roundtrip.

This experiment only repackages a complete, natively readable zone body. It
does not edit XAsset roots or claim asset relocation support.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

try:
    from .workstation_fastfiles import (
        ACTS_DEFAULT, REPLAY_EXECUTABLE, _assert_run_inputs_unchanged,
        acts_tool_identity, decode_source_fastfile, make_replay_header_only_patch,
        pack_replay_uncompressed, sha256_file, source_profile,
        unpack_replay_uncompressed, ZoneBody, ordered_asset_identity_sha256)
except ImportError:  # Direct tools/*.py execution keeps the tools directory on sys.path.
    from workstation_fastfiles import (
        ACTS_DEFAULT, REPLAY_EXECUTABLE, _assert_run_inputs_unchanged,
        acts_tool_identity, decode_source_fastfile, make_replay_header_only_patch,
        pack_replay_uncompressed, sha256_file, source_profile,
        unpack_replay_uncompressed, ZoneBody, ordered_asset_identity_sha256)


def _create_shallow_reader_output(package_path: Path,
                                  required_free_bytes: int) -> Path:
    """Create a short ACTS output directory on a writable volume with room.

    ACTS appends ``mw19replay/<zone>/stream-trace.jsonl`` itself. Keep this
    temporary tree independent of the caller's durable evidence path so long
    verification-cache paths cannot make native trace creation fail on Windows.
    """
    # Prefer the configured temporary volume. A game/package volume may have
    # less free space (and should only be a fallback when the temp volume is
    # unsuitable).
    system_temp = Path(tempfile.gettempdir())
    candidates = [system_temp]
    anchor = Path(package_path.anchor) if package_path.anchor else None
    if anchor is not None and anchor not in candidates:
        candidates.append(anchor)
    rejected = []
    for base in candidates:
        if not base.is_dir():
            continue
        temporary = None
        try:
            temporary = Path(tempfile.mkdtemp(prefix="rvr-", dir=base))
            expected_trace = temporary / "mw19replay" / package_path.stem / "stream-trace.jsonl"
            if len(str(expected_trace)) >= 240:
                rejected.append(f"{base}: expected trace path is too long ({len(str(expected_trace))} characters)")
                temporary.rmdir()
                continue
            if shutil.disk_usage(temporary).free < required_free_bytes:
                rejected.append(f"{base}: insufficient free space for native output")
                temporary.rmdir()
                continue
            return temporary
        except OSError as error:
            if temporary is not None:
                try:
                    temporary.rmdir()
                except OSError:
                    pass
            rejected.append(f"{base}: {error}")
    raise OSError("No short writable ACTS output directory is available: " + "; ".join(rejected))


def _archive_reader_output(reader_root: Path, output_root: Path) -> Path | None:
    """Move ACTS's complete Replay output tree to the caller-owned evidence root."""
    reader_root = reader_root.resolve(strict=True)
    output_root = output_root.resolve(strict=True)
    source = (reader_root / "mw19replay").resolve()
    if not source.exists():
        return None
    if not source.is_relative_to(reader_root):
        raise ValueError("ACTS output tree escaped its owned temporary root")
    destination = (output_root / "mw19replay").resolve()
    if not destination.is_relative_to(output_root):
        raise ValueError("durable native output escaped its requested evidence root")
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite existing native evidence: {destination}")
    shutil.move(str(source), str(destination))
    return destination


def _stage_short_reader_input(package_path: Path,
                              candidate_artifacts: dict) -> tuple[Path, dict, Path | None]:
    """Stage long FF inputs under TEMP without changing their native basename.

    ACTS may exit successfully while parsing zero files for deeply nested
    inputs. Keep normal paths untouched; when necessary, copy the FF and its
    matching sidecars to a unique short directory and verify every copied
    byte against the original inventory before handing it to the reader.
    """
    if len(str(package_path)) < 220:
        return package_path, dict(status="not-needed", requested_path=str(package_path),
                                  staged_path=None, files={}), None
    temp_base = Path(tempfile.gettempdir()).resolve(strict=True)
    stage_root = Path(tempfile.mkdtemp(prefix="rvi-", dir=temp_base))
    created_stat = stage_root.stat()
    staged_ff = stage_root / package_path.name
    staged = {}
    try:
        for suffix in (".ff", ".fp", ".fc"):
            original = package_path if suffix == ".ff" else package_path.with_suffix(suffix)
            expected = candidate_artifacts[suffix]
            if not expected["exists"]:
                staged[suffix] = dict(exists=False)
                continue
            destination = staged_ff if suffix == ".ff" else staged_ff.with_suffix(suffix)
            shutil.copyfile(original, destination)
            observed = dict(exists=True, bytes=destination.stat().st_size,
                            sha256=sha256_file(destination))
            if observed["bytes"] != expected["bytes"] or observed["sha256"] != expected["sha256"]:
                raise ValueError(f"short-path staged {suffix} differs from requested input")
            staged[suffix] = observed
        if len(str(staged_ff)) >= 220:
            raise OSError(f"system TEMP did not provide a sufficiently short ACTS input path ({len(str(staged_ff))})")
        return staged_ff, dict(status="staged", requested_path=str(package_path),
                               staged_path=str(staged_ff), staged_path_length=len(str(staged_ff)),
                               canonical_basename_preserved=staged_ff.name == package_path.name,
                               private_temp_base=str(temp_base),
                               private_stage_identity=dict(device=created_stat.st_dev,
                                                          inode=created_stat.st_ino),
                               files=staged), stage_root
    except BaseException:
        shutil.rmtree(stage_root, ignore_errors=True)
        raise


def _assert_private_stage_for_cleanup(stage_root: Path, staging: dict) -> None:
    """Verify cleanup is confined to the exact fresh directory created under TEMP."""
    expected_base = Path(staging["private_temp_base"]).resolve(strict=True)
    expected_root = Path(staging["staged_path"]).parent
    if stage_root != expected_root or not stage_root.is_absolute():
        raise ValueError("refusing staged-input cleanup: path is not the exact recorded private directory")
    if stage_root.is_symlink() or not stage_root.is_dir():
        raise ValueError("refusing staged-input cleanup: private directory is absent or a symlink")
    attributes = getattr(stage_root.stat(), "st_file_attributes", 0)
    if attributes & getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise ValueError("refusing staged-input cleanup: private directory is a reparse point")
    resolved_root = stage_root.resolve(strict=True)
    if resolved_root.parent != expected_base or resolved_root != stage_root:
        raise ValueError("refusing staged-input cleanup: private directory escaped recorded TEMP base")
    current_stat = stage_root.stat()
    identity = staging.get("private_stage_identity", {})
    if (current_stat.st_dev, current_stat.st_ino) != (identity.get("device"), identity.get("inode")):
        raise ValueError("refusing staged-input cleanup: private directory identity changed")


def verify_native(path: Path, original_body: bytes, source: Path,
                  acts: Path, replay: Path, output_root: Path,
                  timeout: int, trace: bool = False,
                  reference_only_rows: list[dict] | None = None) -> dict:
    before_tool = acts_tool_identity(acts)
    replay_hash = sha256_file(replay)
    source_profile_row = source_profile(source)
    output_root.mkdir(parents=True, exist_ok=True)
    package_path = Path(path).resolve(strict=True)
    durable_tree = output_root / "mw19replay"
    if durable_tree.exists():
        raise FileExistsError(f"native evidence output already exists: {durable_tree}")
    if not package_path.is_file():
        raise FileNotFoundError(package_path)
    candidate_artifacts = {}
    for suffix in (".ff", ".fp", ".fc"):
        candidate = (package_path if suffix == ".ff" else package_path.with_suffix(suffix))
        candidate_artifacts[suffix] = dict(
            path=str(candidate.resolve()), exists=candidate.is_file(),
            bytes=candidate.stat().st_size if candidate.is_file() else None,
            sha256=sha256_file(candidate) if candidate.is_file() else None)
    if not candidate_artifacts[".ff"]["exists"]:
        raise FileNotFoundError(package_path)
    native_package_path, input_staging, input_stage_root = _stage_short_reader_input(
        package_path, candidate_artifacts)
    log_path = output_root / "native-reader.log"
    # Stream traces can be much larger than their serialized input bodies.
    # Keep a multi-gigabyte floor so a 512 MiB volume is not selected for an
    # otherwise valid read whose trace would exhaust it.
    required_free_bytes = max(2 * 1024 * 1024 * 1024, len(original_body) * 4)
    reader_output_root = _create_shallow_reader_output(
        package_path, required_free_bytes)
    command = [str(acts), "--noUpdater", "fastfile", "-r", "mw19replay",
               "-g", str(replay), "--noAssetDump", "-l", "-o",
               str(reader_output_root)]
    if trace:
        command.append("--trace-replay-streams")
    command.append(str(native_package_path))
    invocation_path = output_root / "reader-output-location.json"
    invocation = dict(schema=1, status="running",
                      temporary_output_root=str(reader_output_root),
                      durable_output_root=str(output_root),
                      expected_trace_path_length=len(str(reader_output_root / "mw19replay" / package_path.stem / "stream-trace.jsonl")),
                      required_free_bytes=required_free_bytes, command=command,
                      requested_input_path=str(package_path),
                      requested_input_sha256=candidate_artifacts[".ff"]["sha256"],
                      input_staging=input_staging)
    invocation_path.write_text(json.dumps(invocation, indent=2) + "\n", encoding="utf-8")
    run_error = None
    result = None
    try:
        with log_path.open("w", encoding="utf-8") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=timeout, check=False)
    except BaseException as error:
        run_error = error
    try:
        archived = _archive_reader_output(reader_output_root, output_root)
        invocation.update(
            status=("partial-archived" if run_error is not None else
                    "reader-failed-archived" if result is not None and result.returncode != 0 else
                    "archived" if archived is not None else "no-output"),
            return_code=result.returncode if result is not None else None,
            archived_output_root=str(archived) if archived else None,
            run_error=(f"{type(run_error).__name__}: {run_error}"
                       if run_error is not None else None))
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n", encoding="utf-8")
        # Remove only this invocation's temporary directory, and only when it
        # is empty after archiving. Preserve unexpected leftovers for review.
        if reader_output_root.exists() and not any(reader_output_root.iterdir()):
            reader_output_root.rmdir()
    except BaseException as archive_error:
        invocation.update(status="archive-failed",
                          archive_error=f"{type(archive_error).__name__}: {archive_error}",
                          run_error=(f"{type(run_error).__name__}: {run_error}"
                                     if run_error is not None else None))
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n", encoding="utf-8")
        if run_error is not None:
            raise run_error from archive_error
        raise
    if input_stage_root is not None:
        staged_after = {}
        for suffix in (".ff", ".fp", ".fc"):
            staged = native_package_path if suffix == ".ff" else native_package_path.with_suffix(suffix)
            expected = candidate_artifacts[suffix]
            present = staged.is_file()
            staged_after[suffix] = (dict(exists=True, bytes=staged.stat().st_size,
                                         sha256=sha256_file(staged)) if present else
                                    dict(exists=False))
        if staged_after != {suffix: (dict(exists=False) if not row["exists"] else
                                     dict(exists=True, bytes=row["bytes"], sha256=row["sha256"]))
                            for suffix, row in candidate_artifacts.items()}:
            invocation.update(input_stage_status="staged-input-changed",
                              staged_inputs_after=staged_after)
            invocation_path.write_text(json.dumps(invocation, indent=2) + "\n", encoding="utf-8")
            raise ValueError("native reader changed the private staged FF or patch sidecars")
        invocation.update(input_stage_status="verified-and-cleaned",
                          staged_inputs_after=staged_after)
        _assert_private_stage_for_cleanup(input_stage_root, input_staging)
        shutil.rmtree(input_stage_root)
        invocation["staged_input_cleanup"] = "removed"
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n", encoding="utf-8")
    else:
        invocation.update(input_stage_status="not-needed")
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n", encoding="utf-8")
    if run_error is not None:
        raise run_error
    _assert_run_inputs_unchanged(source, source_profile_row, acts,
                                 before_tool, replay, replay_hash)
    candidate_after = {}
    for suffix in (".ff", ".fp", ".fc"):
        candidate = (package_path if suffix == ".ff" else package_path.with_suffix(suffix))
        candidate_after[suffix] = dict(
            path=str(candidate.resolve()), exists=candidate.is_file(),
            bytes=candidate.stat().st_size if candidate.is_file() else None,
            sha256=sha256_file(candidate) if candidate.is_file() else None)
    if candidate_after != candidate_artifacts:
        raise ValueError("native reader changed the candidate FF or patch sidecars during verification")
    if result.returncode != 0:
        raise RuntimeError(f"Replay reader returned {result.returncode}; see {log_path}")
    manifests = list(output_root.glob("mw19replay/*/manifest.json"))
    if len(manifests) != 1:
        log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
        if result.returncode == 0 and not manifests and "Parsed 0 (0x0) file(s)" in log_text:
            invocation.update(status="reader-parsed-zero-no-manifest",
                              diagnosis="ACTS exited 0 but parsed zero files; the input was not consumed")
            invocation_path.write_text(json.dumps(invocation, indent=2) + "\n", encoding="utf-8")
            raise ValueError("ACTS exited 0 but parsed 0 files and produced no native manifest; see " + str(log_path))
        raise ValueError(f"expected one native reader manifest, found {len(manifests)}")
    manifest_path = manifests[0]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    body = ZoneBody.parse(original_body)
    raw_manifest_path = manifest_path
    raw_manifest_sha256 = sha256_file(raw_manifest_path)
    raw_tested = manifest.get("tested")
    top_level = manifest.get("top_level_index")
    supplied_references = reference_only_rows
    if supplied_references is not None and not isinstance(supplied_references, list):
        raise ValueError("native reference-only descriptors must be a list")
    needs_reference_proof = (bool(supplied_references) or
                             (type(raw_tested) is int and type(top_level) is int and
                              raw_tested < top_level))
    inventory = None
    references = []
    if needs_reference_proof:
        if not trace:
            raise ValueError("reference-only rows require an output trace; caller descriptors alone are not proof")
        trace_path = manifest_path.parent / manifest.get("stream_trace", "stream-trace.jsonl")
        if not trace_path.is_file():
            raise ValueError("reference-only rows require the native output stream trace")
        journal_path = manifest_path.parent / manifest.get("journal", "assets.jsonl")
        raw_rows = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
        try:
            from .workstation_native_references import normalize_native_inventory
        except ImportError:
            from workstation_native_references import normalize_native_inventory
        inventory = normalize_native_inventory(original_body, trace_path, manifest, raw_rows)
        references = inventory["reference_only_rows"]
        if supplied_references is not None:
            def identities(items):
                if not isinstance(items, list):
                    raise ValueError("native reference-only descriptors must be a list")
                result = []
                for row in items:
                    if not isinstance(row, dict):
                        raise ValueError("native reference-only descriptor is malformed")
                    index, type_id = row.get("index"), row.get("type_id")
                    name, token = row.get("name"), row.get("pointer_token")
                    if (type(index) is not int or type(type_id) is not int or
                            not isinstance(name, str) or type(token) is not int):
                        raise ValueError("native reference-only identity fields have invalid types")
                    result.append((index, type_id, name, token))
                return result
            if identities(supplied_references) != identities(references):
                raise ValueError("caller reference descriptors differ from trace-derived output identities")
    elif supplied_references:
        raise ValueError("reference descriptors cannot be accepted without native trace proof")
    reference_indices = {row["index"] for row in references}
    requirements = {
        "complete": True,
        "success": True,
        "profile": "replay-1.20",
        "xfile_version": 0xFF7,
        "tested": len(body.assets) - len(references),
        "failed": 0,
        "unavailable": 0,
        "top_level_index": len(body.assets),
        "serialized_bytes_read": len(original_body),
    }
    def exact_requirement(actual, expected):
        if type(expected) is bool or type(expected) is int:
            return type(actual) is type(expected) and actual == expected
        return type(actual) is type(expected) and actual == expected
    differences = {key: (manifest.get(key), expected)
                   for key, expected in requirements.items()
                   if not exact_requirement(manifest.get(key), expected)}
    if differences:
        raise ValueError(f"native reader proof failed requirements: {differences}")
    loaded_assets = manifest.get("loaded_assets")
    if type(loaded_assets) is not int or loaded_assets < requirements["tested"]:
        raise ValueError("native loaded_assets count is smaller than the tested top-level XAsset table")
    journal = manifest_path.parent / manifest.get("journal", "assets.jsonl")
    rows = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    tested_assets = [asset for asset in body.assets if asset.index not in reference_indices]
    if len(rows) != len(tested_assets) or any(
            row.get("type_id") != asset.type_id
            for row, asset in zip(rows, tested_assets, strict=True)):
        raise ValueError("native XAsset journal differs from the decoded source table")
    normalized_inventory_path = None
    normalized_inventory_sha256 = None
    if references:
        accounted = dict(manifest, reference_only_rows=references)
        accounted_path = manifest_path.parent / "manifest-reference-accounted.json"
        accounted_path.write_text(json.dumps(accounted, indent=2) + "\n", encoding="utf-8")
        normalized_inventory_path = manifest_path.parent / "normalized-inventory.json"
        normalized_inventory_path.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
        normalized_inventory_sha256 = sha256_file(normalized_inventory_path)
        manifest, manifest_path = accounted, accounted_path
    normalized_rows = inventory["normalized_rows"] if inventory is not None else rows
    trace_summary = None
    if trace:
        trace_path = manifest_path.parent / manifest.get("stream_trace", "stream-trace.jsonl")
        if not trace_path.is_file():
            raise ValueError("trace-enabled native read omitted the stream trace")
        try:
            from .workstation_trace_index import build_read_span_index
        except ImportError:
            from workstation_trace_index import build_read_span_index
        index_manifest = manifest_path
        index = build_read_span_index(trace_path, index_manifest, len(original_body))
        trace_summary = dict(event_count=index["event_count"],
                             stream_trace_bytes=trace_path.stat().st_size,
                             stream_trace_sha256=sha256_file(trace_path),
                             max_destination_offsets=index["max_destination_offsets"],
                             physical_load_count_by_stream=index["physical_load_count_by_stream"],
                             physical_load_bytes_by_stream=index["physical_load_bytes_by_stream"],
                             packed_target_stream_counts=index["packed_target_stream_counts"])
    return dict(command=command, return_code=result.returncode,
                native_output_root=str(output_root / "mw19replay"),
                invocation_path=str(invocation_path),
                manifest=manifest, manifest_path=str(manifest_path),
                raw_manifest_path=str(raw_manifest_path),
                raw_manifest_sha256=raw_manifest_sha256,
                journal_sha256=sha256_file(journal),
                journal_asset_identity_sha256=ordered_asset_identity_sha256(rows),
                normalized_asset_identity_sha256=ordered_asset_identity_sha256(normalized_rows),
                normalized_table_count=len(body.assets),
                reference_only_rows=references,
                normalized_inventory_path=(str(normalized_inventory_path)
                                            if normalized_inventory_path else None),
                normalized_inventory_sha256=normalized_inventory_sha256,
                candidate_artifacts=candidate_artifacts,
                log_path=str(log_path), log_sha256=sha256_file(log_path),
                trace_summary=trace_summary,
                acts_tool_identity=before_tool,
                replay_executable_sha256=replay_hash)


def run(source: Path, cache: Path, acts: Path, replay: Path,
        output: Path, timeout: int) -> dict:
    source = source.resolve(strict=True)
    acts = acts.resolve(strict=True)
    replay = replay.resolve(strict=True)
    output = output.resolve()
    if output == source or source in output.parents:
        raise ValueError("roundtrip output must be outside the shipped source directory")
    receipt = decode_source_fastfile(source, cache, acts, replay, timeout)
    body_path = cache / source.stem / receipt["cache_key"] / receipt["final_body_relative_path"]
    original = body_path.read_bytes()
    profile = receipt["source"]
    final_header = profile["final_header"]
    packed = pack_replay_uncompressed(original, final_header["block_sizes"],
                                      xfile_version=final_header["xfile_version"],
                                      transient_type=profile["header"]["transient_type"])
    if unpack_replay_uncompressed(packed) != original:
        raise AssertionError("container self-check was not byte-identical")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = output.with_suffix(output.suffix + ".tmp")
    temporary_output.write_bytes(packed)
    if sha256_file(temporary_output) == sha256_file(source):
        raise ValueError("unsigned IWC output unexpectedly matches signed source bytes")
    # Move atomically only after structural and exact-body validation.
    if output.exists():
        raise FileExistsError(output)
    temporary_output.replace(output)
    output_sidecars = []
    for patch_row in profile.get("patches", []):
        extension = patch_row["extension"]
        source_patch = Path(patch_row["path"]).resolve(strict=True)
        sidecar = output.with_suffix(extension)
        if sidecar.exists():
            raise FileExistsError(sidecar)
        patch_bytes = make_replay_header_only_patch(source_patch.read_bytes(), packed)
        sidecar.write_bytes(patch_bytes)
        output_sidecars.append(dict(path=str(sidecar), bytes=len(patch_bytes),
                                    sha256=sha256_file(sidecar),
                                    replaces_stale_source_patch=str(source_patch)))
    with tempfile.TemporaryDirectory(prefix="rwt-verify-") as temp:
        native = verify_native(output, original, source, acts, replay,
                               Path(temp), timeout)
        applied = native["manifest"].get("applied_patches", [])
        if [Path(item).suffix for item in applied] != [row["extension"] for row in profile.get("patches", [])]:
            raise ValueError("native reader did not apply the emitted header-only patch chain")
        # Preserve only compact proof artifacts; the large reader journal is
        # represented by its hash and the native manifest's exact counts.
        proof_root = output.parent / (output.name + ".reader-proof")
        proof_root.mkdir(exist_ok=False)
        manifest_source = Path(native["manifest_path"])
        shutil.copy2(manifest_source, proof_root / "manifest.json")
        raw_manifest_source = Path(native["raw_manifest_path"])
        shutil.copy2(raw_manifest_source, proof_root / "raw-manifest.json")
        if native.get("normalized_inventory_path"):
            shutil.copy2(native["normalized_inventory_path"],
                          proof_root / "normalized-inventory.json")
            native["normalized_inventory_path"] = str(proof_root / "normalized-inventory.json")
        log_source = Path(native["log_path"])
        shutil.copy2(log_source, proof_root / "native-reader.log")
        journal_source = manifest_source.parent / native["manifest"].get(
            "journal", "assets.jsonl")
        if not journal_source.is_file():
            raise ValueError("native reader proof omitted its XAsset journal")
        shutil.copy2(journal_source, proof_root / "assets.jsonl")
        native["raw_manifest_path"] = str(proof_root / "raw-manifest.json")
        native["manifest_path"] = str(proof_root / "manifest.json")
    result = dict(schema=1, status="unchanged-body-repack-native-reader-pass",
                  source_fastfile=str(source), source_sha256=sha256_file(source),
                  source_body_sha256=receipt["final_body_sha256"],
                  source_body_bytes=len(original), decoded_receipt_key=receipt["cache_key"],
                  decoded_header=profile["final_header"],
                  output_fastfile=str(output), output_sha256=sha256_file(output),
                  output_bytes=output.stat().st_size,
                  output_body_sha256=hashlib.sha256(unpack_replay_uncompressed(
                      output.read_bytes())).hexdigest(),
                  body_byte_identical=(unpack_replay_uncompressed(output.read_bytes()) == original),
                  output_sidecars=output_sidecars,
                  native_reader=native,
                  proof_directory=str(proof_root))
    result["native_reader"].pop("manifest_path", None)
    result["native_reader"].pop("log_path", None)
    report_path = proof_root / "roundtrip-receipt.json"
    report_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--acts", type=Path, default=ACTS_DEFAULT)
    parser.add_argument("--replay", type=Path, default=REPLAY_EXECUTABLE)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    report = run(args.source, args.cache, args.acts, args.replay,
                 args.output, args.timeout)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
