"""Immutable scratch drafts and replacement-bank packaging for resident SABs.

This is deliberately separate from typed FF/XAsset editing. The caller must
provide a type-read, source-pinned alias identity for each stable SAB file ID.
The package operation emits one replacement base .sabs and a JSON receipt; it
never copies or emits the patch bank.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any
import uuid

import workstation_sab_editor as sab


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


def _publish_package(root: Path, files: list[tuple[Path, bytes]]) -> None:
    """Publish fresh outputs, rolling back only files created by this call."""
    owned = []
    try:
        for destination, data in files:
            destination = _inside(root, destination)
            with destination.open("xb") as stream:
                identity = os.fstat(stream.fileno())
                owned.append((destination, identity, _sha(data)))
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if _file_sha(destination) != _sha(data):
                raise ValueError("published SAB package bytes differ from the validated output")
    except BaseException:
        for destination, identity, expected_sha in reversed(owned):
            try:
                actual = destination.lstat()
                if ((actual.st_dev, actual.st_ino) == (identity.st_dev, identity.st_ino) and
                        not _is_reparse_entry(destination, actual) and
                        _file_sha(destination) == expected_sha):
                    destination.unlink()
            except FileNotFoundError:
                pass
        raise


def _is_reparse_entry(path: Path, info: Any) -> bool:
    if stat.S_ISLNK(info.st_mode) or (getattr(info, "st_file_attributes", 0) & 0x400):
        return True
    # pathlib exposes this on recent Windows Python; it catches junctions
    # even when their mode bits do not identify them as symlinks.
    is_junction = getattr(path, "is_junction", None)
    return bool(callable(is_junction) and is_junction())


def _has_reparse_component(path: Path) -> bool:
    """Reject symlink/junction/reparse redirection in every existing component."""
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    components = [current]
    for part in absolute.parts[1:]:
        current = current / part
        components.append(current)
    for candidate in components:
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if _is_reparse_entry(candidate, info):
            return True
    return False


def _inside(root: Path, path: Path) -> Path:
    root_abs = Path(os.path.abspath(root))
    path_abs = Path(os.path.abspath(path))
    if _has_reparse_component(root_abs) or _has_reparse_component(path_abs):
        raise ValueError("SAB draft paths may not contain symlinks, junctions, or reparse points")
    resolved_root = root_abs.resolve()
    resolved = path_abs.resolve()
    if not resolved.is_relative_to(resolved_root):
        raise ValueError("SAB draft path escapes the configured cache or output root")
    return resolved


def _revision(row: dict) -> str:
    core = dict(row)
    core.pop("revision", None)
    return _sha(_canonical(core))


def _writer_identity() -> dict:
    path = Path(sab.__file__).resolve(strict=True)
    return {"path": str(path), "sha256": _file_sha(path)}


def _soundfile_identity(soundfile_root: Path | str | None) -> dict:
    return sab.soundfile_identity(soundfile_root)


class SoundBankDraftStore:
    """Hash-bound, CAS-updated SAB WAV drafts rooted below one cache directory."""

    def __init__(self, cache_root: Path | str):
        self.cache_root = Path(os.path.abspath(cache_root))
        _inside(self.cache_root, self.cache_root)
        self.root = _inside(self.cache_root, self.cache_root / "soundbank-drafts")

    @staticmethod
    def _zone_key(zone_id: str) -> str:
        if not isinstance(zone_id, str) or not zone_id.strip():
            raise ValueError("zone_id must be nonempty text")
        return _sha(zone_id.encode("utf-8"))[:24]

    def _zone_dir(self, zone_id: str) -> Path:
        return _inside(self.cache_root, self.root / self._zone_key(zone_id))

    def _entry_dir(self, zone_id: str, file_id: int) -> Path:
        if not isinstance(file_id, int) or not 0 <= file_id <= 0xFFFFFFFF:
            raise ValueError("file_id must be an unsigned 32-bit integer")
        return _inside(self.cache_root, self._zone_dir(zone_id) / str(file_id))

    def _read_current(self, zone_id: str, file_id: int) -> tuple[Path, dict, bytes]:
        folder = self._entry_dir(zone_id, file_id)
        current = _inside(self.cache_root, folder / "current.json")
        if not current.is_file():
            raise FileNotFoundError(f"No active SAB draft for file ID {file_id}")
        row = json.loads(current.read_text(encoding="utf-8"))
        revision = row.get("revision")
        if (not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{64}", revision) is None or
                _revision(row) != revision):
            raise ValueError("SAB draft revision digest is invalid")
        immutable = _inside(self.cache_root, folder / f"{revision}.json")
        if not immutable.is_file() or json.loads(immutable.read_text(encoding="utf-8")) != row:
            raise ValueError("SAB draft differs from its immutable revision snapshot")
        wav_name = row.get("wav_payload_name")
        if not isinstance(wav_name, str) or Path(wav_name).name != wav_name:
            raise ValueError("SAB draft WAV payload path is invalid")
        wav_path = _inside(self.cache_root, folder / wav_name)
        wav = wav_path.read_bytes()
        if _sha(wav) != row.get("wav_sha256") or len(wav) != row.get("wav_bytes"):
            raise ValueError("SAB draft WAV bytes differ from the immutable snapshot")
        rate, channels, frames = sab._validate_pcm16_wav(wav)
        dimensions = {"rate": rate, "channels": channels, "frames": frames}
        if "authored_dimensions" in row and row["authored_dimensions"] != dimensions:
            raise ValueError("SAB draft dimensions differ from its immutable WAV")
        if row.get("zone_id") != zone_id or row.get("file_id") != file_id:
            raise ValueError("SAB draft identity does not match its storage key")
        if current.resolve() != self._entry_dir(zone_id, file_id).joinpath("current.json").resolve():
            raise ValueError("SAB draft current path does not match its expected cache location")
        return current, row, wav

    def stage_entry(self, *, zone_id: str, base_sab: Path | str,
                    patch_sab: Path | str, file_id: int,
                    linked_alias: dict, wav_bytes: bytes,
                    expected_revision: str | None = None,
                    soundfile_root: Path | str | None = None) -> dict:
        """Stage/revise an authored PCM16 WAV for one source-linked file ID.

        `linked_alias` is supplied by the caller's typed FF alias reader and
        must pin the source fileId/name mapping with its receipt hash. This
        module checks the identity shape and SAB/patch relationship but does
        not claim to parse SndBank/SndAlias XAssets itself.
        """
        if not isinstance(wav_bytes, bytes):
            raise ValueError("wav_bytes must be bytes")
        if not isinstance(linked_alias, dict):
            raise ValueError("linked_alias must come from a typed alias reader")
        alias_id = linked_alias.get("file_id")
        alias_name = linked_alias.get("asset_file_name")
        alias_proof = linked_alias.get("source_identity_sha256")
        if (alias_id != file_id or not isinstance(alias_name, str) or not alias_name or
                not isinstance(alias_proof, str) or re.fullmatch(r"[0-9a-f]{64}", alias_proof) is None):
            raise ValueError("linked alias must bind this file_id, a name, and a source identity SHA-256")
        native_provenance = linked_alias.get("native_provenance")
        if native_provenance is not None:
            required_hashes = ("source_ff_sha256", "decoded_body_sha256",
                               "native_manifest_sha256", "native_trace_sha256",
                               "native_walk_key", "source_patch_set_sha256",
                               "base_sab_sha256", "patch_sab_sha256")
            if (not isinstance(native_provenance, dict) or
                    any(not isinstance(native_provenance.get(key), str) or
                        re.fullmatch(r"[0-9a-f]{64}", native_provenance[key]) is None
                        for key in required_hashes) or
                    native_provenance.get("reader_identity_sha256") != alias_proof):
                raise ValueError("native SoundBank provenance must pin FF/body/manifest/trace/walk and reader identity")
        base_path = Path(base_sab).resolve(strict=True)
        patch_path = Path(patch_sab).resolve(strict=True)
        if base_path.suffix.lower() != ".sabs" or patch_path.suffix.lower() != ".sabs":
            raise ValueError("base and patch inputs must be .sabs files")
        base_data, patch_data = base_path.read_bytes(), patch_path.read_bytes()
        if native_provenance is not None and (
                _sha(base_data) != native_provenance["base_sab_sha256"] or
                _sha(patch_data) != native_provenance["patch_sab_sha256"]):
            raise ValueError("base or patch SAB changed after native alias joining")
        base, patch = sab.parse_sab(base_data), sab.parse_sab(patch_data)
        rows = [row for row in base.rows if row.file_id == file_id]
        if len(rows) != 1:
            raise ValueError("source base bank must contain exactly one selected file_id")
        target = rows[0]
        if target.codec != 8 or target.hybrid:
            raise ValueError("only resident codec-8 entries without hybrid bytes can be staged")
        if any(row.file_id == file_id for row in patch.rows):
            raise ValueError("selected file_id is present in the patch bank and shadows the base entry")
        wav_rate, wav_channels, wav_frames = sab._validate_pcm16_wav(wav_bytes)
        writer = _writer_identity()
        codec_dependencies = _soundfile_identity(soundfile_root)
        wav_sha = _sha(wav_bytes)
        source_identity = {
            "base_path": str(base_path), "base_sha256": _sha(base_data),
            "base_bytes": len(base_data), "patch_path": str(patch_path),
            "patch_sha256": _sha(patch_data), "patch_bytes": len(patch_data),
            "file_id": file_id, "row_index": target.index,
            "asset_file_name": alias_name, "alias_source_identity_sha256": alias_proof,
            "codec": target.codec, "rate": target.rate, "channels": target.channels,
            "frames": target.frames, "seek_bytes": target.seek,
            "hybrid_bytes": target.hybrid,
        }
        if native_provenance is not None:
            source_identity["native_provenance"] = dict(native_provenance)
        core = {
            "schema": "replay120-sab-entry-draft-v1", "zone_id": zone_id,
            "file_id": file_id,
            "source_identity": source_identity,
            "writer_identity": writer,
            "codec_dependencies": codec_dependencies,
            "wav_sha256": wav_sha, "wav_bytes": len(wav_bytes),
            "wav_format": "RIFF/WAVE integer PCM16",
            "authored_dimensions": {"rate": wav_rate, "channels": wav_channels, "frames": wav_frames},
            "wav_payload_name": f"{wav_sha}.wav",
        }
        revision = _revision(core)
        row = dict(core, revision=revision)
        folder = self._entry_dir(zone_id, file_id)
        folder.mkdir(parents=True, exist_ok=True)
        payload = _inside(self.cache_root, folder / row["wav_payload_name"])
        if payload.exists() and _file_sha(payload) != wav_sha:
            raise ValueError("immutable SAB draft WAV path collides with different bytes")
        if expected_revision is not None:
            try:
                _current, prior, _prior_wav = self._read_current(zone_id, file_id)
            except FileNotFoundError:
                raise ValueError("SAB draft revision conflict; no current draft exists")
            if prior["revision"] != expected_revision:
                raise ValueError("SAB draft revision conflict; reload before saving")
            if (prior.get("source_identity") != source_identity or
                    prior.get("writer_identity") != writer):
                raise ValueError("SAB draft source or writer identity changed; start a fresh draft")
        else:
            current = folder / "current.json"
            if current.exists():
                raise ValueError("SAB draft already exists; provide its revision for compare-and-swap")
        if not payload.exists():
            temp_payload = payload.with_name(payload.name + "." + uuid.uuid4().hex + ".tmp")
            temp_payload.write_bytes(wav_bytes)
            temp_payload.replace(payload)
        immutable = _inside(self.cache_root, folder / f"{revision}.json")
        if immutable.exists() and json.loads(immutable.read_text(encoding="utf-8")) != row:
            raise ValueError("immutable SAB draft revision collides with different metadata")
        if not immutable.exists():
            _atomic_json(immutable, row)
        current_path = _inside(self.cache_root, folder / "current.json")
        _atomic_json(current_path, row)
        return {"zone_id": zone_id, "file_id": file_id, "asset_file_name": alias_name,
                "revision": revision, "wav_sha256": wav_sha, "wav_bytes": len(wav_bytes),
                "authored_dimensions": core["authored_dimensions"],
                "status": "sab-wav-draft-staged", "pending_path": str(current_path)}

    def list_drafts(self, zone_id: str | None = None) -> list[dict]:
        zones = [self._zone_dir(zone_id)] if zone_id is not None else (
            list(self.root.iterdir()) if self.root.is_dir() else [])
        result = []
        for zone_folder in zones:
            _inside(self.cache_root, zone_folder)
            if not zone_folder.is_dir():
                continue
            for entry_folder in zone_folder.iterdir():
                if not entry_folder.is_dir() or not entry_folder.name.isdecimal():
                    continue
                current = entry_folder / "current.json"
                if not current.is_file():
                    continue
                preview = json.loads(current.read_text(encoding="utf-8"))
                expected_folder = self._entry_dir(preview.get("zone_id"), int(entry_folder.name))
                if expected_folder.resolve() != entry_folder.resolve():
                    raise ValueError("SAB draft current path does not match its expected cache location")
                loaded_current, row, wav = self._read_current(preview["zone_id"], int(entry_folder.name))
                if loaded_current.resolve() != current.resolve():
                    raise ValueError("SAB draft current path changed during listing")
                rate, channels, frames = sab._validate_pcm16_wav(wav)
                result.append({"zone_id": row["zone_id"], "file_id": row["file_id"],
                               "asset_file_name": row["source_identity"]["asset_file_name"],
                               "revision": row["revision"], "wav_sha256": row["wav_sha256"],
                               "wav_bytes": len(wav), "pending_path": str(current.resolve()),
                               "authored_dimensions": {"rate": rate, "channels": channels, "frames": frames}})
        return sorted(result, key=lambda item: (item["zone_id"], item["file_id"]))

    def discard_entry(self, zone_id: str, file_id: int,
                      expected_revision: str) -> dict:
        """Remove the active pointer by revision CAS while preserving history."""
        current, row, _wav = self._read_current(zone_id, file_id)
        if row.get("revision") != expected_revision:
            raise ValueError("SAB draft revision conflict; reload before discarding")
        # Re-read immediately before unlink so a concurrent save cannot be
        # mistaken for the revision the caller asked to discard.
        current_again, latest, _latest_wav = self._read_current(zone_id, file_id)
        if (current_again != current or latest.get("revision") != expected_revision):
            raise ValueError("SAB draft revision conflict; reload before discarding")
        checked = _inside(self.cache_root, current)
        checked.unlink()
        return {"zone_id": zone_id, "file_id": file_id,
                "discarded_revision": expected_revision,
                "status": "sab-draft-discarded-history-retained",
                "pending_path": str(checked)}

    def pending_snapshot(self, zone_id: str | None = None) -> dict[str, str]:
        """Hash each current draft, immutable snapshot, and authored WAV for build pinning."""
        result: dict[str, str] = {}
        for item in self.list_drafts(zone_id):
            current, row, _wav = self._read_current(item["zone_id"], item["file_id"])
            folder = current.parent
            for path in (current, folder / f"{row['revision']}.json",
                         folder / row["wav_payload_name"]):
                checked = _inside(self.cache_root, path)
                result[checked.relative_to(self.cache_root).as_posix()] = _file_sha(checked)
        return result

    def package_zone(self, *, zone_id: str, output_dir: Path | str,
                     soundfile_root: Path | str | None = None,
                     expected_snapshot: dict[str, str] | None = None) -> dict:
        """Apply all current drafts for a zone sequentially to one replacement SAB."""
        start_snapshot = self.pending_snapshot(zone_id)
        if expected_snapshot is not None and start_snapshot != expected_snapshot:
            raise ValueError("SAB draft snapshot changed before packaging")
        drafts = self.list_drafts(zone_id)
        if not drafts:
            raise ValueError("zone has no active SAB entry drafts")
        loaded = []
        for item in drafts:
            _path, row, wav = self._read_current(zone_id, item["file_id"])
            loaded.append((row, wav))
        source = loaded[0][0]["source_identity"]
        writer_id = loaded[0][0]["writer_identity"]
        bank_keys = ("base_path", "base_sha256", "base_bytes",
                     "patch_path", "patch_sha256", "patch_bytes")
        source_banks = {key: source[key] for key in bank_keys}
        if any({key: row["source_identity"].get(key) for key in bank_keys} != source_banks
               for row, _wav in loaded):
            raise ValueError("drafts do not share one pinned base/patch bank identity")
        if any(row["writer_identity"] != writer_id for row, _wav in loaded):
            raise ValueError("drafts were staged with different SAB writer identities")
        current_writer = _writer_identity()
        if current_writer != writer_id:
            raise ValueError("SAB writer changed after draft staging; restage against the current writer")
        dependencies = _soundfile_identity(soundfile_root)
        if any(row.get("codec_dependencies") != dependencies for row, _wav in loaded):
            raise ValueError("SAB codec dependencies changed after draft staging; restage with the current toolchain")
        base_path = Path(source["base_path"]).resolve(strict=True)
        patch_path = Path(source["patch_path"]).resolve(strict=True)
        original = base_path.read_bytes()
        patch = patch_path.read_bytes()
        if (_sha(original) != source["base_sha256"] or len(original) != source["base_bytes"] or
                _sha(patch) != source["patch_sha256"] or len(patch) != source["patch_bytes"]):
            raise ValueError("source SAB or linked patch changed after draft staging")
        current_bank = original
        item_receipts = []
        for row, wav in sorted(loaded, key=lambda pair: pair[0]["source_identity"]["file_id"]):
            staged = row["source_identity"]
            before = sab.parse_sab(current_bank)
            selected = [entry for entry in before.rows if entry.file_id == staged["file_id"]]
            if len(selected) != 1 or selected[0].codec != 8 or selected[0].hybrid:
                raise ValueError("selected fileId no longer identifies an editable codec-8 row")
            if (selected[0].rate, selected[0].channels, selected[0].frames) != (
                    staged["rate"], staged["channels"], staged["frames"]):
                raise ValueError("selected fileId metadata changed from the immutable draft identity")
            current_bank, receipt = sab.rewrite_entry(
                current_bank, staged["file_id"], wav, soundfile_root=soundfile_root)
            item_receipts.append({"revision": row["revision"], "file_id": staged["file_id"],
                                  "asset_file_name": staged["asset_file_name"],
                                  "alias_source_identity_sha256": staged["alias_source_identity_sha256"],
                                  "wav_sha256": row["wav_sha256"], "writer_receipt": receipt})
        if (_file_sha(base_path) != source["base_sha256"] or
                _file_sha(patch_path) != source["patch_sha256"] or
                _writer_identity() != writer_id or
                _soundfile_identity(soundfile_root) != dependencies):
            raise ValueError("SAB source, writer, or codec dependency changed during package build")
        end_snapshot = self.pending_snapshot(zone_id)
        if end_snapshot != start_snapshot or (expected_snapshot is not None and end_snapshot != expected_snapshot):
            raise ValueError("SAB drafts changed during package build")
        output_root = Path(output_dir).resolve()
        output_root.mkdir(parents=True, exist_ok=True)
        source_name = base_path.name
        output_path = _inside(output_root, output_root / source_name)
        if output_path == base_path or output_path == patch_path:
            raise ValueError("replacement output must not overwrite source or patch bank")
        output_receipt_path = _inside(output_root, output_root / (base_path.stem + ".sab-draft-receipt.json"))
        package = {
            "schema": "replay120-sab-zone-draft-package-v1",
            "zone_id": zone_id,
            "source_banks": source_banks,
            "writer_identity": writer_id,
            "draft_snapshot_sha256": _sha(_canonical(start_snapshot)),
            "codec_dependencies": dependencies,
            "edits": item_receipts,
            "output": {"path": str(output_path), "filename": output_path.name,
                       "bytes": len(current_bank), "sha256": _sha(current_bank)},
            "emitted_files": [output_path.name],
            "patch_bank_emitted": False,
            "checksum_semantics": "opaque per-entry/header checksum bytes preserved; meaning unverified",
            "native_entry_acceptance_evidence": "prior candidate only; regenerated package not runtime tested",
            "playback_verified": False,
        }
        receipt_bytes = (json.dumps(package, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        _publish_package(output_root, [(output_path, current_bank),
                                       (output_receipt_path, receipt_bytes)])
        package["receipt_path"] = str(output_receipt_path)
        package["receipt_sha256"] = _file_sha(output_receipt_path)
        return package

