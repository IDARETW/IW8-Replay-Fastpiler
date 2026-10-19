"""Coordinator for native-trace-linked Replay SAB audio drafts.

This adapter keeps SAB entry editing separate from the FF dispatcher. It uses
FastfileWorkspace's validated decode/native-walk receipts and the typed
SoundBank reader; browser callers provide only zone/asset/file IDs and WAV
bytes, never arbitrary filesystem paths.
"""
from __future__ import annotations

import hashlib
import io
import math
import os
from pathlib import Path
import re
import json
import tempfile
from typing import Any

import workstation_fastfiles as fastfiles
import workstation_sab_drafts as drafts_module
import workstation_sab_editor as sab
from workstation_soundbank import (list_resident_codec8_base_ids,
                                   read_native_soundbank)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_codec8_wav(bank_bytes: bytes, file_id: int, *,
                      soundfile_root: str | Path | None = None) -> tuple[bytes, dict]:
    """Decode one resident, non-hybrid SAB codec-8 row to verified PCM16 WAV."""
    parsed = sab.parse_sab(bank_bytes)
    matches = [row for row in parsed.rows if row.file_id == file_id]
    if len(matches) != 1:
        raise ValueError("SAB must contain exactly one requested fileId")
    row = matches[0]
    if row.codec != 8 or row.hybrid:
        raise ValueError("only resident non-hybrid codec-8 rows can be exported")
    if not 0 <= row.seek < row.size:
        raise ValueError("codec-8 row has no FLAC frames after its seek extent")
    frames = bank_bytes[row.offset + row.seek:row.offset + row.size]
    if len(frames) != row.size - row.seek:
        raise ValueError("codec-8 FLAC frame extent is truncated")
    wrapped = sab._wrap_frames(frames, row.rate, row.channels, row.frames)
    np, sf = sab._soundfile(soundfile_root)
    pcm, rate = sf.read(io.BytesIO(wrapped), dtype="int16", always_2d=True)
    if rate != row.rate or pcm.shape != (row.frames, row.channels):
        raise ValueError("native SAB entry did not decode to its exact rate/channel/frame dimensions")
    output = io.BytesIO()
    sf.write(output, pcm, rate, format="WAV", subtype="PCM_16")
    wav = output.getvalue()
    if sab._validate_pcm16_wav(wav) != (row.rate, row.channels, row.frames):
        raise ValueError("exported PCM16 WAV dimensions differ from the native SAB row")
    checked, checked_rate = sf.read(io.BytesIO(wav), dtype="int16", always_2d=True)
    if checked_rate != rate or not np.array_equal(checked, pcm):
        raise ValueError("PCM16 WAV encode/decode changed the native decoded samples")
    return wav, {
        "schema": "replay120-sab-codec8-pcm16-export-v1",
        "file_id": file_id, "sab_index": row.index, "codec": row.codec,
        "rate": row.rate, "channels": row.channels, "frames": row.frames,
        "seek_bytes": row.seek, "hybrid_bytes": row.hybrid,
        "flac_frame_bytes": len(frames), "pcm16_wav_bytes": len(wav),
        "pcm16_wav_sha256": _sha(wav), "decoded_pcm_sha256": _sha(pcm.tobytes()),
        "dimensions_verified": True,
    }


def apply_linear_gain(wav_bytes: bytes, gain: float, *,
                      soundfile_root: str | Path | None = None) -> tuple[bytes, dict]:
    """Create a bounded same-dimension PCM16 gain revision."""
    if not isinstance(gain, (int, float)) or not math.isfinite(gain) or not 0.0 <= gain <= 4.0:
        raise ValueError("linear gain must be finite and between 0 and 4")
    rate, channels, frames = sab._validate_pcm16_wav(wav_bytes)
    np, sf = sab._soundfile(soundfile_root)
    pcm, read_rate = sf.read(io.BytesIO(wav_bytes), dtype="int16", always_2d=True)
    if read_rate != rate or pcm.shape != (frames, channels):
        raise ValueError("input WAV decoder dimensions differ from its PCM16 header")
    changed = np.clip(np.rint(pcm.astype(np.float64) * float(gain)), -32768, 32767).astype(np.int16)
    out = io.BytesIO()
    sf.write(out, changed, rate, format="WAV", subtype="PCM_16")
    result = out.getvalue()
    if sab._validate_pcm16_wav(result) != (rate, channels, frames):
        raise ValueError("gain operation changed the PCM16 WAV dimensions")
    reread, reread_rate = sf.read(io.BytesIO(result), dtype="int16", always_2d=True)
    if reread_rate != rate or not np.array_equal(reread, changed):
        raise ValueError("gain WAV did not preserve its exact quantized PCM samples")
    return result, {
        "schema": "replay120-sab-pcm16-linear-gain-v1", "gain": float(gain),
        "source_wav_sha256": _sha(wav_bytes), "result_wav_sha256": _sha(result),
        "rate": rate, "channels": channels, "frames": frames,
        "result_pcm_sha256": _sha(changed.tobytes()), "dimensions_preserved": True,
    }


class SoundBankWorkspace:
    """Trace-backed sound inventory, content-addressed exports and CAS drafts."""

    def __init__(self, fastfile_workspace: Any, cache_root: str | Path,
                 soundfile_root: str | Path | None = None):
        self.fastfiles = fastfile_workspace
        self.cache_root = Path(os.path.abspath(cache_root))
        # SoundBankDraftStore validates the full cache-root component chain.
        self.drafts = drafts_module.SoundBankDraftStore(self.cache_root)
        self.soundfile_root = Path(soundfile_root) if soundfile_root else None

    def _source_path(self, relative_path: str | Path) -> Path:
        candidate = Path(relative_path)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("zone path must be a confined relative FF path")
        source = (self.fastfiles.game_root / candidate).resolve(strict=True)
        if not source.is_relative_to(self.fastfiles.game_root) or source.suffix.lower() != ".ff":
            raise ValueError("zone path must identify an FF inside the configured game root")
        return source

    @staticmethod
    def _sab_paths(source_path: Path, bank: dict) -> tuple[Path, Path]:
        zone_name = bank["root"]["strings"]["zone"]["value"]
        if (not isinstance(zone_name, str) or not zone_name or
                Path(zone_name).name != zone_name or zone_name in (".", "..") or
                re.fullmatch(r"[A-Za-z0-9_.-]+", zone_name) is None):
            raise ValueError("SoundBank zone metadata is not a safe sibling-bank identity")
        base = source_path.with_name(zone_name + ".sabs")
        patch = source_path.with_name("patch_" + zone_name + ".sabs")
        if not base.is_file() or not patch.is_file():
            raise FileNotFoundError("SoundBank metadata does not resolve to both resident base and patch SABs")
        return base.resolve(strict=True), patch.resolve(strict=True)

    @staticmethod
    def _verify_sab_pair(bank: dict) -> tuple[bytes, bytes]:
        base_path, patch_path = bank["base_sab_path"], bank["patch_sab_path"]
        base_data, patch_data = base_path.read_bytes(), patch_path.read_bytes()
        links = bank["receipt"].get("sab_links", {})
        if (_sha(base_data) != links.get("base_sab", {}).get("sha256") or
                _sha(patch_data) != links.get("patch_sab", {}).get("sha256")):
            raise ValueError("base or patch SAB changed after native alias joining")
        return base_data, patch_data

    def _zone_snapshot(self, relative_path: str | Path) -> dict:
        source_path = self._source_path(relative_path)
        extraction = self.fastfiles.extract(relative_path)
        zone_id = extraction.get("zone_id")
        if not isinstance(zone_id, str) or extraction.get("source", {}).get("path") != str(source_path):
            raise ValueError("FastfileWorkspace extraction receipt does not pin the requested source FF")
        cache_path, decode_receipt = self.fastfiles._validated_zone_receipt(zone_id)
        body_path = (cache_path / decode_receipt["final_body_relative_path"]).resolve(strict=True)
        body_bytes = body_path.read_bytes()
        if (_sha(body_bytes) != decode_receipt.get("final_body_sha256") or
                _file_sha(source_path) != decode_receipt.get("source", {}).get("sha256")):
            raise ValueError("decoded body or source FF changed after FastfileWorkspace validation")
        patch_identity = []
        for patch in decode_receipt.get("source", {}).get("patches", []):
            patch_path = Path(patch.get("path", "")).resolve(strict=True)
            patch_sha = patch.get("sha256")
            if (_file_sha(patch_path) != patch_sha or
                    patch_path.stat().st_size != patch.get("bytes")):
                raise ValueError("applied FF patch changed after FastfileWorkspace validation")
            patch_identity.append({"path": str(patch_path), "sha256": patch_sha,
                                   "bytes": patch["bytes"]})
        patch_identity.sort(key=lambda row: row["path"].casefold())
        patch_identity_sha = _sha(json.dumps(patch_identity, sort_keys=True,
                                             separators=(",", ":")).encode("utf-8"))
        if extraction.get("native_walk", {}).get("decoded_body_sha256") != _sha(body_bytes):
            raise ValueError("native walk was produced from another decoded FF body")
        body = fastfiles.ZoneBody.parse(body_bytes)
        walk, native_rows = fastfiles._read_native_rows(cache_path, body, require_trace=True)
        if walk.get("walk_key") != extraction.get("native_walk", {}).get("walk_key"):
            raise ValueError("native walk receipt changed during SoundBank discovery")
        manifest_path = fastfiles._native_walk_artifact(walk, "manifest_relative_path")
        trace_path = fastfiles._native_walk_artifact(walk, "stream_trace_relative_path")
        if (_file_sha(manifest_path) != walk.get("manifest_sha256") or
                _file_sha(trace_path) != walk.get("stream_trace_sha256")):
            raise ValueError("native SoundBank manifest or trace changed after validation")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (manifest.get("profile") != "replay-1.20" or manifest.get("xfile_version") != 4087 or
                manifest.get("failed") != 0 or manifest.get("loaded_assets") != len(body.assets)):
            raise ValueError("SoundBank source requires a complete successful Replay native asset walk")
        if _file_sha(source_path) != decode_receipt["source"]["sha256"]:
            raise ValueError("source FF changed during SoundBank discovery")
        if any(_file_sha(Path(row["path"])) != row["sha256"] for row in patch_identity):
            raise ValueError("applied FF patch changed during SoundBank discovery")

        banks = []
        for index, asset in enumerate(body.assets):
            if asset.type_id != 21:
                continue
            native = native_rows[index]
            if native.get("type") != "soundbank" or not native.get("name"):
                raise ValueError(f"type-21 XAsset {index} has no native SoundBank identity row")
            # The typed reader resolves root zone metadata before the external
            # SAB pair is chosen, so first read without a guessed bank path.
            receipt = read_native_soundbank(
                body_path=body_path, source_fastfile=source_path,
                manifest_path=manifest_path, trace_path=trace_path,
                asset_index=index, asset_name=native["name"])
            base_sab, patch_sab = self._sab_paths(source_path, receipt)
            receipt["sab_links"] = list_resident_codec8_base_ids(
                receipt, sab_base_path=base_sab, sab_patch_path=patch_sab)
            self._verify_sab_pair({"base_sab_path": base_sab,
                                   "patch_sab_path": patch_sab, "receipt": receipt})
            if _file_sha(source_path) != receipt["provenance"]["source_fastfile"]["sha256"]:
                raise ValueError("source FF changed while typed SoundBank alias mapping was built")
            banks.append({"asset_index": index, "asset_id": f"{zone_id}:{index}",
                          "asset_name": native["name"], "receipt": receipt,
                          "base_sab_path": base_sab, "patch_sab_path": patch_sab})
        return {
            "zone_id": zone_id, "relative_path": Path(relative_path).as_posix(),
            "source_path": source_path, "source_sha256": decode_receipt["source"]["sha256"],
            "source_patch_identity": patch_identity,
            "source_patch_set_sha256": patch_identity_sha,
            "body_path": body_path, "body_sha256": _sha(body_bytes),
            "native_walk_key": walk["walk_key"], "manifest_path": manifest_path,
            "manifest_sha256": walk["manifest_sha256"], "trace_path": trace_path,
            "trace_sha256": walk["stream_trace_sha256"], "banks": banks,
        }

    def _zone_snapshot_by_id(self, zone_id: str) -> dict:
        cache_path, decode_receipt = self.fastfiles._validated_zone_receipt(zone_id)
        source = Path(decode_receipt["source"]["path"]).resolve(strict=True)
        if not source.is_relative_to(self.fastfiles.game_root):
            raise ValueError("decoded zone source is outside the configured game root")
        snapshot = self._zone_snapshot(source.relative_to(self.fastfiles.game_root))
        if snapshot["zone_id"] != zone_id:
            raise ValueError("source FF changed and now has a different decoded zone identity")
        return snapshot

    @staticmethod
    def _public_entries(snapshot: dict) -> list[dict]:
        output = []
        for bank in snapshot["banks"]:
            receipt = bank["receipt"]
            for row in receipt["sab_links"]["available"]:
                alias = row["linked_alias"]
                output.append({
                    "zone_id": snapshot["zone_id"], "asset_id": bank["asset_id"],
                    "asset_index": bank["asset_index"], "asset_name": bank["asset_name"],
                    "bank_zone": receipt["root"]["strings"]["zone"]["value"],
                    "file_id": row["file_id"], "sab_index": row["sab_index"],
                    "codec": row["codec"], "rate": row["rate"],
                    "channels": row["channels"], "frames": row["frames"],
                    "alias_name": alias["alias_name"],
                    "asset_file_name": alias["asset_file_name"],
                    "alias": alias, "native_identity_sha256": receipt["source_identity_sha256"],
                    "editable": row["codec"] == 8,
                })
        unique = {}
        for entry in output:
            key = (entry["bank_zone"], entry["file_id"])
            previous = unique.get(key)
            if previous is None:
                unique[key] = entry
            else:
                raise ValueError("one SAB fileId is owned by multiple SoundBank assets; ownership is ambiguous")
        return sorted(unique.values(), key=lambda row: (row["bank_zone"], row["file_id"], row["asset_id"]))

    def list_entries(self, relative_path: str | Path) -> dict:
        snapshot = self._zone_snapshot(relative_path)
        entries = self._public_entries(snapshot)
        return {"schema": "replay120-soundbank-inventory-v1",
                "zone_id": snapshot["zone_id"], "relative_path": snapshot["relative_path"],
                "native_walk_key": snapshot["native_walk_key"],
                "source_identity": {"source_ff_sha256": snapshot["source_sha256"],
                                    "source_patch_set_sha256": snapshot["source_patch_set_sha256"],
                                    "decoded_body_sha256": snapshot["body_sha256"],
                                    "manifest_sha256": snapshot["manifest_sha256"],
                                    "trace_sha256": snapshot["trace_sha256"]},
                "bank_count": len(snapshot["banks"]), "entry_count": len(entries),
                "entries": entries}

    def _select_entry(self, snapshot: dict, asset_id: str, file_id: int) -> tuple[dict, dict]:
        if not isinstance(asset_id, str) or not asset_id.startswith(snapshot["zone_id"] + ":"):
            raise ValueError("asset_id does not belong to the selected decoded zone")
        matches = []
        for bank in snapshot["banks"]:
            if bank["asset_id"] != asset_id:
                continue
            matches.extend(row for row in bank["receipt"]["sab_links"]["available"]
                           if row["file_id"] == file_id)
            if matches:
                return bank, matches[0]
        raise KeyError("fileId is not an unshadowed, trace-linked codec-8 row of this SoundBank asset")

    def export_wav(self, zone_id: str, asset_id: str, file_id: int) -> dict:
        snapshot = self._zone_snapshot_by_id(zone_id)
        bank, selected = self._select_entry(snapshot, asset_id, file_id)
        source_sab = bank["base_sab_path"]
        base_data, _patch_data = self._verify_sab_pair(bank)
        links = bank["receipt"]["sab_links"]
        codec_dependencies = drafts_module._soundfile_identity(self.soundfile_root)
        cache_key_payload = {
            "schema": "replay120-sab-audio-cache-key-v1", "zone_id": zone_id,
            "asset_id": asset_id, "file_id": file_id,
            "reader_identity_sha256": bank["receipt"]["source_identity_sha256"],
            "base_sab_sha256": links["base_sab"]["sha256"],
            "patch_sab_sha256": links["patch_sab"]["sha256"],
            "codec_dependencies": codec_dependencies,
        }
        cache_key = _sha(json.dumps(cache_key_payload, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8"))
        cache_index = drafts_module._inside(
            self.cache_root, self.cache_root / "soundbank-audio-index" / zone_id /
            str(bank["asset_index"]) / str(file_id) / (cache_key + ".json"))
        cached = None
        if cache_index.is_file():
            cached = json.loads(cache_index.read_text(encoding="utf-8"))
            if (cached.get("schema") != "replay120-sab-audio-cache-v1" or
                    cached.get("cache_key_sha256") != cache_key or
                    cached.get("source_identity") != cache_key_payload):
                raise ValueError("cached SAB audio index has a stale or mismatched source identity")
            wav_sha = cached.get("wav_sha256")
            if not isinstance(wav_sha, str) or re.fullmatch(r"[0-9a-f]{64}", wav_sha) is None:
                raise ValueError("cached SAB audio index has an invalid WAV hash")
            output = drafts_module._inside(
                self.cache_root, self.cache_root / "soundbank-audio" / zone_id /
                str(bank["asset_index"]) / str(file_id) / (wav_sha + ".wav"))
            wav = output.read_bytes()
            if _sha(wav) != wav_sha or len(wav) != cached.get("wav_bytes"):
                raise ValueError("cached content-addressed WAV differs from its index")
            rate, channels, frames = sab._validate_pcm16_wav(wav)
            if (rate, channels, frames) != (selected["rate"], selected["channels"], selected["frames"]):
                raise ValueError("cached WAV dimensions differ from the current SAB row")
            decode_receipt = cached.get("decode")
            if (not isinstance(decode_receipt, dict) or
                    decode_receipt.get("schema") != "replay120-sab-codec8-pcm16-export-v1" or
                    decode_receipt.get("file_id") != file_id or
                    decode_receipt.get("sab_index") != selected["sab_index"] or
                    decode_receipt.get("pcm16_wav_sha256") != wav_sha or
                    decode_receipt.get("pcm16_wav_bytes") != len(wav) or
                    decode_receipt.get("dimensions_verified") is not True or
                    (decode_receipt.get("rate"), decode_receipt.get("channels"),
                     decode_receipt.get("frames")) != (rate, channels, frames)):
                raise ValueError("cached SAB decode receipt does not match its source row and WAV")
        else:
            wav, decode_receipt = decode_codec8_wav(
                base_data, file_id, soundfile_root=self.soundfile_root)
            output = (self.cache_root / "soundbank-audio" / zone_id /
                      str(bank["asset_index"]) / str(file_id) /
                      (decode_receipt["pcm16_wav_sha256"] + ".wav"))
        output = drafts_module._inside(self.cache_root, output)
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            if _file_sha(output) != decode_receipt["pcm16_wav_sha256"]:
                raise ValueError("content-addressed audio export path contains different bytes")
        else:
            temp = output.with_name(output.name + "." + os.urandom(8).hex() + ".tmp")
            temp.write_bytes(wav)
            if _file_sha(temp) != decode_receipt["pcm16_wav_sha256"]:
                temp.unlink(missing_ok=True)
                raise ValueError("WAV export failed its content-addressed hash check")
            temp.replace(output)
        if cached is None:
            cache_index.parent.mkdir(parents=True, exist_ok=True)
            drafts_module._atomic_json(cache_index, {
                "schema": "replay120-sab-audio-cache-v1",
                "cache_key_sha256": cache_key, "source_identity": cache_key_payload,
                "wav_sha256": decode_receipt["pcm16_wav_sha256"],
                "wav_bytes": len(wav), "decode": decode_receipt,
            })
        return {"schema": "replay120-soundbank-audio-export-v1",
                "zone_id": zone_id, "asset_id": asset_id, "file_id": file_id,
                "asset_file_name": selected["linked_alias"]["asset_file_name"],
                "wav_path": str(output), "wav_sha256": decode_receipt["pcm16_wav_sha256"],
                "wav_bytes": len(wav), "decode": decode_receipt,
                "native_identity_sha256": bank["receipt"]["source_identity_sha256"],
                "source_identity": {
                    "source_ff_sha256": snapshot["source_sha256"],
                    "source_patch_set_sha256": snapshot["source_patch_set_sha256"],
                    "decoded_body_sha256": snapshot["body_sha256"],
                    "native_manifest_sha256": snapshot["manifest_sha256"],
                    "native_trace_sha256": snapshot["trace_sha256"],
                    "native_walk_key": snapshot["native_walk_key"],
                    "base_sab_sha256": bank["receipt"]["sab_links"]["base_sab"]["sha256"],
                    "patch_sab_sha256": bank["receipt"]["sab_links"]["patch_sab"]["sha256"],
                },
                "codec_dependencies": codec_dependencies,
                "cache_hit": cached is not None,
                "playback_verified": False}

    def export_draft_wav(self, zone_id: str, asset_id: str, file_id: int, revision: str) -> dict:
        """Preview the exact authored revision after its native alias is revalidated."""
        snapshot = self._zone_snapshot_by_id(zone_id)
        self._select_entry(snapshot, asset_id, file_id)
        plan = self.plan_zone(snapshot['relative_path'])
        matches = [row for row in plan['edits'] if row['file_id'] == file_id and row['asset_id'] == asset_id]
        if len(matches) != 1 or matches[0]['revision'] != revision:
            raise ValueError('SAB draft revision conflict; reload before previewing')
        current, draft, _wav = self.drafts._read_current(zone_id, file_id)
        if draft['revision'] != revision:
            raise ValueError('SAB draft changed during preview validation')
        return {'wav_path': str(current.parent / draft['wav_payload_name']),
                'wav_sha256': draft['wav_sha256'], 'revision': revision}

    def stage_wav(self, zone_id: str, asset_id: str, file_id: int, wav_bytes: bytes,
                  expected_revision: str | None = None) -> dict:
        snapshot = self._zone_snapshot_by_id(zone_id)
        bank, selected = self._select_entry(snapshot, asset_id, file_id)
        self._verify_sab_pair(bank)
        same_id = [entry for entry in self._public_entries(snapshot)
                   if entry["file_id"] == file_id]
        if len(same_id) != 1 or same_id[0]["asset_id"] != asset_id:
            raise ValueError("cannot stage a fileId owned by multiple SoundBank roots")
        selected_pair = (str(bank["base_sab_path"].resolve()),
                         str(bank["patch_sab_path"].resolve()))
        for draft in self.drafts.list_drafts(zone_id):
            _current, active, _wav = self.drafts._read_current(zone_id, draft["file_id"])
            source = active["source_identity"]
            active_pair = (source.get("base_path"), source.get("patch_path"))
            if active_pair != selected_pair:
                raise ValueError("one zone draft set cannot span separate base/patch SAB pairs")
        alias = dict(selected["linked_alias"])
        sab_links = bank["receipt"]["sab_links"]
        alias["native_provenance"] = {
            "source_ff_sha256": snapshot["source_sha256"],
            "source_patch_set_sha256": snapshot["source_patch_set_sha256"],
            "decoded_body_sha256": snapshot["body_sha256"],
            "native_manifest_sha256": snapshot["manifest_sha256"],
            "native_trace_sha256": snapshot["trace_sha256"],
            "native_walk_key": snapshot["native_walk_key"],
            "reader_identity_sha256": bank["receipt"]["source_identity_sha256"],
            "base_sab_sha256": sab_links["base_sab"]["sha256"],
            "patch_sab_sha256": sab_links["patch_sab"]["sha256"],
        }
        staged = self.drafts.stage_entry(
            zone_id=zone_id, base_sab=bank["base_sab_path"],
            patch_sab=bank["patch_sab_path"], file_id=file_id,
            linked_alias=alias, wav_bytes=wav_bytes,
            expected_revision=expected_revision,
            soundfile_root=self.soundfile_root)
        return dict(staged, asset_id=asset_id,
                    native_identity_sha256=bank["receipt"]["source_identity_sha256"],
                    native_walk_key=snapshot["native_walk_key"],
                    native_source_identity={
                        "source_ff_sha256": snapshot["source_sha256"],
                        "source_patch_set_sha256": snapshot["source_patch_set_sha256"],
                        "decoded_body_sha256": snapshot["body_sha256"],
                        "native_manifest_sha256": snapshot["manifest_sha256"],
                        "native_trace_sha256": snapshot["trace_sha256"],
                        "native_walk_key": snapshot["native_walk_key"],
                        "reader_identity_sha256": bank["receipt"]["source_identity_sha256"],
                        "base_sab_sha256": sab_links["base_sab"]["sha256"],
                        "patch_sab_sha256": sab_links["patch_sab"]["sha256"]})

    def stage_gain(self, zone_id: str, asset_id: str, file_id: int, gain: float,
                   expected_revision: str | None = None) -> dict:
        exported = (self.export_draft_wav(zone_id, asset_id, file_id, expected_revision)
                    if expected_revision is not None else self.export_wav(zone_id, asset_id, file_id))
        source_wav = Path(exported["wav_path"]).read_bytes()
        gained, gain_receipt = apply_linear_gain(source_wav, gain,
                                                 soundfile_root=self.soundfile_root)
        staged = self.stage_wav(zone_id, asset_id, file_id, gained, expected_revision)
        return dict(staged, gain= gain_receipt)

    def discard(self, zone_id: str, file_id: int, expected_revision: str) -> dict:
        return self.drafts.discard_entry(zone_id, file_id, expected_revision)

    def plan_zone(self, relative_path: str | Path) -> dict:
        snapshot = self._zone_snapshot(relative_path)
        entries = self._public_entries(snapshot)
        by_id: dict[int, list[dict]] = {}
        for entry in entries:
            by_id.setdefault(entry["file_id"], []).append(entry)
        staged = self.drafts.list_drafts(snapshot["zone_id"])
        codec_dependencies = drafts_module._soundfile_identity(self.soundfile_root)
        planned = []
        for draft in staged:
            matches = by_id.get(draft["file_id"], [])
            if len(matches) != 1:
                raise ValueError("staged fileId no longer has one current native alias mapping")
            entry = matches[0]
            owner_bank = next(bank for bank in snapshot["banks"]
                              if bank["asset_id"] == entry["asset_id"])
            self._verify_sab_pair(owner_bank)
            _path, current, _wav = self.drafts._read_current(snapshot["zone_id"], draft["file_id"])
            source = current["source_identity"]
            expected_native_provenance = {
                "source_ff_sha256": snapshot["source_sha256"],
                "source_patch_set_sha256": snapshot["source_patch_set_sha256"],
                "decoded_body_sha256": snapshot["body_sha256"],
                "native_manifest_sha256": snapshot["manifest_sha256"],
                "native_trace_sha256": snapshot["trace_sha256"],
                "native_walk_key": snapshot["native_walk_key"],
                "reader_identity_sha256": entry["native_identity_sha256"],
                "base_sab_sha256": owner_bank["receipt"]["sab_links"]["base_sab"]["sha256"],
                "patch_sab_sha256": owner_bank["receipt"]["sab_links"]["patch_sab"]["sha256"],
            }
            if (source.get("alias_source_identity_sha256") != entry["native_identity_sha256"] or
                    source.get("asset_file_name") != entry["asset_file_name"] or
                    source.get("base_sha256") != owner_bank["receipt"]["sab_links"]["base_sab"]["sha256"] or
                    source.get("patch_sha256") != owner_bank["receipt"]["sab_links"]["patch_sab"]["sha256"] or
                    current.get("codec_dependencies") != codec_dependencies or
                    source.get("native_provenance") != expected_native_provenance):
                raise ValueError("staged draft's native SoundBank alias proof is stale")
            planned.append({"file_id": draft["file_id"], "asset_id": entry["asset_id"],
                            "asset_file_name": entry["asset_file_name"],
                            "revision": draft["revision"],
                            "native_identity_sha256": entry["native_identity_sha256"]})
        return {"schema": "replay120-soundbank-package-plan-v1",
                "zone_id": snapshot["zone_id"], "relative_path": snapshot["relative_path"],
                "source_identity": {"source_ff_sha256": snapshot["source_sha256"],
                                    "source_patch_set_sha256": snapshot["source_patch_set_sha256"],
                                    "decoded_body_sha256": snapshot["body_sha256"],
                                    "manifest_sha256": snapshot["manifest_sha256"],
                                    "trace_sha256": snapshot["trace_sha256"],
                                    "native_walk_key": snapshot["native_walk_key"],
                                    "codec_dependencies": codec_dependencies},
                "edits": planned, "pending_snapshot": self.drafts.pending_snapshot(snapshot["zone_id"]),
                "packageable": bool(planned)}

    def package_zone(self, relative_path: str | Path, output_dir: str | Path,
                     expected_snapshot: dict[str, str] | None = None) -> dict:
        plan = self.plan_zone(relative_path)
        if not plan["packageable"]:
            raise ValueError("zone has no active native-linked SAB WAV drafts")
        if expected_snapshot is not None and plan["pending_snapshot"] != expected_snapshot:
            raise ValueError("SAB draft set changed after coordinator planning")
        cache_parent = drafts_module._inside(
            self.cache_root, self.cache_root / "soundbank-package-tmp")
        cache_parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="package-", dir=cache_parent) as temp_name:
            package = self.drafts.package_zone(
                zone_id=plan["zone_id"], output_dir=temp_name,
                soundfile_root=self.soundfile_root,
                expected_snapshot=plan["pending_snapshot"])
            # Rewalk the native source immediately before publication. Draft
            # and SAB hashes are separately rechecked by the packager.
            after = self.plan_zone(relative_path)
            if (after["source_identity"] != plan["source_identity"] or
                    after["pending_snapshot"] != plan["pending_snapshot"]):
                raise ValueError("native SoundBank source or staged drafts changed during package build")
            filename = package["output"]["filename"]
            output_root = Path(os.path.abspath(output_dir))
            final_path = drafts_module._inside(output_root, output_root / filename)
            first = self.drafts.list_drafts(plan["zone_id"])[0]
            _draft_path, draft_row, _wav = self.drafts._read_current(
                plan["zone_id"], first["file_id"])
            source_identity = draft_row["source_identity"]
            if final_path in (Path(source_identity["base_path"]).resolve(),
                              Path(source_identity["patch_path"]).resolve()):
                raise ValueError("replacement SAB output must not overwrite a source or patch bank")
            output_root.mkdir(parents=True, exist_ok=True)
            final_path = drafts_module._inside(output_root, output_root / filename)
            packaged_bytes = Path(package["output"]["path"]).read_bytes()
            if _sha(packaged_bytes) != package["output"]["sha256"]:
                raise ValueError("temporary SAB package no longer matches its writer receipt")
            package["output"]["path"] = str(final_path)
            package["native_source_identity"] = plan["source_identity"]
            package["native_source_identity"]["soundbank_receipts"] = [
                {"asset_id": edit["asset_id"], "file_id": edit["file_id"],
                 "reader_identity_sha256": edit["native_identity_sha256"]}
                for edit in plan["edits"]]
            package["native_aliases_revalidated"] = True
            package["playback_verified"] = False
            receipt_path = drafts_module._inside(
                output_root, output_root / (Path(filename).stem + ".sab-draft-receipt.json"))
            package["receipt_path"] = str(receipt_path)
            receipt_bytes = (json.dumps(package, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
            drafts_module._publish_package(output_root, [(final_path, packaged_bytes),
                                                        (receipt_path, receipt_bytes)])
            package["receipt_sha256"] = _file_sha(receipt_path)
            return package
