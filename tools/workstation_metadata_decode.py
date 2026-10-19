"""Strict source decode fallback that exposes only the serialized XAsset table."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile

import workstation_fastfiles as fastfiles


def _stable(value):
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str))


def _source_identity(profile):
    value = _stable(profile)
    return dict(source=value.get("path"), sha256=value.get("sha256"),
                input_format=value.get("input_format"), header=value.get("header"),
                final_header=value.get("final_header"),
                patches=[dict(extension=row.get("extension"), path=row.get("path"),
                              bytes=row.get("bytes"), sha256=row.get("sha256"))
                         for row in value.get("patches", [])])


def _validate_decode_receipt(receipt, body, cache_key, source_profile,
                             acts_identity, replay_sha, source):
    if (not isinstance(receipt, dict) or receipt.get("status") != "decoded-and-validated" or
            receipt.get("cache_key") != cache_key or
            receipt.get("final_body_sha256") != body.source_sha256 or
            receipt.get("final_body_bytes") != len(body.data)):
        raise ValueError("table-only decode receipt does not match its validated body")
    if _source_identity(receipt.get("source", {})) != _source_identity(source_profile):
        raise ValueError("table-only receipt has a stale or incomplete source/FP/FC identity")
    tools = receipt.get("tools")
    if (not isinstance(tools, dict) or tools.get("acts_tool_identity") != _stable(acts_identity) or
            tools.get("acts_sha256") != acts_identity.get("executable_sha256") or
            tools.get("replay_executable_sha256") != replay_sha):
        raise ValueError("table-only receipt has stale ACTS or Replay reader identity")
    patches = source_profile.get("patches", [])
    outputs = receipt.get("outputs")
    if not isinstance(outputs, list):
        raise ValueError("table-only receipt has no validated decode output list")
    output_paths = {row.get("relative_path") for row in outputs
                    if isinstance(row, dict) and isinstance(row.get("relative_path"), str)}
    application = receipt.get("patch_application")
    header_only = source_profile.get("header_only_zero_payload_chain") is True
    header_only_application = (isinstance(application, dict) and
                               application.get("mode") == "header-only-fp-no-body-change")
    if header_only_application:
        if not header_only or not patches or not all(
                row.get("header_only_zero_payload") is True for row in patches):
            raise ValueError("header-only receipt mode lacks a freshly validated zero-payload source chain")
        if _stable(receipt.get("source")) != _stable(source_profile):
            raise ValueError("header-only receipt source profile differs from current full source/patch proof")
        expected = [dict(extension=row.get("extension"), sha256=row.get("sha256"),
                         previous_header_hex=row.get("previous_header_hex"),
                         target_header_hex=row.get("target_header_hex"),
                         previous_layout=row.get("previous_layout"),
                         target_layout=row.get("target_layout")) for row in patches]
        if _stable(application.get("patches")) != _stable(expected):
            raise ValueError("header-only receipt patch headers/layouts/digests differ from current source")
    elif header_only:
        raise ValueError("validated zero-payload source chain lacks its exact header-only receipt proof")
    # These unsigned formats are decoded directly by the strict Python reader,
    # so their receipts have no ACTS patch decode outputs.
    if (patches and not header_only_application and source_profile.get("input_format") not in (
            "replay120-iwc-uncompressed-v1", "replay120-stored-frame-v1")):
        for patch in patches:
            ext = patch.get("extension")
            if (not isinstance(ext, str) or
                    not any(path.endswith(f"{source.stem}{ext}.dec") for path in output_paths) or
                    not any(path.endswith(f"{source.stem}{ext}.patched.dec") for path in output_paths)):
                raise ValueError("table-only receipt does not include every decoded FP/FC patch output")
        final = receipt.get("final_body_relative_path")
        if not isinstance(final, str) or not final.endswith(
                f"{source.stem}{patches[-1]['extension']}.patched.dec"):
            raise ValueError("table-only receipt final body is not the fully patched decode")
    table = receipt.get("xasset_table")
    if (not isinstance(table, dict) or table.get("asset_count") != len(body.assets) or
            table.get("first_payload_offset") != body.first_payload_offset):
        raise ValueError("table-only receipt XAsset table coverage differs from the decoded body")


def decode_table_only_metadata(workspace, relative, native_reader_error=None,
                               decode_cache_root=None):
    """Strictly decode one FF and return its full XAsset table without a native walk.

    By default, the strict decode cache lives in a system temporary directory
    and is removed before returning. A caller may pass the workspace's own
    cache root to reuse an already validated decode. This result is for
    display/search only; native names, reference classifications, and asset-
    root ownership remain unknown.
    """
    source = workspace._zone_path(relative)
    source_before = _stable(fastfiles.source_profile(source))
    acts_before = _stable(fastfiles.acts_tool_identity(workspace.acts_path))
    replay_path = Path(workspace.replay_executable).resolve(strict=True)
    replay_before = fastfiles.sha256_file(replay_path)

    if decode_cache_root is None:
        cache_context = tempfile.TemporaryDirectory(prefix="table-only-decode-")
        cache_root = None
    else:
        cache_root = Path(decode_cache_root).resolve()
        expected_cache_root = Path(workspace.cache_root).resolve()
        if cache_root != expected_cache_root:
            raise ValueError("decode_cache_root must equal the workspace cache root")
        cache_context = None

    def decode_from_cache(cache_root):
        decode = fastfiles.decode_source_fastfile(
            source, cache_root, workspace.acts_path, replay_path)
        cache_key = decode.get("cache_key") if isinstance(decode, dict) else None
        if not isinstance(cache_key, str) or not cache_key:
            raise ValueError("strict source decoder returned no cache key")
        cache_path = cache_root / source.stem / cache_key
        receipt, body = fastfiles._cache_receipt(cache_path, cache_key, include_body=True)
        _validate_decode_receipt(receipt, body, cache_key, source_before,
                                 acts_before, replay_before, source)

        source_after = fastfiles.source_profile(source)
        acts_after = fastfiles.acts_tool_identity(workspace.acts_path)
        replay_after = fastfiles.sha256_file(replay_path)
        if (_source_identity(source_after) != _source_identity(source_before) or
                _stable(acts_after) != _stable(acts_before) or replay_after != replay_before):
            raise RuntimeError("source fastfile, FP/FC chain, ACTS, or Replay changed during table decode")
        rows = [dict(index=header.index, type_id=header.type_id,
                     pointer_token=f"0x{header.pointer_token:016x}",
                     name=None, type_name=None, reference_only=None,
                     status="xasset-table-only-reader-unavailable")
                for header in body.assets]
        result = dict(zone_id=cache_key, source_identity=_source_identity(source_before),
                      body_sha256=body.source_sha256, native_walk_key=None,
                      reader_scope="xasset-table-only", rows=rows)
        if native_reader_error is not None:
            result["native_reader_error"] = str(native_reader_error)
        return result

    if cache_context is not None:
        with cache_context as temporary:
            return decode_from_cache(Path(temporary) / "cache")
    return decode_from_cache(cache_root)
