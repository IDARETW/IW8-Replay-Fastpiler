"""Trace-bound Replay 1.20 RawFile inspection and native payload replacement."""
from __future__ import annotations

from dataclasses import dataclass, field
from dataclasses import asdict
import base64
import hashlib
import json
from pathlib import Path
import struct
import zlib

try:
    from workstation_fastfiles import ZoneBody
    from workstation_native_child_relocation import InlineChildLayout, relocate_stream5_children
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody
    from tools.workstation_native_child_relocation import InlineChildLayout, relocate_stream5_children


RAWFILE_TYPE_ID = 51
RAWFILE_ROOT_BYTES = 24
INLINE = 0xFFFFFFFFFFFFFFFE
PTR_FOLLOWS = 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True)
class RawFileLayout:
    asset_index: int
    asset_name: str
    root_archive_offset: int
    root_stream_offset: int
    payload_archive_offset: int
    payload_stream_offset: int
    payload_bytes: int
    raw_bytes: int
    compressed: bool
    root_token: int
    source_body_sha256: str
    source_payload_sha256: str
    name_inline: bool = True

    @property
    def buffer_token(self) -> int:
        """Serialized RawFile buffer token (historical field name: root_token)."""
        return self.root_token


@dataclass(frozen=True)
class RawFileReadContext:
    """Validate one immutable decoded body once for a whole-zone reread."""
    data: bytes = field(repr=False)
    parsed: ZoneBody = field(init=False, repr=False)
    sha256: str = field(init=False)

    def __post_init__(self):
        if type(self.data) is not bytes:
            raise ValueError("RawFile read context requires immutable body bytes")
        object.__setattr__(self, "parsed", ZoneBody.parse(self.data))
        object.__setattr__(self, "sha256", _sha(self.data))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _raw_bytes(body: bytes, trace_asset: dict, native_row: dict,
               expected_body_sha256: str | None,
               context: RawFileReadContext | None = None) -> tuple[RawFileLayout, bytes]:
    if context is None:
        context = RawFileReadContext(body)
    if type(context) is not RawFileReadContext or context.data is not body:
        raise ValueError("RawFile read context belongs to a different decoded body")
    parsed = context.parsed
    index = native_row.get("index", native_row.get("xasset_index"))
    name = native_row.get("name")
    if (type(index) is not int or not 0 <= index < len(parsed.assets) or
            parsed.assets[index].type_id != RAWFILE_TYPE_ID or
            native_row.get("type_id") != RAWFILE_TYPE_ID):
        raise ValueError("selected XAsset is not a type-51 RawFile")
    if (trace_asset.get("index", trace_asset.get("xasset_index")) != index or
            trace_asset.get("type_id") != RAWFILE_TYPE_ID or
            trace_asset.get("name") != name):
        raise ValueError("native trace row does not match the selected RawFile")
    if not isinstance(name, str) or not name or "\0" in name:
        raise ValueError("RawFile has an invalid native name")
    digest = context.sha256
    if expected_body_sha256 is not None and digest != expected_body_sha256:
        raise ValueError("RawFile trace belongs to a different decoded body")
    row = parsed.assets[index]
    root_token = row.pointer_token
    if root_token != INLINE:
        raise ValueError("RawFile XAsset root is not the supported inline form")
    spans = trace_asset.get("read_spans")
    if not isinstance(spans, list):
        raise ValueError("RawFile trace row has no physical read spans")
    roots = [span for span in spans if span.get("origin") == "load_stream_call" and
             span.get("reader_start_arg") == 0 and span.get("size") == RAWFILE_ROOT_BYTES and
             isinstance(span.get("destination_stream_location"), dict) and
             span["destination_stream_location"].get("stream") == 1]
    if len(roots) != 1:
        raise ValueError("RawFile requires exactly one traced 24-byte AtStart root")
    root = roots[0]
    root_at = root.get("archive_offset")
    root_loc = root.get("destination_stream_location")
    if (type(root_at) is not int or root_at < 0 or root_at + RAWFILE_ROOT_BYTES > len(body) or
            not isinstance(root_loc, dict) or root_loc.get("stream") != 1 or
            type(root_loc.get("offset")) is not int):
        raise ValueError("RawFile root is outside the decoded body or not on stream 1")
    name_token, compressed_len, raw_len, buffer_token = struct.unpack_from("<QiiQ", body, root_at)
    if min(compressed_len, raw_len) < 0:
        raise ValueError("RawFile contains a negative native payload length")
    name_data = name.encode("utf-8") + b"\0"
    child_start = root_at + RAWFILE_ROOT_BYTES
    name_inline = name_token in (PTR_FOLLOWS, INLINE)
    if name_token in (PTR_FOLLOWS, INLINE):
        name_spans = [span for span in spans if span.get("origin") == "string_data" and
                      span.get("archive_offset") == child_start and span.get("size") == len(name_data)]
        if len(name_spans) != 1:
            raise ValueError("RawFile name requires one exact trace-owned string read")
        name_span = name_spans[0]
        name_at = name_span.get("archive_offset")
        name_loc = name_span.get("destination_stream_location")
        if (type(name_at) is not int or name_at + len(name_data) > len(body) or
                body[name_at:name_at + len(name_data)] != name_data or
                not isinstance(name_loc, dict) or name_loc.get("stream") != 5):
            raise ValueError("RawFile name bytes differ from the exact traced XAsset name")
        name_stream_end = name_loc["offset"] + len(name_data)
        child_start += len(name_data)
    else:
        # A reused XString consumes no archive bytes. Bind the serialized
        # root field to its native resolution and the earlier physical read.
        resolutions = [event for event in trace_asset.get("packed_pointer_events", [])
                       if event.get("xasset_index") == index and event.get("raw_token") == name_token and
                       event.get("field_stream_location") == root_loc and
                       event.get("kind") in ("packed_resolve", "packed_alias")]
        if len(resolutions) != 1 or name_token >> 32 != 5 or (name_token & 0xFFFFFFFF) == 0:
            raise ValueError("RawFile packed name has no exact absolute stream-5 resolution")
        resolution = resolutions[0]
        target = resolution.get("resolved_target_stream_location")
        target_offset = (name_token & 0xFFFFFFFF) - 1
        if target != {"stream": 5, "offset": target_offset}:
            raise ValueError("RawFile packed name token differs from its native resolved target")
        name_spans = []
        for span in trace_asset.get("_all_physical_spans", []):
            location = span.get("destination_stream_location")
            start, size, sequence = (location.get("offset") if isinstance(location, dict) else None,
                                     span.get("size"), span.get("event_sequence"))
            if (not isinstance(location, dict) or location.get("stream") != 5 or
                    type(start) is not int or type(size) is not int or type(sequence) is not int or
                    type(resolution.get("sequence")) is not int or sequence >= resolution["sequence"] or
                    not start <= target_offset or target_offset + len(name_data) > start + size):
                continue
            archive_at = span.get("archive_offset")
            if type(archive_at) is not int:
                continue
            name_at = archive_at + target_offset - start
            if 0 <= name_at <= len(body) - len(name_data) and body[name_at:name_at + len(name_data)] == name_data:
                name_spans.append(span)
        if len(name_spans) != 1:
            raise ValueError("RawFile packed name does not identify one earlier trace-owned XString")
        name_stream_end = -1
    if compressed_len == 0 and raw_len == 0:
        if buffer_token not in (0, INLINE):
            raise ValueError("empty RawFile buffer uses an unsupported pointer mode")
        child = None
        payload = b""
        child_at = child_start
        child_stream = name_stream_end
    else:
        if buffer_token != INLINE:
            raise ValueError("RawFile buffer uses an unsupported packed, shared or referenced pointer")
        payload_bytes = compressed_len if compressed_len else raw_len
        children = [span for span in spans if span.get("origin") == "load_stream_call" and
                    span.get("reader_start_arg") == 0 and span.get("size") == payload_bytes and
                    span.get("archive_offset", -1) == child_start and
                    isinstance(span.get("destination_stream_location"), dict) and
                    span["destination_stream_location"].get("stream") == 5]
        if len(children) != 1:
            raise ValueError("RawFile payload requires one exact traced AtStart compressed buffer read")
        child = children[0]
        child_at = child.get("archive_offset")
        child_loc = child.get("destination_stream_location")
        if (type(child_at) is not int or child_at < 0 or child_at + payload_bytes > len(body) or
                not isinstance(child_loc, dict) or child_loc.get("stream") != 5 or
                type(child_loc.get("offset")) is not int or child_at < root_at + RAWFILE_ROOT_BYTES):
            raise ValueError("RawFile payload span is outside the body or not on stream 5")
        payload = body[child_at:child_at + payload_bytes]
        child_stream = child_loc["offset"]
    payload_bytes = compressed_len if compressed_len else raw_len
    end_at = child_at + payload_bytes if payload_bytes else child_start
    if trace_asset.get("end_cursor") != end_at:
        raise ValueError("RawFile trace end cursor does not match its serialized root and payload")
    if compressed_len:
        try:
            inflater = zlib.decompressobj()
            raw = inflater.decompress(payload, raw_len + 1)
        except zlib.error as error:
            raise ValueError("RawFile compressed payload is not valid zlib data") from error
        if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
            raise ValueError("RawFile zlib payload has trailing or incomplete data")
        if len(raw) != raw_len:
            raise ValueError("RawFile decompressed length differs from its native len field")
    else:
        raw = payload
        if len(raw) != raw_len:
            raise ValueError("RawFile uncompressed buffer length differs from its native len field")
    layout = RawFileLayout(index, name, root_at, root_loc["offset"], child_at,
                           child_stream, payload_bytes, raw_len, bool(compressed_len),
                           buffer_token, digest, _sha(payload), name_inline)
    return layout, raw


def read_rawfile(body_data: bytes, native_row: dict, trace_asset: dict,
                 expected_body_sha256: str | None = None, *,
                 context: RawFileReadContext | None = None) -> tuple[RawFileLayout, dict]:
    """Read a trace-owned RawFile as UTF-8 text or lossless base64 binary."""
    layout, raw = _raw_bytes(body_data, trace_asset, native_row, expected_body_sha256, context)
    try:
        content = raw.decode("utf-8")
        if any(byte < 32 and byte not in (9, 10, 13) for byte in raw):
            raise UnicodeDecodeError("utf-8", raw, 0, len(raw), "binary control bytes")
        mode = "text"
    except UnicodeDecodeError:
        content = base64.b64encode(raw).decode("ascii")
        mode = "base64"
    return layout, dict(mode=mode, content=content, byte_length=len(raw),
                        raw_sha256=_sha(raw), asset_name=layout.asset_name,
                        asset_index=layout.asset_index)


def encode_rawfile(content: str, layout: RawFileLayout, mode: str) -> bytes:
    """Encode editor content without losing binary RawFile bytes."""
    if mode == "text":
        if not isinstance(content, str):
            raise ValueError("RawFile text content must be a string")
        raw = content.encode("utf-8")
    elif mode == "base64":
        if not isinstance(content, str):
            raise ValueError("RawFile base64 content must be a string")
        try:
            raw = base64.b64decode(content, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ValueError("RawFile binary editor content must be valid base64") from error
    else:
        raise ValueError("RawFile editor mode must be text or base64")
    if len(raw) > 0x7FFFFFFF:
        raise ValueError("RawFile exceeds the target signed length range")
    return raw


def replace_rawfile_payload(body_data: bytes, native_row: dict, trace_asset: dict,
                            content: str, mode: str, expected_body_sha256: str,
                            trace_path: str, manifest_path: str) -> tuple[bytes, dict]:
    """Replace one inline RawFile buffer and relocate native stream-5 aliases."""
    layout, _ = _raw_bytes(body_data, trace_asset, native_row, expected_body_sha256)
    raw = encode_rawfile(content, layout, mode)
    if not layout.payload_bytes and not raw:
        return body_data, dict(schema="replay120-rawfile-empty-noop-v1",
            status="semantic-noop-null-buffer", asset_index=layout.asset_index,
            asset_name=layout.asset_name, output_body_sha256=_sha(body_data))
    if (not layout.payload_bytes and
            (layout.raw_bytes != 0 or layout.buffer_token != 0 or not layout.name_inline or
             layout.payload_stream_offset < 0)):
        raise ValueError("null-buffer RawFile growth requires exact inline-name and cursor ownership")
    # Replay's RawFile loader consumes the buffer using compressedLen. A
    # null/zero source has no encoding mode to preserve, so newly allocated
    # buffers must use the native zlib representation even when len=0 was
    # originally stored with compressedLen=0.
    output_compressed = layout.compressed or (layout.payload_bytes == 0 and bool(raw))
    payload = zlib.compress(raw) if output_compressed else raw
    if len(payload) > 0x7FFFFFFF:
        raise ValueError("RawFile encoded payload exceeds the target signed length range")
    native_layout = InlineChildLayout(
        asset_name=layout.asset_name, root_archive_offset=layout.root_archive_offset,
        child_archive_offset=layout.payload_archive_offset,
        child_stream_offset=layout.payload_stream_offset, child_bytes=layout.payload_bytes,
        child_sha256=layout.source_payload_sha256,
        length_field_offset=8 if output_compressed else 12,
        length_format="<i", allow_empty_insert=layout.payload_bytes == 0)
    updated, receipt = relocate_stream5_children(
        body_data, {layout.asset_index: native_layout},
        {layout.asset_index: payload}, trace_path, manifest_path)
    if updated != body_data:
        changed = bytearray(updated)
        struct.pack_into("<i", changed, layout.root_archive_offset + 8,
                         len(payload) if output_compressed else 0)
        struct.pack_into("<i", changed, layout.root_archive_offset + 12, len(raw))
        if layout.payload_bytes == 0:
            struct.pack_into("<Q", changed, layout.root_archive_offset + 16, INLINE)
        updated = bytes(changed)
    return updated, dict(schema="replay120-rawfile-edit-v1", asset_index=layout.asset_index,
                         asset_name=layout.asset_name, mode=mode,
                         old_raw_bytes=layout.raw_bytes, new_raw_bytes=len(raw),
                         old_payload_bytes=layout.payload_bytes, new_payload_bytes=len(payload),
                         output_compressed=output_compressed,
                         output_body_sha256=_sha(updated), relocation=receipt)


def _workspace_inputs(snapshot, selected=None):
    from workstation_fastfiles import _native_walk_artifact, sha256_file
    from workstation_trace_index import build_read_span_index
    walk, profile = snapshot.native_walk, snapshot.source_profile
    if (not walk.get("stream_trace_enabled") or
            walk.get("identity", {}).get("source_sha256") != profile.get("sha256") or
            walk.get("identity", {}).get("patch_sha256s") !=
            [row["sha256"] for row in profile.get("patches", [])]):
        raise ValueError("RawFile requires the complete native trace of the current FF/patch chain")
    trace = _native_walk_artifact(walk, "stream_trace_relative_path")
    manifest = _native_walk_artifact(walk, "manifest_relative_path")
    if sha256_file(trace) != walk.get("stream_trace_sha256") or sha256_file(manifest) != walk.get("manifest_sha256"):
        raise ValueError("RawFile trace/manifest differs from its validated reader receipt")
    index = build_read_span_index(trace, manifest, len(snapshot.body.data), selected_assets=selected)
    assets = {row["index"]: dict(row, name=snapshot.native_rows[row["index"]].get("name"),
        _all_physical_spans=index["_all_physical_spans"]) for row in index["assets"]}
    return trace, manifest, assets


def get_rawfile_asset(workspace, asset_id, snapshot, index):
    trace, manifest, assets = _workspace_inputs(snapshot, {index})
    native = dict(snapshot.native_rows[index], index=index)
    trace_asset = assets[index]
    layout, decoded = read_rawfile(snapshot.body.data, native, trace_asset, snapshot.body.source_sha256)
    walk, profile = snapshot.native_walk, snapshot.source_profile
    suffix = Path(native["name"]).suffix.lstrip(".").lower() or "txt"
    identity = dict(body_sha256=snapshot.body.source_sha256, source_fastfile_sha256=profile["sha256"],
        native_walk_key=walk["walk_key"], native_manifest_sha256=walk["manifest_sha256"],
        stream_trace_sha256=walk["stream_trace_sha256"], xasset_index=index,
        root_span=dict(archive_offset=layout.root_archive_offset, bytes=24),
        record_span=dict(archive_offset=layout.payload_archive_offset, bytes=layout.payload_bytes,
                         sha256=layout.source_payload_sha256),
        typed_layout=asdict(layout) | {"editor_mode": decoded["mode"]})
    remove_candidate = (index == len(snapshot.body.assets) - 1 and layout.name_inline and
        trace_asset.get("end_cursor") == len(snapshot.body.data) and
        (layout.payload_bytes == 0 and layout.buffer_token in (0, INLINE) or
         layout.payload_bytes > 0 and layout.buffer_token == INLINE))
    remove_reason = None if remove_candidate else (
        "Only the final RawFile with trace-owned inline name/buffer spans reaching body EOF is a removal candidate")
    return dict(asset_id=asset_id, zone_id=snapshot.zone_id, index=index, type_id=51,
        type="rawfile", name=native["name"], content=decoded["content"],
        language="ini" if suffix == "cfg" and decoded["mode"] == "text" else "plaintext",
        extension=suffix if decoded["mode"] == "text" else "base64", editor_mode=decoded["mode"],
        revision=_sha(decoded["content"].encode("utf-8")),
        editable=bool(layout.payload_bytes) or (layout.raw_bytes == 0 and layout.buffer_token == 0
            and layout.name_inline and layout.payload_stream_offset >= 0), archive_writable=False,
        row_remove_supported=remove_candidate, row_remove_reason=remove_reason,
        payload_format="Replay RawFile zlib buffer" if layout.compressed else "Replay RawFile inline buffer",
        payload_bytes=layout.payload_bytes, payload_sha256=layout.source_payload_sha256,
        raw_bytes=decoded["byte_length"], source=identity,
        package_status="Native RawFile text/binary edits relocate stream-5 references and require a complete replacement-zone reread"
            if layout.payload_bytes else "Null-buffer empty RawFile accepts growth only when the native trace proves its inline-name stream cursor")


def compile_rawfile_asset(workspace, asset_id, content, current, body, cache_path, walk, native):
    from workstation_fastfiles import _native_walk_artifact, sha256_file
    from workstation_trace_index import build_read_span_index
    index = current["index"]
    trace = _native_walk_artifact(walk, "stream_trace_relative_path")
    manifest = _native_walk_artifact(walk, "manifest_relative_path")
    if (sha256_file(trace) != current["source"].get("stream_trace_sha256") or
            sha256_file(manifest) != current["source"].get("native_manifest_sha256")):
        raise ValueError("RawFile source trace changed before compilation")
    span_index = build_read_span_index(trace, manifest, len(body.data), selected_assets={index})
    rows = span_index["assets"]
    if len(rows) != 1:
        raise ValueError("RawFile trace ownership is ambiguous")
    owner = dict(rows[0], name=native["name"], _all_physical_spans=span_index["_all_physical_spans"])
    layout, original = read_rawfile(body.data, dict(native, index=index), owner, body.source_sha256)
    mode = current["source"]["typed_layout"]["editor_mode"]
    raw = encode_rawfile(content, layout, mode)
    output_compressed = layout.compressed or (layout.payload_bytes == 0 and bool(raw))
    payload = zlib.compress(raw) if output_compressed else raw
    _, replacement = replace_rawfile_payload(body.data, dict(native, index=index), owner,
        content, mode, body.source_sha256, str(trace), str(manifest))
    module_path = Path(__file__).resolve()
    receipt = dict(schema="replay120-rawfile-compile-receipt-v1", status="replay120-rawfile-encode-pass",
        asset_name=native["name"], source=dict(sha256=_sha(content.encode("utf-8"))),
        compiler=dict(writer_module_path=str(module_path), writer_module_sha256=sha256_file(module_path)),
        input=dict(asset_index=index, mode=mode, source_raw_sha256=original["raw_sha256"]),
        result=dict(native_payload_sha256=_sha(payload), native_payload_bytes=len(payload), raw_bytes=len(raw)),
        replacement=replacement)
    return payload, "Replay RawFile zlib buffer" if output_compressed else "Replay RawFile inline buffer", receipt


def plan_rawfile_edits(workspace, snapshot, rows):
    """Validate a native RawFile batch against its immutable draft revisions."""
    from workstation_fastfiles import _validate_pending_snapshot
    trace, manifest, assets = _workspace_inputs(snapshot, {row["index"] for row in rows})
    edits = []
    for planned in rows:
        index = planned["index"]
        _, pending, payload = _validate_pending_snapshot(snapshot.cache_path, index, planned["asset_id"], snapshot.body)
        native = dict(snapshot.native_rows[index], index=index)
        if (pending.get("revision") != planned["revision"] or pending.get("type_id") != 51 or
                native.get("type_id") != 51 or native.get("name") != planned["name"]):
            raise ValueError("RawFile draft/native row differs from its preflight identity")
        reason = workspace._staged_asset_staleness(pending, snapshot.body, index, native,
            snapshot.native_walk, snapshot.source_path, _snapshot=snapshot)
        if reason:
            raise ValueError(reason)
        layout, _ = read_rawfile(snapshot.body.data, native, assets[index], snapshot.body.source_sha256)
        mode = pending["native_source_identity"]["typed_layout"]["editor_mode"]
        raw = encode_rawfile(pending["content"], layout, mode)
        output_compressed = layout.compressed or (layout.payload_bytes == 0 and bool(raw))
        expected = zlib.compress(raw) if output_compressed else raw
        if payload.read_bytes() != expected:
            raise ValueError("RawFile compiled buffer differs from its draft source")
        edits.append((layout, raw, expected, pending))
    updated, relocation = _replace_batch(snapshot.body.data, edits, trace, manifest)
    return updated, relocation, edits


def _replace_batch(body, edits, trace, manifest):
    layouts, payloads = {}, {}
    for layout, raw, payload, _ in edits:
        layouts[layout.asset_index] = InlineChildLayout(layout.asset_name, layout.root_archive_offset,
            layout.payload_archive_offset, layout.payload_stream_offset, layout.payload_bytes,
            layout.source_payload_sha256, 8 if layout.compressed or (layout.payload_bytes == 0 and bool(raw)) else 12, "<i",
            allow_empty_insert=(layout.payload_bytes == 0 and layout.root_token == 0
                                and layout.name_inline and layout.payload_stream_offset >= 0))
        payloads[layout.asset_index] = payload
    effective = {index: payload for index, payload in payloads.items()
                 if payload or layouts[index].child_bytes}
    effective_layouts = {index: layouts[index] for index in effective}
    if effective:
        updated, proof = relocate_stream5_children(body, effective_layouts, effective, trace, manifest)
    else:
        updated, proof = body, dict(status="semantic-noop-empty-rawfile-batch",
            source_body_sha256=_sha(body), output_body_sha256=_sha(body), edits=[],
            packed_stream5_aliases_rebased=0, stream_reservation_sizes=None)
    changed = bytearray(updated)
    # The shared relocator patches native buffer lengths before splicing. RawFile
    # also stores the decompressed length; map its root through those same splices.
    for layout, raw, payload, _ in edits:
        # An empty buffer can end at the next root's original address;
        # inserting there shifts that root as well.
        root = layout.root_archive_offset + sum(len(payload) - other.payload_bytes
            for other, _, payload, _ in edits if other.payload_archive_offset <= layout.root_archive_offset)
        struct.pack_into("<i", changed, root + 12, len(raw))
        if layout.payload_bytes == 0 and payload:
            struct.pack_into("<Q", changed, root + 16, INLINE)
    return bytes(changed), proof


def build_rawfile_replacement(workspace, snapshot, zone_plan, output, timeout):
    from workstation_fastfiles import (ZoneBody, acts_tool_identity, pack_replay_uncompressed,
        unpack_replay_uncompressed, make_replay_header_only_patch, sha256_file,
        ordered_asset_identity_sha256, _assert_run_inputs_unchanged)
    from workstation_trace_index import build_read_span_index
    from roundtrip_replay_fastfile import verify_native
    rows = []
    for planned in zone_plan["edits"]:
        index = int(planned["asset_id"].rsplit(":", 1)[1])
        rows.append(dict(planned, index=index))
    updated, relocation, edits = plan_rawfile_edits(workspace, snapshot, rows)
    source, profile, walk = snapshot.source_path, snapshot.source_profile, snapshot.native_walk
    reservations = list(profile["final_header"]["block_sizes"])
    high_water = relocation.get("stream_reservation_sizes")
    if high_water is not None:
        reservations = [max(old, required) for old, required in zip(reservations, high_water, strict=True)]
    packed = pack_replay_uncompressed(updated, reservations, profile["final_header"]["xfile_version"],
                                     profile["header"]["transient_type"])
    if unpack_replay_uncompressed(packed) != updated:
        raise AssertionError("RawFile package framing changed the compiled body")
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    tool_before, replay_before = acts_tool_identity(workspace.acts_path), sha256_file(workspace.replay_executable)
    output.write_bytes(packed)
    sidecars = []
    try:
        for patch in profile.get("patches", []):
            path = output.with_suffix(patch["extension"])
            path.write_bytes(make_replay_header_only_patch(Path(patch["path"]).read_bytes(), packed))
            sidecars.append(dict(path=str(path), bytes=path.stat().st_size, sha256=sha256_file(path),
                                 replaces_stale_source_patch=str(patch["path"])))
        reader_root = output.with_suffix(output.suffix + ".native-reader")
        read = verify_native(output, updated, source, workspace.acts_path,
                             workspace.replay_executable, reader_root, timeout, trace=True)
        manifest = read["manifest"]
        if (manifest.get("loaded_assets") != walk.get("loaded_assets") or
                read.get("normalized_asset_identity_sha256", read.get("journal_asset_identity_sha256")) !=
                ordered_asset_identity_sha256(snapshot.native_rows)):
            raise ValueError("RawFile package changed native asset names, order or loaded count")
        manifest_path = Path(read["manifest_path"])
        trace_path = manifest_path.parent / manifest.get("stream_trace", "stream-trace.jsonl")
        output_spans = build_read_span_index(trace_path, manifest_path, len(updated))
        owners = {row["index"]: dict(row, name=snapshot.native_rows[row["index"]].get("name"),
            _all_physical_spans=output_spans["_all_physical_spans"]) for row in output_spans["assets"]}
        expected_raw = {layout.asset_index: raw for layout, raw, _, _ in edits}
        source_trace, source_manifest, source_owners = _workspace_inputs(snapshot)
        source_context, output_context = RawFileReadContext(snapshot.body.data), RawFileReadContext(updated)
        verified = []
        for index, native in enumerate(snapshot.native_rows):
            if native.get("type_id") != 51 or native.get("status") == "reference":
                continue
            if index not in source_owners or index not in owners:
                raise ValueError("RawFile semantic reread lost a source owner")
            _, before = read_rawfile(snapshot.body.data, dict(native, index=index), source_owners[index], snapshot.body.source_sha256,
                                     context=source_context)
            _, after = read_rawfile(updated, dict(native, index=index), owners[index], output_context.sha256,
                                    context=output_context)
            before_bytes = before["content"].encode("utf-8") if before["mode"] == "text" else base64.b64decode(before["content"])
            after_bytes = after["content"].encode("utf-8") if after["mode"] == "text" else base64.b64decode(after["content"])
            if after_bytes != expected_raw.get(index, before_bytes):
                raise ValueError("RawFile semantic reread differs from edited or retained source bytes")
            verified.append(dict(index=index, name=native["name"], sha256=_sha(after_bytes), edited=index in expected_raw))
        _assert_run_inputs_unchanged(source, profile, workspace.acts_path, tool_before,
                                     workspace.replay_executable, replay_before)
        if unpack_replay_uncompressed(output.read_bytes()) != updated:
            raise ValueError("RawFile output changed during native reread")
        for _, _, _, pending in edits:
            index = pending["xasset_index"]
            latest = json.loads((snapshot.cache_path / "pending-edits" / str(index) / "current.json").read_text(encoding="utf-8"))
            if latest != pending:
                raise ValueError("RawFile draft revision changed during packaging")
        proof = dict(schema="replay120-native-rawfile-package-v1", status="native-full-zone-rawfile-package-pass",
            zone_id=snapshot.zone_id, output_fastfile=dict(path=str(output), sha256=sha256_file(output), bytes=output.stat().st_size),
            sidecars=sidecars, native_reader=read, relocation=relocation,
            semantic_readback=dict(status="all-rawfiles-semantic-reread-pass", items=verified))
        proof_path = output.with_suffix(output.suffix + ".edit-receipt.json")
        proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
        return dict(schema=proof["schema"], status=proof["status"], zone_id=snapshot.zone_id,
            output_fastfile=str(output), output_fastfile_sha256=proof["output_fastfile"]["sha256"],
            sidecars=sidecars, receipt_path=str(proof_path), native_reader_status=manifest.get("status"),
            native_reader_loaded=manifest.get("loaded_assets"), semantic_readback=proof["semantic_readback"],
            edits=[dict(asset_id=pending["asset_id"], revision=pending["revision"]) for _, _, _, pending in edits])
    except Exception:
        output.unlink(missing_ok=True)
        for row in sidecars:
            Path(row["path"]).unlink(missing_ok=True)
        raise
