"""Fail-closed same-extent editors for trace-owned Replay 1.20 shader/image data.

These helpers consume the normalized rows produced by
``workstation_trace_index.build_read_span_index``. They do not infer a child
from nearby serialized bytes: every editable child must match a physical read
owned by the selected XAsset. Inline DXBC stage shaders use a typed 40-byte
root; hull/domain roots also require their exact packed debug-name resolve and
global indexed string span. Shared null hull/domain aliases are read-only.
"""
from __future__ import annotations

import hashlib
import struct


INLINE = 0xFFFFFFFFFFFFFFFE
INLINE_ALT = 0xFFFFFFFFFFFFFFFF
SHADER_TYPES = {12: "computeshader", 14: "vertexshader", 15: "hullshader",
                16: "domainshader", 17: "pixelshader"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _assert_owner(body: bytes, asset_row: dict, trace_asset: dict,
                  expected_body_sha256: str, expected_type: int) -> int:
    if _sha(body) != expected_body_sha256:
        raise ValueError("decoded XFile body changed after native trace preflight")
    index = asset_row.get("index", asset_row.get("xasset_index"))
    if not isinstance(index, int) or trace_asset.get("index") != index:
        raise ValueError("trace owner index differs from the selected XAsset row")
    if asset_row.get("type_id") != expected_type or trace_asset.get("type_id") != expected_type:
        raise ValueError("selected XAsset has the wrong native type")
    return index


def _root(body: bytes, trace_asset: dict, root_size: int) -> tuple[int, bytes, list[dict]]:
    spans = trace_asset.get("read_spans")
    if not isinstance(spans, list):
        raise ValueError("native trace row has no physical read spans")
    roots = [span for span in spans if span.get("origin") == "load_stream_call"
             and span.get("reader_start_arg") == 0 and span.get("size") == root_size]
    if len(roots) != 1:
        raise ValueError(f"trace must identify exactly one {root_size}-byte type root")
    span = roots[0]
    offset = span.get("archive_offset")
    if not isinstance(offset, int) or offset < 0 or offset + root_size > len(body):
        raise ValueError("traced root falls outside the decoded XFile body")
    return offset, body[offset:offset + root_size], spans


def _children(body: bytes, spans: list[dict]) -> list[tuple[dict, bytes]]:
    output = []
    for span in spans:
        if span.get("origin") not in ("load_stream_call", "string_data"):
            continue
        size, offset = span.get("size"), span.get("archive_offset")
        if not isinstance(size, int) or not isinstance(offset, int) or size <= 0:
            continue
        if offset < 0 or offset + size > len(body):
            raise ValueError("traced child falls outside the decoded XFile body")
        output.append((span, body[offset:offset + size]))
    return output


def _packed_event_and_span(body: bytes, trace_asset: dict, *, index: int,
                           type_id: int, offset: int, token: int) -> tuple[dict, dict]:
    events = trace_asset.get("packed_pointer_events")
    if not isinstance(events, list):
        raise ValueError("shader root pointer has no indexed native resolve events")
    root_location = trace_asset.get("root_stream_location")
    if (not isinstance(root_location, dict) or root_location.get("stream") != 1
            or type(root_location.get("offset")) is not int):
        raise ValueError("shader packed-name owner has no exact stream-1 root location")
    expected_field = {"stream": 1, "offset": root_location["offset"] + offset}
    matches = [event for event in events
               if event.get("kind") == "packed_resolve"
               and event.get("xasset_index") == index
               and event.get("type_id") == type_id
               and event.get("raw_token") == token
               and event.get("field_stream_location") == expected_field]
    if len(matches) != 1:
        raise ValueError("shader root pointer lacks one exact owner-local packed-resolve event")
    event = matches[0]
    target = event.get("resolved_target_stream_location")
    if type_id == 12:
        # Replay compute roots use a fixed 0x15 token. Its meaning is proven
        # by this owner's callback and indexed string span, not the token's
        # low word (which is not a stream-5 coordinate).
        valid_target = (token == 0x0000001500000001 and
                        isinstance(target, dict) and target.get("stream") == 5 and
                        type(target.get("offset")) is int and target["offset"] >= 0)
    else:
        valid_target = (type(token) is int and token >> 32 == 5 and
                        (token & 0xFFFFFFFF) != 0 and
                        isinstance(target, dict) and target.get("stream") == 5 and
                        target.get("offset") == (token & 0xFFFFFFFF) - 1)
    if not valid_target:
        raise ValueError("shader packed source-name pointer does not resolve into stream 5")
    indexed_spans = trace_asset.get("indexed_string_data_spans")
    if not isinstance(indexed_spans, list):
        indexed_spans = trace_asset.get("read_spans", [])
    spans = [span for span in indexed_spans
             if span.get("origin") == "string_data"
             and span.get("destination_stream_location") == target]
    if len(spans) != 1:
        raise ValueError("shader packed source-name pointer lacks one exact indexed string span")
    span = spans[0]
    event_sequence = event.get("sequence")
    span_sequence = span.get("event_sequence")
    begin_sequence, end_sequence = (trace_asset.get("begin_sequence"),
                                    trace_asset.get("end_sequence"))
    if (any(type(value) is not int for value in
            (event_sequence, span_sequence, begin_sequence, end_sequence)) or
            not span_sequence < event_sequence or
            not begin_sequence < event_sequence < end_sequence):
        raise ValueError("shader packed source-name span was not live before its owner callback")
    stream_offset = target.get("offset")
    span_size = span.get("size")
    if type(stream_offset) is not int or type(span_size) is not int or span_size <= 0:
        raise ValueError("shader packed source-name span has invalid stream bounds")
    physical_spans = trace_asset.get("indexed_physical_spans")
    if not isinstance(physical_spans, list):
        raise ValueError("shader packed name requires complete physical allocation context")
    for other in physical_spans:
        if other is span or not isinstance(other, dict):
            continue
        other_location = other.get("destination_stream_location")
        if (not isinstance(other_location, dict) or
                other_location.get("stream") != target.get("stream")):
            continue
        other_offset, other_size = other_location.get("offset"), other.get("size")
        if type(other_offset) is not int or type(other_size) is not int or other_size <= 0:
            continue
        other_sequence = other.get("event_sequence")
        if (other_sequence == span_sequence and other.get("archive_offset") == span.get("archive_offset")
                and other_offset == stream_offset and other_size == span_size):
            continue
        if other_offset < stream_offset + span_size and stream_offset < other_offset + other_size:
            if type(other_sequence) is not int:
                raise ValueError("shader packed name allocation has no ordered physical event")
            raise ValueError("shader packed source-name span overlaps another physical allocation")
    start, size = span.get("archive_offset"), span.get("size")
    if (type(start) is not int or type(size) is not int or size < 2
            or start < 0 or start + size > len(body)):
        raise ValueError("shader packed source-name span falls outside the decoded body")
    raw = body[start:start + size]
    if raw[-1:] != b"\0" or b"\0" in raw[:-1]:
        raise ValueError("shader packed source-name span is not one terminated string")
    try:
        value = raw[:-1].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("shader packed source-name span is not UTF-8") from error
    is_compute_asset_name = (type_id == 12 and
                             (value.lower().endswith(".hlsl") or
                              (".hlsl/" in value.lower() and
                               value.lower().split(".hlsl/", 1)[1])))
    if not value or (not is_compute_asset_name and not value.lower().endswith(".hlsl")):
        raise ValueError("shader packed source-name is not an HLSL source or compute-entry name")
    return event, span


def read_inline_shader(body: bytes, asset_row: dict, trace_asset: dict,
                       expected_body_sha256: str,
                       trace_assets: list[dict] | None = None) -> dict:
    """Read a trace-owned inline DXBC root; compute reads require full ownership context."""
    index = _assert_owner(body, asset_row, trace_asset, expected_body_sha256,
                          asset_row.get("type_id"))
    type_id = asset_row["type_id"]
    if type_id not in SHADER_TYPES:
        raise ValueError("only Replay type-12/14/15/16/17 shader stage assets are supported")
    if type_id == 12 and not isinstance(trace_assets, list):
        raise ValueError("compute shader ownership requires the complete native trace index")
    name = asset_row.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("shader XAsset row has no stable native name")
    root_offset, root_bytes, spans = _root(body, trace_asset, 40)
    children = _children(body, spans)
    named = [(s, b) for s, b in children if b == name.encode("utf-8") + b"\0"]
    programs = [(s, b) for s, b in children if b.startswith(b"DXBC")]
    name_token = struct.unpack_from("<Q", root_bytes, 0)[0]
    if name_token not in (INLINE, INLINE_ALT) or len(named) != 1 or len(programs) != 1:
        raise ValueError("shader must have one traced inline XString and one DXBC child")
    debug_name = None
    debug_name_stream_location = None
    program_identity = struct.unpack_from("<I", root_bytes, 36)[0]
    if type_id in (12, 15, 16):
        debug_token = struct.unpack_from("<Q", root_bytes, 8)[0]
        if (struct.unpack_from("<Q", root_bytes, 16)[0] != 0
                or struct.unpack_from("<Q", root_bytes, 24)[0] not in (INLINE, INLINE_ALT)):
            raise ValueError("type-12/15/16 shader root differs from the observed 40-byte layout")
        event, debug_span = _packed_event_and_span(
            body, trace_asset, index=index, type_id=type_id, offset=8, token=debug_token)
        inline_name_sequence = named[0][0].get("event_sequence")
        if (type(inline_name_sequence) is not int or
                not trace_asset.get("begin_sequence", -1) < inline_name_sequence < event["sequence"] <
                trace_asset.get("end_sequence", -1)):
            raise ValueError("shader inline XString was not read before its owner packed callback")
        start, size = debug_span["archive_offset"], debug_span["size"]
        debug_name = body[start:start + size - 1].decode("utf-8")
        debug_name_stream_location = event["resolved_target_stream_location"]
        if type_id == 12 and debug_name != name:
            raise ValueError("type-12 packed debug name differs from the selected compute-shader name")
    from workstation_asset_codecs import dxbc_native_shader_type
    program_span, program = programs[0]
    if type_id == 12:
        program_location = program_span.get("destination_stream_location")
        if not isinstance(program_location, dict):
            raise ValueError("compute DXBC child has no exact destination stream location")
        owners = []
        for candidate in trace_assets:
            if not isinstance(candidate, dict) or not isinstance(candidate.get("read_spans"), list):
                raise ValueError("compute ownership index contains a malformed trace row")
            for candidate_span in candidate["read_spans"]:
                if (candidate_span.get("origin") == "load_stream_call" and
                        candidate_span.get("destination_stream_location") == program_location and
                        candidate_span.get("size") == len(program)):
                    candidate_start = candidate_span.get("archive_offset")
                    if (type(candidate_start) is int and 0 <= candidate_start <= len(body) - len(program)
                            and body[candidate_start:candidate_start + 4] == b"DXBC"):
                        owners.append(candidate.get("index"))
        if owners != [index]:
            raise ValueError("compute DXBC child is shared or lacks unique whole-zone physical ownership")
    declared_size = struct.unpack_from("<I", root_bytes, 32)[0]
    if declared_size != len(program):
        raise ValueError("shader root bytecode size disagrees with traced DXBC child")
    if len(program) < 32 or struct.unpack_from("<I", program, 24)[0] != len(program):
        raise ValueError("traced shader child is not a complete DXBC container")
    if dxbc_native_shader_type(program) != type_id:
        raise ValueError("DXBC shader stage does not match the native XAsset type")
    return dict(asset_index=index, type_id=type_id, name=name,
                root_archive_offset=root_offset, root_bytes=root_bytes,
                name_archive_offset=named[0][0]["archive_offset"],
                debug_name=debug_name,
                debug_name_stream_location=debug_name_stream_location,
                program_identity=program_identity,
                program_archive_offset=program_span["archive_offset"],
                program=program, program_sha256=_sha(program),
                trace_begin_cursor=trace_asset.get("begin_cursor"),
                trace_end_cursor=trace_asset.get("end_cursor"))


def replace_inline_shader(body: bytes, asset_row: dict, trace_asset: dict,
                          expected_body_sha256: str, replacement_program: bytes,
                          trace_assets: list[dict] | None = None) -> tuple[bytes, dict]:
    """Replace a traced shader program without changing any serialized extent."""
    current = read_inline_shader(body, asset_row, trace_asset, expected_body_sha256,
                                 trace_assets=trace_assets)
    if not isinstance(replacement_program, bytes) or len(replacement_program) != len(current["program"]):
        raise ValueError("shader replacement must retain the original bytecode extent")
    if replacement_program[:4] != b"DXBC" or len(replacement_program) < 32:
        raise ValueError("shader replacement is not a complete DXBC container")
    if struct.unpack_from("<I", replacement_program, 24)[0] != len(replacement_program):
        raise ValueError("replacement DXBC declared length differs from its byte length")
    from workstation_asset_codecs import dxbc_native_shader_type
    if dxbc_native_shader_type(replacement_program) != current["type_id"]:
        raise ValueError("replacement DXBC shader stage differs from the native XAsset type")
    start = current["program_archive_offset"]
    result = bytearray(body)
    result[start:start + len(replacement_program)] = replacement_program
    updated = bytes(result)
    return updated, dict(asset_index=current["asset_index"], type_id=current["type_id"],
                         name=current["name"], archive_offset=start,
                         debug_name=current["debug_name"],
                         original_program_sha256=current["program_sha256"],
                         replacement_program_sha256=_sha(replacement_program),
                         original_size=len(current["program"]),
                         replacement_size=len(replacement_program), same_extent=True,
                         xasset_table_unchanged=True)


def read_null_shader_alias(body: bytes, asset_row: dict, trace_asset: dict,
                           expected_body_sha256: str) -> dict:
    """Recognize shared null hull/domain aliases without making them editable."""
    index = _assert_owner(body, asset_row, trace_asset, expected_body_sha256,
                          asset_row.get("type_id"))
    type_id = asset_row["type_id"]
    if type_id not in (15, 16):
        raise ValueError("only hull/domain shared null shader aliases are recognized")
    root_offset, root_bytes, spans = _root(body, trace_asset, 40)
    first, second = struct.unpack_from("<QQ", root_bytes, 0)
    if (first != second or first >> 32 != 5 or (first & 0xFFFFFFFF) == 0
            or struct.unpack_from("<Q", root_bytes, 16)[0] != 0
            or struct.unpack_from("<Q", root_bytes, 24)[0] not in (INLINE, INLINE_ALT)):
        raise ValueError("shader root is not the observed shared packed null alias form")
    event0, span0 = _packed_event_and_span(body, trace_asset, index=index,
                                           type_id=type_id, offset=0, token=first)
    event8, span8 = _packed_event_and_span(body, trace_asset, index=index,
                                           type_id=type_id, offset=8, token=second)
    if (event0.get("sequence") == event8.get("sequence") or
            span0.get("destination_stream_location") != span8.get("destination_stream_location")):
        raise ValueError("shared null alias fields do not resolve through distinct native callbacks to one string")
    start, size = span0["archive_offset"], span0["size"]
    shared_name = body[start:start + size - 1].decode("utf-8")
    if shared_name != "null_vshsds.hlsl":
        raise ValueError("packed alias does not identify the observed shared null hull/domain source")
    if asset_row.get("name") != shared_name:
        raise ValueError("null alias journal identity differs from its resolved shared name")
    programs = [(span, data) for span, data in _children(body, spans)
                if data.startswith(b"DXBC")]
    declared_size = struct.unpack_from("<I", root_bytes, 32)[0]
    if len(programs) != 1 or len(programs[0][1]) != declared_size:
        raise ValueError("shared null alias lacks one exact root-sized DXBC child")
    from workstation_asset_codecs import dxbc_native_shader_type
    if dxbc_native_shader_type(programs[0][1]) != type_id:
        raise ValueError("shared null shader DXBC stage does not match its native XAsset type")
    return dict(asset_index=index, type_id=type_id, name=shared_name,
                root_archive_offset=root_offset, root_bytes=root_bytes,
                debug_name=shared_name,
                program_archive_offset=programs[0][0]["archive_offset"],
                program=programs[0][1], program_sha256=_sha(programs[0][1]),
                editable=False,
                status="read-only-shared-null-shader",
                reason="null hull/domain aliases share packed name storage and have no separately owned editable DXBC")


def read_native_shader(body: bytes, asset_row: dict, trace_asset: dict,
                       expected_body_sha256: str,
                       trace_assets: list[dict] | None = None) -> dict:
    """Decode an editable stage shader, or identify the proven null alias as read-only."""
    type_id = asset_row.get("type_id")
    if type_id in (15, 16):
        root_offset, root_bytes, _ = _root(body, trace_asset, 40)
        del root_offset
        first = struct.unpack_from("<Q", root_bytes, 0)[0]
        if first not in (INLINE, INLINE_ALT):
            return read_null_shader_alias(body, asset_row, trace_asset, expected_body_sha256)
    return read_inline_shader(body, asset_row, trace_asset, expected_body_sha256,
                              trace_assets=trace_assets)


def read_resident_image(body: bytes, asset_row: dict, trace_asset: dict,
                        expected_body_sha256: str) -> dict:
    """Read a bounded type-19 image only when its pixels are inline and unstreamed."""
    index = _assert_owner(body, asset_row, trace_asset, expected_body_sha256, 19)
    name = asset_row.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("image XAsset row has no stable native name")
    root_offset, root_bytes, spans = _root(body, trace_asset, 232)
    name_token = struct.unpack_from("<Q", root_bytes, 0)[0]
    total_size = struct.unpack_from("<I", root_bytes, 0x1C)[0]
    width, height, depth, elements = struct.unpack_from("<4H", root_bytes, 0x24)
    streamed_parts = root_bytes[0x32]
    pixels_token = struct.unpack_from("<Q", root_bytes, 0xE0)[0]
    stream_records = root_bytes[0x38:0xD8]
    if name_token not in (INLINE, INLINE_ALT) or pixels_token != INLINE:
        raise ValueError("image name/pixels pointer is not a proven inline -1/-2 name and -2 pixel form")
    if streamed_parts != 0 or any(stream_records):
        raise ValueError("streamed/XPak image payloads are not supported by this writer")
    children = _children(body, spans)
    named = [(s, b) for s, b in children if b == name.encode("utf-8") + b"\0"]
    payloads = [(s, b) for s, b in children
                if s.get("origin") == "load_stream_call"
                and s.get("reader_start_arg") == 0 and len(b) == total_size]
    if len(named) != 1 or len(payloads) != 1:
        raise ValueError("image needs one traced name and one unique resident pixel child")
    payload_span, payload = payloads[0]
    return dict(asset_index=index, type_id=19, name=name,
                root_archive_offset=root_offset, root_bytes=root_bytes,
                name_archive_offset=named[0][0]["archive_offset"],
                payload_archive_offset=payload_span["archive_offset"],
                payload=payload, payload_sha256=_sha(payload),
                format=struct.unpack_from("<I", root_bytes, 0x14)[0],
                flags=struct.unpack_from("<I", root_bytes, 0x18)[0],
                dimensions=(width, height, depth, elements),
                level_count=root_bytes[0x30], total_size=total_size,
                trace_begin_cursor=trace_asset.get("begin_cursor"),
                trace_end_cursor=trace_asset.get("end_cursor"))


def replace_resident_image(body: bytes, asset_row: dict, trace_asset: dict,
                           expected_body_sha256: str, replacement_pixels: bytes) -> tuple[bytes, dict]:
    """Replace an inline resident pixel child while retaining its exact size/root."""
    current = read_resident_image(body, asset_row, trace_asset, expected_body_sha256)
    if not isinstance(replacement_pixels, bytes) or len(replacement_pixels) != len(current["payload"]):
        raise ValueError("resident image replacement must retain the traced pixel extent")
    start = current["payload_archive_offset"]
    result = bytearray(body)
    result[start:start + len(replacement_pixels)] = replacement_pixels
    updated = bytes(result)
    return updated, dict(asset_index=current["asset_index"], type_id=19,
                         name=current["name"], archive_offset=start,
                         format=current["format"], dimensions=list(current["dimensions"]),
                         original_payload_sha256=current["payload_sha256"],
                         replacement_payload_sha256=_sha(replacement_pixels),
                         original_size=len(current["payload"]),
                         replacement_size=len(replacement_pixels), same_extent=True,
                         xasset_table_unchanged=True)
