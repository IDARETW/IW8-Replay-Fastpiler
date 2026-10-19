"""Production adapter for trace-proven variable shader or resident-image edits."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import struct

try:
    from workstation_shader_identity import build_inventory, validate_inventory_set
    from workstation_shader_growth import replace_inline_shaders_with_relocation
    from workstation_image_resize import resize_resident_images
    from workstation_native_asset_edits import read_resident_image
except ModuleNotFoundError:
    from tools.workstation_shader_identity import build_inventory, validate_inventory_set
    from tools.workstation_shader_growth import replace_inline_shaders_with_relocation
    from tools.workstation_image_resize import resize_resident_images
    from tools.workstation_native_asset_edits import read_resident_image


def apply_variable_native_edits(body: bytes, edits: list[dict], *, body_path: Path,
                                journal_path: Path, trace_path: Path,
                                manifest_path: Path, replay_executable: Path,
                                additional_identity_inventories: list[dict] | None = None) -> tuple[bytes, dict]:
    """Apply one variable-sized asset family and return normalized reservations.

    Image scratch growth and persistent stream-5 shader relocation have distinct
    address semantics. Combined edits are merged from their original trace
    coordinates so no phase consumes offsets already shifted by another.
    """
    if not edits:
        raise ValueError("variable native edit transaction is empty")
    kinds = {row.get("kind") for row in edits}
    if not kinds or not kinds <= {"shader", "image"}:
        raise ValueError("variable edit transaction contains an unsupported family")
    source_sha = hashlib.sha256(body).hexdigest()
    if body_path.read_bytes() != body:
        raise ValueError("variable edit body differs from its cached native-walk body")
    shader_edits = [row for row in edits if row["kind"] == "shader"]
    image_edits = [row for row in edits if row["kind"] == "image"]
    shader_output = body
    shader_writer = None
    inventory_receipt = None
    if shader_edits:
        replay_sha = hashlib.sha256(replay_executable.read_bytes()).hexdigest()
        compute_only = all(isinstance(row.get("asset_row"), dict)
                           and row["asset_row"].get("type_id") == 12 for row in shader_edits)
        if compute_only:
            # Type-12 root +36 semantics are opaque here. No graphics identity
            # inventory or discriminator allocation is performed.
            inventories = []
            inventory_receipt = {"policy": "compute-root-u32-36-preserved-opaque",
                                 "inventory_count": 0}
        else:
            fastfile_root = next((parent for parent in body_path.parents if parent.name == "fastfiles"), None)
            inventory_cache = fastfile_root / "_shader-identity-inventories" if fastfile_root else None
            cached = list(additional_identity_inventories or [])
            for candidate in list(cached):
                validate_inventory_set([candidate], replay_sha)
            if inventory_cache and inventory_cache.is_dir():
                for path in inventory_cache.glob("*.json"):
                    try:
                        candidate = json.loads(path.read_text(encoding="utf-8"))
                        validate_inventory_set([candidate], replay_sha)
                        cached.append(candidate)
                    except (OSError, ValueError, KeyError, TypeError):
                        continue
            inventory = next((row for row in cached if row.get("body_sha256") == source_sha), None)
            if inventory is None:
                inventory = build_inventory(body_path, journal_path, trace_path,
                                            manifest_path, replay_executable)
            inventories = [inventory]
            # Reuse every complete hash-valid cached inventory available beneath
            # the same fastfile cache. This prevents a new discriminator from
            # colliding with another currently provisioned zone on the same EXE.
            if inventory_cache:
                inventory_cache.mkdir(exist_ok=True)
                source_inventory_path = inventory_cache / f"{inventory['inventory_sha256']}.json"
                if not source_inventory_path.exists():
                    source_inventory_path.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
                for candidate in cached:
                    if candidate["inventory_sha256"] not in {row["inventory_sha256"] for row in inventories}:
                        inventories.append(candidate)
        shader_output, shader_writer = replace_inline_shaders_with_relocation(
            body, [{"asset_row": row["asset_row"], "trace_asset": row["trace_asset"],
                    "trace_assets": row.get("trace_assets"),
                    "payload": row["payload"]} for row in shader_edits], source_sha,
            trace_path, manifest_path, identity_inventories=inventories,
            replay_executable_sha256=replay_sha)
        relocation = shader_writer["relocation"]
        reservations = list(relocation["stream_reservation_sizes"])
        if not compute_only:
            inventory_receipt = {"inventories":[{key: item[key] for key in
                             ("inventory_sha256", "shader_count", "journal_sha256",
                              "trace_sha256", "manifest_sha256")} for item in inventories],
                             "inventory_count":len(inventories)}
    if image_edits:
        image_output, image_writer = resize_resident_images(
            body, [{"asset_row": row["asset_row"], "trace_asset": row["trace_asset"],
                    "width": row["width"], "height": row["height"],
                    "mip_count": row["mip_count"], "payload": row["payload"]}
                   for row in image_edits], source_sha, trace_path, manifest_path)
        if not shader_edits:
            updated, writer = image_output, image_writer
            reservations = list(image_writer["stream_reservation_sizes"])
        else:
            # Both writers inspect the original trace exactly once. Merge the
            # independent physical splices against original archive offsets;
            # image pixels are scratch-only and therefore add no packed alias
            # relocation beyond the shader writer's stream-5 graph.
            shader_splices = sorted((row["child_archive_offset"], row["physical_extent_delta"])
                                    for row in relocation["edits"])
            def mapped(at):
                return at + sum(delta for child, delta in shader_splices if child < at)
            merged = bytearray(shader_output)
            image_layouts = []
            shader_ranges = [(row["child_archive_offset"],
                              row["child_archive_offset"] + row["old_child_bytes"])
                             for row in relocation["edits"]]
            for row in image_edits:
                current = read_resident_image(body, row["asset_row"], row["trace_asset"], source_sha)
                root, payload_at = current["root_archive_offset"], current["payload_archive_offset"]
                image_ranges = ((root, root + len(current["root_bytes"])),
                                (payload_at, payload_at + current["total_size"]))
                if any(a < d and c < b for a,b in image_ranges for c,d in shader_ranges):
                    raise ValueError("combined shader/image original physical spans overlap")
                mapped_root = mapped(root)
                struct.pack_into("<I", merged, mapped_root + 0x1c, len(row["payload"]))
                struct.pack_into("<HH", merged, mapped_root + 0x24,
                                 row["width"], row["height"])
                merged[mapped_root + 0x30] = row["mip_count"]
                image_layouts.append((mapped(payload_at), current["total_size"], row["payload"]))
            for at, old_size, payload in sorted(image_layouts, reverse=True):
                merged[at:at+old_size] = payload
            updated = bytes(merged)
            reservations[1] = max(reservations[1], image_writer["stream_reservation_sizes"][1])
            writer = {"schema":"replay120-combined-shader-image-writer-v1",
                      "shader":shader_writer,"image":image_writer,
                      "original_trace_offsets_applied_once":True,
                      "stream_reservation_sizes":reservations,
                      "publication_ready":False}
    else:
        updated, writer = shader_output, shader_writer
    return updated, {"schema":"replay120-variable-native-edit-transaction-v1",
        "family":"combined" if len(kinds)>1 else next(iter(kinds)), "source_body_sha256":source_sha,
        "output_body_sha256":hashlib.sha256(updated).hexdigest(),
        "edit_count":len(edits), "stream_reservation_sizes":reservations,
        "shader_identity_inventory":inventory_receipt, "writer":writer,
        "publication_ready":False,
        "remaining_gate":"complete packaged full-zone native reread; live renderer remains untested"}
