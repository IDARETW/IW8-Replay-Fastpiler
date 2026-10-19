"""Fail-closed validation for the supported MP Omnvar StringTable schema.

The schema is grounded in the reconstructed IW8 consumer's
BG_Omnvar_RegisterFromStringTable, BG_Omnvar_RegisterTypeFromStringTable, and
Omnvar_RegisterFlagsFromStringTable. This validator does not claim runtime
OmnvarDef support for edits.
"""
from __future__ import annotations

import math
import re
import struct
from collections.abc import Sequence


SUPPORTED_ASSET = "omnvars/mp/omnvars.csv"
COLUMN_NAMES = {
    0: "name",
    1: "flag 0x41",
    2: "flag 0x04",
    3: "scope",
    4: "type",
    5: "initial value",
    6: "minimum (type i)",
    7: "maximum (type i)",
    8: "flag 0x08",
    9: "opaque column 9 (not read by registration)",
    10: "flag 0x10",
    11: "flag 0x40",
    12: "flag 0x80",
    13: "opaque annotation column (not read by registration)",
}
_TYPE_WORDS = {
    # (native OmnvarType byte, native userType byte), from the exact packed
    # values assigned by BG_Omnvar_RegisterTypeFromStringTable.
    "a": (3, 7), "b": (0, 0), "d": (1, 9), "e": (2, 6),
    "f": (1, 1), "i": (2, 2), "n": (4, 8), "p": (2, 5),
    "s": (5, 4), "t": (4, 3),
}
_NOTIFY_USER_TYPE = 8  # Confirmed by Replay's named Omnvar_RegisterFlagsFromStringTable pseudocode.
_BOOL_COLUMNS = (1, 2, 8, 10, 11, 12)
_INT_RE = re.compile(r"[+-]?[0-9]+\Z")
_FLOAT_RE = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")


class OmnvarValidationError(ValueError):
    """Validation failure with a stable, readable table row and column."""


def _asset_key(value: str) -> str:
    return value.replace("\\", "/").strip("/").casefold()


def _validated_asset_path(value: str, *, native_include_member: bool) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise OmnvarValidationError("asset path must be a non-empty safe relative path")
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    if (normalized.startswith("/") or any(part in ("", ".", "..") for part in parts)):
        raise OmnvarValidationError("asset path must be a non-empty safe relative path")
    if native_include_member:
        if _asset_key(normalized) == SUPPORTED_ASSET:
            raise OmnvarValidationError("the MP Omnvar root is not an included-table identity")
    elif _asset_key(normalized) != SUPPORTED_ASSET:
        raise OmnvarValidationError(
            f"unsupported Omnvar schema path {value!r}; only {SUPPORTED_ASSET!r} is proven"
        )
    return normalized


def _fail(row_number: int, column: int | None, message: str) -> None:
    if column is None:
        raise OmnvarValidationError(f"row {row_number}: {message}")
    label = COLUMN_NAMES.get(column, f"column {column}")
    raise OmnvarValidationError(f"row {row_number}, column {column} ({label}): {message}")


def _integer(value: str, row_number: int, column: int, *, minimum: int, maximum: int) -> int:
    if not _INT_RE.fullmatch(value):
        _fail(row_number, column, "expected a signed decimal integer")
    number = int(value, 10)
    if not minimum <= number <= maximum:
        _fail(row_number, column, f"value must be between {minimum} and {maximum}")
    return number


def _native_name_hash(name: str) -> int:
    # Matches the unsigned 32-bit `j = byte + 33 * j` hash used while building
    # the native Omnvar name table. Native duplicate detection keys on this
    # hash, so different names with the same hash also collide there.
    result = 0
    for byte in name.encode("utf-8"):
        result = (byte + 33 * result) & 0xFFFFFFFF
    return result


def _finite_native_float(value: str, row_number: int, column: int) -> None:
    if not _FLOAT_RE.fullmatch(value):
        _fail(row_number, column, "expected a finite decimal float")
    try:
        native_value = struct.unpack("<f", struct.pack("<f", float(value)))[0]
    except (OverflowError, ValueError):
        _fail(row_number, column, "value is outside the native 32-bit float range")
    if not math.isfinite(native_value):
        _fail(row_number, column, "value is outside the native 32-bit float range")


def _definition_rows(rows: Sequence[Sequence[str]]) -> tuple[list[tuple[int, Sequence[str]]], list[Sequence[str]]]:
    definitions: list[tuple[int, Sequence[str]]] = []
    includes: list[Sequence[str]] = []
    saw_definition = False
    for row_number, row in enumerate(rows, start=1):
        if row and row[0] == "include":
            if saw_definition:
                _fail(row_number, 0, "include directives must precede Omnvar definition rows")
            includes.append(row)
            continue
        saw_definition = True
        definitions.append((row_number, row))
    return definitions, includes


def validate_omnvar_mp_rows(
    rows: Sequence[Sequence[str]],
    *,
    asset_path: str = SUPPORTED_ASSET,
    original_rows: Sequence[Sequence[str]] | None = None,
    client_limit: int | None = None,
    native_include_member: bool = False,
) -> dict[str, object]:
    """Validate one CSV document using the proven MP Omnvar row schema.

    `original_rows` is required for edits that must retain the source include
    directives. Existing rows may change, be appended, or be removed; include
    rows may not change. The two columns the native registration code never
    reads (9 and 13) stay opaque. For surviving same-name definitions, column
    9 is preserved; column 13 remains available for human comments. The
    `native_include_member` form is only for an asset already resolved and
    body/trace-bound as a member of this root's native include closure.
    """
    normalized_asset_path = _validated_asset_path(
        asset_path, native_include_member=native_include_member)
    if not rows:
        raise OmnvarValidationError("row 1: table must contain at least one include or definition row")

    definitions, includes = _definition_rows(rows)
    if not definitions:
        raise OmnvarValidationError("table must contain at least one Omnvar definition row")

    include_values: list[str] = []
    for row_number, row in enumerate(includes, start=1):
        if len(row) != 14:
            _fail(row_number, len(row), "MP Omnvar rows must have exactly 14 columns")
        if not row[1] or row[1].strip() != row[1]:
            _fail(row_number, 1, "include path must be non-empty and have no surrounding whitespace")
        if any(row[index] for index in range(2, 14)):
            _fail(row_number, 2, "include rows may only populate the include path")
        include_values.append(row[1])

    if original_rows is not None:
        _, original_includes = _definition_rows(original_rows)
        if [list(row) for row in includes] != [list(row) for row in original_includes]:
            _fail(1, 0, "include directives are read-only in the initial Omnvar editor scope")

    names: dict[int, tuple[str, int]] = {}
    original_by_name: dict[str, Sequence[str]] = {}
    if original_rows is not None:
        original_definitions, _ = _definition_rows(original_rows)
        original_by_name = {row[0]: row for _, row in original_definitions if row}

    types_seen: set[str] = set()
    scopes_seen: set[str] = set()
    for row_number, row in definitions:
        if len(row) != 14:
            _fail(row_number, len(row), "MP Omnvar rows must have exactly 14 columns")
        name = row[0]
        if not name or name.strip() != name:
            _fail(row_number, 0, "name must be non-empty and have no surrounding whitespace")
        if any(ord(char) < 0x20 for char in name):
            _fail(row_number, 0, "name must not contain control characters")
        try:
            name.encode("ascii")
        except UnicodeEncodeError:
            _fail(row_number, 0, "non-ASCII names are unsupported by this proven native hash path")
        key = _native_name_hash(name)
        previous = names.get(key)
        if previous is not None:
            prior_name, prior_row = previous
            _fail(row_number, 0, f"native Omnvar name hash collides with row {prior_row} ({prior_name!r})")
        names[key] = (name, row_number)

        scope = row[3]
        if scope not in ("c", "g"):
            _fail(row_number, 3, "unsupported scope; native MP registration accepts only 'c' or 'g'")
        kind = row[4]
        if kind not in _TYPE_WORDS:
            _fail(row_number, 4, "unsupported type code; native registration does not handle this code")
        scopes_seen.add(scope)
        types_seen.add(kind)

        for column in _BOOL_COLUMNS:
            if row[column] not in ("", "0", "1"):
                _fail(row_number, column, "expected empty, '0', or '1'")

        if not row[5] and kind not in ("e", "n"):
            _fail(row_number, 5, f"type {kind!r} requires an initial value")
        if row[5] and kind in ("a", "p", "t"):
            initial_integer = _integer(row[5], row_number, 5,
                                       minimum=-(1 << 31), maximum=(1 << 31) - 1)
            if kind == "p":
                if client_limit is not None:
                    if not isinstance(client_limit, int) or isinstance(client_limit, bool) or client_limit <= 0:
                        _fail(row_number, 5, "target game-mode client limit must be a positive integer")
                    if not -1 <= initial_integer < client_limit:
                        _fail(row_number, 5, f"type 'p' value must be -1 through {client_limit - 1}")
        elif row[5] and kind == "b":
            if row[5] not in ("0", "1"):
                _fail(row_number, 5, "boolean initial value must be '0' or '1'")
        elif row[5] and kind in ("d", "f"):
            _finite_native_float(row[5], row_number, 5)
        elif row[5] and kind == "i":
            initial = _integer(row[5], row_number, 5, minimum=-(1 << 31), maximum=(1 << 31) - 1)
            minimum = _integer(row[6], row_number, 6, minimum=-(1 << 31), maximum=(1 << 31) - 1)
            maximum = _integer(row[7], row_number, 7, minimum=-(1 << 31), maximum=(1 << 31) - 1)
            if minimum > maximum:
                _fail(row_number, 6, "minimum must not exceed maximum")
            if not minimum <= initial <= maximum:
                _fail(row_number, 5, "initial value must be inside the inclusive minimum/maximum range")
            if maximum - minimum > (1 << 31) - 1:
                _fail(row_number, 7, "integer range is wider than the native signed range")
        elif row[5] and kind == "s":
            if not row[5].strip():
                _fail(row_number, 5, "NCS string value must be non-empty")

        # These are the exact incompatibilities checked when the consumer
        # turns CSV columns into native Omnvar flags. The Replay target's
        # OMNVAR_USER_TYPE_NOTIFY value is pinned as 8, so this rule applies to
        # every validated row, including newly authored and type-changed rows.
        if row[8] == "1":
            native_type = _TYPE_WORDS[kind][0]
            user_type = _TYPE_WORDS[kind][1]
            if ((native_type - 1) & 0xFC) != 0 or native_type == 3:
                _fail(row_number, 8, "flag 0x08 is incompatible with this native type")
            if user_type == _NOTIFY_USER_TYPE:
                _fail(row_number, 8, "flag 0x08 is incompatible with notify userType")
        if row[10] == "1":
            if row[8] == "1":
                _fail(row_number, 10, "flag 0x10 cannot be combined with flag 0x08")
            if kind not in ("d", "f"):
                _fail(row_number, 10, "flag 0x10 requires a native float type")
        if row[11] == "1" and row[1] != "1":
            _fail(row_number, 11, "flag 0x40 requires column 1 to be '1'")
        if row[12] == "1":
            if scope != "c":
                _fail(row_number, 12, "flag 0x80 requires client scope ('c')")
            if row[2] == "1":
                _fail(row_number, 12, "flag 0x80 cannot be combined with flag 0x04")
        # The Replay table consumer converts column 2 into the archived flag;
        # that flag belongs only to client-scoped Omnvars in this MP schema.
        if row[2] == "1" and scope != "c":
            _fail(row_number, 2, "flag 0x04 requires client scope ('c')")

        # Column 9 is unconsumed by this native registration path. Preserve it
        # when editing an existing named row; new definitions must leave it
        # empty until its meaning is proven. Column 13 is a known comment field
        # in the current MP CSV and is also not consumed by the native path.
        old = original_by_name.get(name)
        if old is not None and len(old) == 14 and row[9] != old[9]:
            _fail(row_number, 9, "opaque native-unread column must be preserved on existing rows")
        if original_rows is not None and old is None and row[9]:
            _fail(row_number, 9, "opaque native-unread column must be empty on new rows")

    return {
        "asset_path": normalized_asset_path,
        "row_count": len(rows),
        "include_count": len(includes),
        "definition_count": len(definitions),
        "column_count": 14,
        "scope_codes": sorted(scopes_seen),
        "type_codes": sorted(types_seen),
        "include_paths": include_values,
        "opaque_columns": [9, 13],
        "runtime_omnvar_definition_support_claimed": False,
    }


def validate_omnvar_mp_edit(
    original_rows: Sequence[Sequence[str]],
    edited_rows: Sequence[Sequence[str]],
    *,
    asset_path: str = SUPPORTED_ASSET,
    included_definition_names: Sequence[str] | None = None,
    client_limit: int | None = None,
    native_include_member: bool = False,
) -> dict[str, object]:
    """Validate both sides of one add/edit/remove operation.

    When names are added/renamed, `included_definition_names` must contain
    every definition expanded from this table's include chain. This closes the
    native duplicate-hash check across recursively registered include assets.
    """
    validate_omnvar_mp_rows(original_rows, asset_path=asset_path,
                            original_rows=original_rows, client_limit=client_limit,
                            native_include_member=native_include_member)
    result = validate_omnvar_mp_rows(
        edited_rows, asset_path=asset_path, original_rows=original_rows,
        client_limit=client_limit, native_include_member=native_include_member,
    )
    old_defs, old_includes = _definition_rows(original_rows)
    new_defs, _ = _definition_rows(edited_rows)
    old_names = {row[0] for _, row in old_defs if row}
    new_names = {row[0] for _, row in new_defs if row}
    added_names = new_names - old_names
    for row_number, row in new_defs:
        if row[4] != "p":
            continue
        old = next((candidate for _, candidate in old_defs if candidate and candidate[0] == row[0]), None)
        changed = old is None or old[4] != "p" or old[5] != row[5]
        if changed and client_limit is None:
            _fail(row_number, 5, "type 'p' edits require the target game-mode client limit")
    if added_names and old_includes and included_definition_names is None:
        raise OmnvarValidationError(
            "include definition names are required when adding or renaming rows; "
            "the native loader registers included Omnvars before this table"
        )
    if included_definition_names is not None:
        hashes: dict[int, str] = {}
        for name in included_definition_names:
            if not name or not name.isascii():
                raise OmnvarValidationError("included definition names must be non-empty ASCII strings")
            native_hash = _native_name_hash(name)
            prior = hashes.get(native_hash)
            if prior is not None:
                raise OmnvarValidationError(
                    f"included native Omnvar name hash collides between {prior!r} and {name!r}"
                )
            hashes[native_hash] = name
        for row_number, row in new_defs:
            native_hash = _native_name_hash(row[0])
            prior = hashes.get(native_hash)
            if prior is not None:
                _fail(row_number, 0, f"native Omnvar name hash collides with included definition {prior!r}")
            hashes[native_hash] = row[0]

    # The editor currently has no proof of the complete mode/game-type/map
    # registration closure, the selected mode's definition cap, or the target
    # NCS dictionary/client-layout state. Keep row-shape validation broad, but
    # fail closed on edits whose safety depends on that missing context.
    old_by_name = {row[0]: (row_number, row) for row_number, row in old_defs if row}
    new_by_name = {row[0]: (row_number, row) for row_number, row in new_defs if row}
    for name in sorted(new_names - old_names):
        row_number, row = new_by_name[name]
        if row[4] == "s":
            _fail(row_number, 5, "adding an NCS default requires complete execution context and a pinned target NCS registry")
        _fail(row_number, 0, "adding an Omnvar changes aggregate definition/scope counts; complete execution context is unavailable")
    for name in sorted(old_names - new_names):
        row_number, old = old_by_name[name]
        if old[4] == "s":
            _fail(row_number, 0, "removing an NCS definition changes aggregate counts; complete execution context is unavailable")
        _fail(row_number, 0, "removing an Omnvar changes aggregate definition/scope counts; complete execution context is unavailable")

    for row_number, row in new_defs:
        old = old_by_name[row[0]][1]
        if row[3] != old[3]:
            _fail(row_number, 3, "changing scope changes aggregate client/game counts; complete execution context is unavailable")
        for column, label in ((2, "archive"), (10, "PMOVE"), (12, "client-spectate")):
            if row[column] != old[column]:
                _fail(row_number, column, f"changing the {label} flag changes aggregate runtime counters; complete execution context is unavailable")
        if row[4] == "s" or old[4] == "s":
            if row[4] != old[4]:
                _fail(row_number, 4, "changing to or from the NCS type requires complete execution context and a pinned target NCS registry")
            if row[5] != old[5]:
                _fail(row_number, 5, "changing an NCS default requires a pinned target NCS registry and complete execution context")

    result["operation"] = _operation(original_rows, edited_rows)
    result["runtime_execution_context_complete"] = False
    result["runtime_count_sensitive_edits"] = "rejected-without-context"
    return result


def _operation(original_rows: Sequence[Sequence[str]], edited_rows: Sequence[Sequence[str]]) -> str:
    old_defs, _ = _definition_rows(original_rows)
    new_defs, _ = _definition_rows(edited_rows)
    old_names = {row[0] for _, row in old_defs if row}
    new_names = {row[0] for _, row in new_defs if row}
    if old_names == new_names:
        return "edit-or-no-op"
    if old_names <= new_names:
        return "add"
    if new_names <= old_names:
        return "remove"
    return "mixed"
