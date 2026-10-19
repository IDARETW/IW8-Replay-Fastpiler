"""RVA translation and short-branch relaxation for the native code layout."""

from bisect import bisect_right
import struct

from coff import align


def encode_relative_table(item, target, origin):
    """Require the relocated target to survive the native table's decoding."""
    distance = origin-target if item["subtract"] else target-origin
    shift, width = item["shift"], item.get("width", 4)
    if width not in (1, 2, 4, 8) or not 0 <= shift < 64:
        raise ValueError("Unsupported relative table encoding")
    if distance % (1 << shift):
        raise ValueError("Shifted switch target is not representable by its table encoding")
    value = distance >> shift
    signed = item.get("signed", True)
    bits = width * 8
    minimum = -(1 << (bits-1)) if signed else 0
    maximum = (1 << (bits-1)) - 1 if signed else (1 << bits) - 1
    if not minimum <= value <= maximum:
        raise ValueError("Shifted switch table target is out of range")
    return (value & ((1 << bits)-1)).to_bytes(width, "little")


class Layout:
    def __init__(self, manifest, sizes, native_text):
        self.replacements = manifest["replacements"]
        self.sizes = sizes
        self.text_start = manifest["sections"][0]["rva"]
        self.data_start = manifest["sections"][1]["rva"]
        text = manifest["sections"][0]
        text_end = self.text_start + max(text["raw_size"], text["virtual_size"])
        previous_end = self.text_start
        names = set()
        for item in sorted(self.replacements, key=lambda row: row["begin"]):
            if not self.text_start <= item["begin"] < item["end"] <= text_end:
                raise ValueError("Replacement span is outside native executable text")
            if item["begin"] < previous_end:
                raise ValueError("Replacement spans overlap")
            if item["symbol"] in names:
                raise ValueError("Replacement symbol is duplicated")
            if not item.get("retired") and sizes.get(item["symbol"], 0) <= 0:
                raise ValueError("Replacement has no nonempty compiled function")
            names.add(item["symbol"])
            previous_end = item["end"]
        self.events = {}
        self.interior_rvas = {}
        self.interior_uses = {}
        self.widened = {}
        # Preserve every original alignment up to SectionAlignment, including
        # unnamed SIMD constants/tables that have no COFF alignment record.
        self.granularity = manifest["optional"].get("SectionAlignment", 16)
        for item in self.replacements:
            if item.get("retired"):
                continue
            excess = sizes[item["symbol"]] - (item["end"]-item["begin"])
            if excess > 0:
                self.events[item["end"]] = align(excess, self.granularity)
        while True:
            self.refresh(manifest)
            changed = False
            for site, target in manifest["short_references"]:
                if self.replaced(site) or site in self.widened:
                    continue
                offset = site-self.text_start
                prefix = bytearray()
                while native_text[offset+len(prefix)] in (0x66, 0x67, 0x2e, 0x3e, 0x40, 0xf2):
                    prefix.append(native_text[offset+len(prefix)])
                opcode = native_text[offset+len(prefix)]
                size = len(prefix)+2
                distance = self.resolve(target)-(self.map(site)+size)
                if -128 <= distance <= 127:
                    continue
                if opcode != 0xeb and not 0x70 <= opcode <= 0x7f and not 0xe0 <= opcode <= 0xe3:
                    raise ValueError(f"Unsupported short branch at {site:x}")
                # Reserving a multiple of 16 preserves alignment of downstream
                # functions, inline tables, and SSE data. Unused bytes are NOPs.
                self.events[site+size] = self.events.get(site+size, 0)+self.granularity
                self.widened[site] = dict(target=target, size=size, opcode=opcode, prefix=bytes(prefix))
                changed = True
            if not changed:
                break
        self.refresh(manifest)

    def refresh(self, manifest):
        self.points = sorted(self.events)
        self.deltas = [0]
        for point in self.points:
            self.deltas.append(self.deltas[-1]+self.events[point])
        old = manifest["sections"][0]
        end = old["rva"]+max(old["raw_size"], old["virtual_size"])
        self.section_delta = max(0, align(end+self.deltas[-1], manifest["optional"].get("SectionAlignment", 4096))-self.data_start)

    def map(self, rva):
        if rva >= self.data_start:
            return rva+self.section_delta
        return rva+self.deltas[bisect_right(self.points, rva)]

    def replaced(self, rva):
        return next((item for item in self.replacements if item["begin"] <= rva < item["end"]), None)

    def resolve(self, rva):
        item = self.replaced(rva)
        if item:
            if item.get("retired"):
                raise ValueError(f"Reference targets retired function code: {rva:x}")
            if rva == item["begin"]:
                return self.map(rva)
            if rva in self.interior_rvas:
                replacement = self.interior_rvas[rva]
                if replacement["symbol"] != item["symbol"]:
                    raise ValueError(f"Ambiguous replacement mapping for code RVA {rva:x}")
                self.interior_uses[rva] = replacement
                return replacement["mapped_rva"]
            raise ValueError(f"Reference into replaced function interior {rva:x} has no emitted instruction label")
        return self.map(rva)

    def add_interior_rvas(self, mappings):
        """Register compiler-emitted labels keyed by their original code RVA."""
        for old_rva, new_rva, owner in mappings:
            item = self.replaced(old_rva)
            if item is None or item.get("retired") or item["symbol"] != owner:
                raise ValueError(f"Instruction label {old_rva:x} has no live replacement owner")
            if not item["begin"] < old_rva < item["end"]:
                raise ValueError(f"Instruction label {old_rva:x} is outside replacement interior")
            new_begin = self.map(item["begin"])
            new_end = new_begin + self.sizes[item["symbol"]]
            if not new_begin <= new_rva < new_end:
                raise ValueError(f"Mapped replacement label for {old_rva:x} is outside bounded code")
            existing = self.interior_rvas.get(old_rva)
            value = {"symbol": owner, "mapped_rva": new_rva}
            if existing and existing != value:
                raise ValueError(f"Duplicate instruction-label mapping for {old_rva:x}")
            self.interior_rvas[old_rva] = value

    def copy_text(self, data):
        output = bytearray()
        start = self.text_start
        for point in self.points:
            output.extend(data[start-self.text_start:point-self.text_start])
            output.extend(b"\x90"*self.events[point])
            start = point
        output.extend(data[start-self.text_start:])
        return output

    def branches(self, text, manifest):
        for site, target in manifest["short_references"]:
            if self.replaced(site):
                continue
            at = self.map(site)-self.text_start
            wide = self.widened.get(site)
            if wide:
                prefix, opcode = wide["prefix"], wide["opcode"]
                if opcode == 0xeb:
                    code = prefix+b"\xe9"
                elif 0x70 <= opcode <= 0x7f:
                    code = prefix+bytes([0x0f, opcode+0x10])
                else:
                    # LOOP/JCXZ have no near encoding. This preserves their
                    # register/flag behavior and both successors.
                    code = prefix+bytes([opcode, 2, 0xeb, 5, 0xe9])
                displacement = self.resolve(target)-(self.map(site)+len(code)+4)
                if not -(1 << 31) <= displacement < 1 << 31:
                    raise ValueError("Relaxed branch exceeds REL32 range")
                code += struct.pack("<i", displacement)
                extent = wide["size"]+self.granularity
                text[at:at+extent] = code+b"\x90"*(extent-len(code))
            else:
                # The original encoding includes any redundant/address prefix.
                size = 2
                while text[at+size-2] in (0x66, 0x67, 0x2e, 0x3e, 0x40, 0xf2):
                    size += 1
                displacement = self.resolve(target)-(self.map(site)+size)
                struct.pack_into("<b", text, at+size-1, displacement)

    def report(self, manifest):
        points = sorted(set([0, self.data_start, manifest["optional"]["SizeOfImage"]]+self.points))
        ranges = [dict(begin=a, end=b, mapped_begin=self.map(a)) for a,b in zip(points, points[1:])]
        return dict(ranges=ranges, insertions=[dict(rva=p, size=self.events[p]) for p in self.points],
                    section_delta=self.section_delta,
                    interior_reference_resolutions=[dict(original_rva=rva, mapped_rva=row["mapped_rva"],
                                                         symbol=row["symbol"])
                                                    for rva, row in sorted(self.interior_uses.items())],
                    widened_branches=[dict(rva=p, target=w["target"], size=w["size"]) for p,w in sorted(self.widened.items())])

    def unwind_offsets(self, entries, read):
        owners_by_info = {}
        for begin,end,at in entries:
            owners_by_info.setdefault(at, []).append((begin,end))

        writes = {}
        for at, owners in owners_by_info.items():
            affected = [any(begin < point <= end for point in self.points)
                        for begin,end in owners]
            if not any(affected):
                continue
            header = read(at,4)
            if header[0] & 7 != 1:
                raise ValueError("Relaxation inside a version-2 unwind function requires source reconstruction")
            codes = read(at+4,header[2]*2)
            code_fields = []
            index = 0
            while index < header[2]:
                offset, encoded = codes[index*2:index*2+2]
                code_fields.append((at+4+index*2, offset))
                operation, info = encoded & 15, encoded >> 4
                index += 1+({1: 1 if info == 0 else 2,4:1,5:2,8:1,9:2}.get(operation,0))

            owner_adjustments = []
            for (begin,_end), owner_affected in zip(owners,affected):
                if owner_affected:
                    prolog = self.map(begin+header[1])-self.map(begin)
                    offsets = [(field,self.map(begin+offset)-self.map(begin))
                               for field,offset in code_fields]
                else:
                    # Shared UNWIND_INFO also describes unaffected functions.
                    # Include their original values so a write needed by one
                    # owner cannot silently invalidate another owner.
                    prolog = header[1]
                    offsets = [(field,offset) for field,offset in code_fields]
                owner_adjustments.append([(at+1,prolog),*offsets])

            expected = owner_adjustments[0]
            if any(adjustments != expected for adjustments in owner_adjustments[1:]):
                raise ValueError("Shared native unwind info needs separate source definitions after relaxation")
            for field,value in expected:
                if not 0 <= value <= 255:
                    raise ValueError("Relaxed prologue exceeds the x64 unwind offset limit")
                original = header[1] if field == at+1 else codes[field-(at+4)]
                if value != original:
                    writes[field] = value
        return writes


def from_report(rva, report):
    # Replaced functions keep their native entry point, but instructions
    # within them can move when the source is reassembled.  The linker records
    # only instruction labels that were emitted and validated; consult those
    # exact mappings before applying the coarse section insertion map.
    for item in report.get("rva_map", {}).get("interior_reference_resolutions", []):
        if item["original_rva"] == rva:
            return item["mapped_rva"]
    ranges = report.get("rva_map", {}).get("ranges", [])
    for item in ranges:
        if item["begin"] <= rva < item["end"]:
            return item["mapped_begin"]+rva-item["begin"]
    if ranges and rva == ranges[-1]["end"]:
        item = ranges[-1]
        return item["mapped_begin"]+rva-item["begin"]
    return rva
