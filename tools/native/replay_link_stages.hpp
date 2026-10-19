// Internal implementation of the versioned link-stage ABI. Included once by
// replay_linker.cpp; no host files, original executable or third-party parser.
namespace {
using u16 = std::uint16_t;
using Bytes = std::vector<u8>;

u64 aligned(u64 value, u64 alignment) {
    if (!alignment || (alignment & (alignment - 1)) || value > std::numeric_limits<u64>::max() - (alignment - 1))
        throw std::runtime_error("Invalid linker alignment or extent overflow");
    return (value + alignment - 1) & ~(alignment - 1);
}
u32 rva32(i64 value) {
    if (value < 0 || static_cast<u64>(value) > std::numeric_limits<u32>::max())
        throw std::runtime_error("Linked extent exceeds PE RVA domain");
    return static_cast<u32>(value);
}
u32 count(Reader& reader, u64 minimum) {
    auto n = reader.take<u32>();
    if (minimum && n > (reader.size - reader.at) / minimum)
        throw std::runtime_error("Truncated native linker record array");
    return n;
}
Bytes blob(Reader& reader) {
    auto n = reader.take<u64>();
    if (n > reader.size - reader.at) throw std::runtime_error("Truncated native linker byte extent");
    Bytes result(reader.data + reader.at, reader.data + reader.at + n);
    reader.at += n;
    return result;
}
std::string string(Reader& reader) {
    auto data = blob(reader);
    return {data.begin(), data.end()};
}
struct Writer {
    Bytes data;
    template<class T> void put(T value) {
        const auto* begin = reinterpret_cast<const u8*>(&value);
        data.insert(data.end(), begin, begin + sizeof(T));
    }
    void bytes(const Bytes& value) {
        put<u64>(value.size()); data.insert(data.end(), value.begin(), value.end());
    }
    void text(const std::string& value) { bytes(Bytes(value.begin(), value.end())); }
};
void finish(Reader& reader) {
    if (reader.at != reader.size) throw std::runtime_error("Trailing native linker stage data");
}
template<class T> void patch(Bytes& bytes, u64 at, T value) {
    if (at > bytes.size() || sizeof(T) > bytes.size() - at)
        throw std::runtime_error("Native linker write is outside section");
    std::memcpy(bytes.data() + at, &value, sizeof(T));
}
struct Replacement { i64 begin, end; u64 size; bool retired; std::string symbol; };
std::vector<Replacement> replacements(Reader& reader) {
    std::vector<Replacement> result;
    auto n = count(reader, 36);
    for (u32 i = 0; i < n; ++i) {
        Replacement row;
        row.begin = reader.take<i64>(); row.end = reader.take<i64>();
        row.size = reader.take<u64>(); row.retired = reader.take<u32>() != 0;
        if (row.size > std::numeric_limits<u32>::max()) throw std::runtime_error("Compiled replacement exceeds PE extent domain");
        row.symbol = string(reader); result.push_back(std::move(row));
    }
    return result;
}
struct Branch { i64 site, target; u32 size, opcode; Bytes prefix; };
Bytes prefix_at(const Bytes& text, u64 offset) {
    Bytes prefix;
    for (;;) {
        if (offset >= text.size()) throw std::runtime_error("Short branch escapes native text");
        u8 byte = text[offset++];
        if (byte != 0x66 && byte != 0x67 && byte != 0x2e && byte != 0x3e && byte != 0x40 && byte != 0xf2) break;
        prefix.push_back(byte);
        if (prefix.size() > 13) throw std::runtime_error("Invalid x64 short branch prefix extent");
    }
    if (offset >= text.size()) throw std::runtime_error("Truncated short branch displacement");
    return prefix;
}
void layout_stage(Reader& reader, Writer& writer) {
    auto text_start = reader.take<i64>(), data_start = reader.take<i64>();
    auto text_size = reader.take<u64>(), granularity = reader.take<u64>();
    aligned(0, granularity);
    if (text_start < 0 || data_start <= text_start || text_size > std::numeric_limits<u32>::max() || granularity > std::numeric_limits<u32>::max())
        throw std::runtime_error("Invalid PE native layout domain");
    auto rows = replacements(reader);
    auto short_count = count(reader, 16);
    std::vector<std::pair<i64, i64>> shorts;
    for (u32 i = 0; i < short_count; ++i) {
        auto site = reader.take<i64>(), target = reader.take<i64>(); shorts.emplace_back(site, target);
    }
    auto text = blob(reader); finish(reader);
    Context context{}; context.data_start = data_start;
    std::map<i64, i64> events;
    std::map<i64, Branch> widened;
    std::set<std::string> names;
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) { return a.begin < b.begin; });
    i64 end = text_start;
    for (const auto& row : rows) {
        if (row.begin < text_start || row.begin < end || row.begin >= row.end || row.end > add(text_start, static_cast<i64>(text_size)))
            throw std::runtime_error("Replacement span overlaps or escapes native executable text");
        if (!names.insert(row.symbol).second) throw std::runtime_error("Replacement symbol is duplicated");
        if (!row.retired && !row.size) throw std::runtime_error("Replacement has no nonempty compiled function");
        context.replacements.push_back({row.begin, row.end, row.retired}); end = row.end;
        if (!row.retired && row.size > static_cast<u64>(row.end - row.begin))
            events[row.end] = static_cast<i64>(aligned(row.size - (row.end - row.begin), granularity));
    }
    auto refresh = [&] {
        context.events.clear(); i64 delta = 0;
        for (auto [point, size] : events) { delta = add(delta, size); context.events.emplace_back(point, delta); }
        auto new_end = aligned(static_cast<u64>(add(add(text_start, static_cast<i64>(text_size)), delta)), granularity);
        context.section_delta = std::max<i64>(0, add(static_cast<i64>(new_end), -data_start));
        rva32(add(data_start, context.section_delta));
    };
    for (;;) {
        refresh(); bool changed = false;
        for (auto [site, target] : shorts) {
            if (context.replaced(site) || widened.contains(site)) continue;
            if (site < text_start) throw std::runtime_error("Short branch precedes native text");
            auto prefix = prefix_at(text, static_cast<u64>(site - text_start));
            auto opcode = text[site - text_start + prefix.size()];
            auto size = static_cast<u32>(prefix.size() + 2);
            auto displacement = add(context.resolve(target), -add(context.map(site), size));
            if (-128 <= displacement && displacement <= 127) continue;
            if (opcode != 0xeb && !(0x70 <= opcode && opcode <= 0x7f) && !(0xe0 <= opcode && opcode <= 0xe3))
                throw std::runtime_error("Unsupported short branch requiring relaxation");
            if (granularity < 8) throw std::runtime_error("Branch relaxation requires at least 8 insertion bytes");
            events[site + size] = add(events[site + size], static_cast<i64>(granularity));
            widened.emplace(site, Branch{site, target, size, opcode, std::move(prefix)}); changed = true;
        }
        if (!changed) break;
    }
    refresh(); writer.put<i64>(context.section_delta); writer.put<u32>(static_cast<u32>(events.size()));
    for (auto [point, size] : events) { writer.put<i64>(point); writer.put<i64>(size); }
    writer.put<u32>(static_cast<u32>(widened.size()));
    for (const auto& [site, row] : widened) {
        writer.put<i64>(site); writer.put<i64>(row.target); writer.put<u32>(row.size);
        writer.put<u32>(row.opcode); writer.bytes(row.prefix);
    }
}
std::unordered_map<std::string, i64> bindings(Reader& reader) {
    std::unordered_map<std::string, i64> result;
    auto n = count(reader, 16);
    for (u32 i = 0; i < n; ++i) {
        auto name = string(reader); auto value = reader.take<i64>();
        if (!result.emplace(name, value).second) throw std::runtime_error("Duplicate native symbol binding");
    }
    return result;
}
struct Definition { std::string name; u64 value; u32 kind; };
struct InputSection {
    std::string name; u64 size; u32 flags; bool discarded;
    std::vector<Definition> definitions;
    i64 rva = -1; u32 placement = 0; std::int32_t owner = -1;
};
void placement_stage(Context& context, Reader& reader, Writer& writer) {
    auto grow = reader.take<u32>() != 0;
    auto tail = reader.take<i64>(), tail_end = reader.take<i64>(), appended = reader.take<i64>();
    auto bss_tail = reader.take<i64>(), bss_limit = reader.take<i64>();
    auto data_alignment = reader.take<u64>(); auto rows = replacements(reader);
    auto native = bindings(reader);
    std::vector<InputSection> sections;
    auto n = count(reader, 28);
    for (u32 i = 0; i < n; ++i) {
        InputSection s; s.name = string(reader); s.size = reader.take<u64>();
        s.flags = reader.take<u32>(); s.discarded = reader.take<u32>() != 0;
        if (s.size > std::numeric_limits<u32>::max()) throw std::runtime_error("Compiled section exceeds PE extent domain");
        auto definitions = count(reader, 20);
        for (u32 j = 0; j < definitions; ++j) {
            auto name = string(reader); auto value = reader.take<u64>(); auto kind = reader.take<u32>();
            s.definitions.push_back({std::move(name), value, kind});
        }
        sections.push_back(std::move(s));
    }
    finish(reader); aligned(0, data_alignment);
    u64 code_size = 0, writable_size = 0;
    std::unordered_map<std::string, u32> definitions, owners;
    for (u32 i = 0; i < rows.size(); ++i) if (!rows[i].retired) owners.emplace(rows[i].symbol, i);
    for (u32 i = 0; i < sections.size(); ++i) {
        auto& s = sections[i];
        if (s.discarded || !s.size || s.name.starts_with(".debug") || s.name.starts_with(".llvm") || s.name == ".pdata") continue;
        auto base = s.name.substr(0, s.name.find('$'));
        if (base != ".text" && base != ".rdata" && base != ".xdata" && base != ".data" && base != ".bss")
            throw std::runtime_error("Unsupported C++ section: " + s.name);
        auto exponent = (s.flags >> 20) & 15;
        if (exponent == 15) throw std::runtime_error("Reserved COFF section alignment");
        auto alignment = u64{1} << (exponent ? exponent - 1 : 0);
        for (const auto& def : s.definitions) {
            if (!definitions.emplace(def.name, i).second) throw std::runtime_error("Duplicate strong definition: " + def.name);
            if (owners.contains(def.name)) s.owner = static_cast<std::int32_t>(owners.at(def.name));
            if (native.contains(def.name) && !owners.contains(def.name)) throw std::runtime_error("Native symbol is not a replaceable function: " + def.name);
        }
        if (s.owner >= 0) {
            if (s.definitions.size() != 1 || s.definitions[0].value || !(s.definitions[0].kind & 0x20) ||
                base != ".text" || !(s.flags & 0x20) || !(s.flags & 0x20000000))
                throw std::runtime_error("A replacement must be an external function in its own executable text section");
            s.rva = context.map(rows[s.owner].begin); s.placement = 1;
            if (s.rva % alignment) throw std::runtime_error("Replacement alignment exceeds its original entry guarantee");
        } else if (!(s.flags & 0x80000000)) {
            auto at = aligned(static_cast<u64>(tail), alignment);
            if (!grow && add(static_cast<i64>(at), static_cast<i64>(s.size)) <= tail_end) {
                s.rva = static_cast<i64>(at); tail = add(s.rva, static_cast<i64>(s.size)); s.placement = 2;
            } else {
                auto at_code = aligned(static_cast<u64>(add(appended, static_cast<i64>(code_size))), alignment);
                s.rva = static_cast<i64>(at_code); code_size = at_code - appended + s.size; s.placement = 3;
            }
        } else {
            auto at = aligned(static_cast<u64>(bss_tail), alignment);
            if (!grow && base == ".bss" && add(static_cast<i64>(at), static_cast<i64>(s.size)) <= bss_limit) {
                s.rva = static_cast<i64>(at); bss_tail = add(s.rva, static_cast<i64>(s.size)); s.placement = 4;
            } else {
                s.rva = static_cast<i64>(aligned(writable_size, alignment)); writable_size = s.rva + s.size;
                data_alignment = std::max(data_alignment, alignment); s.placement = 5;
            }
        }
        rva32(add(s.rva, static_cast<i64>(s.size)));
    }
    auto data_rva = aligned(static_cast<u64>(add(appended, static_cast<i64>(code_size))), data_alignment);
    rva32(add(static_cast<i64>(data_rva), static_cast<i64>(writable_size)));
    context.native_bindings = native; context.bindings.clear();
    for (const auto& [name, value] : native) context.bindings.emplace(name, context.map(value));
    for (auto& s : sections) {
        if (s.placement == 5) s.rva = add(s.rva, static_cast<i64>(data_rva));
        if (s.placement) for (const auto& def : s.definitions) {
            if (def.value > s.size) throw std::runtime_error("COFF symbol escapes compiled section");
            context.bindings[def.name] = add(s.rva, static_cast<i64>(def.value));
        }
    }
    for (const auto& [name, index] : owners) {
        (void)index;
        if (!definitions.contains(name)) throw std::runtime_error("Replacement has no compiled definition: " + name);
    }
    writer.put<i64>(tail); writer.put<i64>(bss_tail); writer.put<i64>(appended);
    writer.put<u64>(code_size); writer.put<u64>(data_rva); writer.put<u64>(writable_size);
    writer.put<u32>(static_cast<u32>(sections.size()));
    for (const auto& s : sections) { writer.put<i64>(s.rva); writer.put<u32>(s.placement); writer.put<std::int32_t>(s.owner); }
}
void bind_stage(Context& context, Reader& reader) {
    auto native = bindings(reader), linked = bindings(reader); finish(reader);
    context.native_bindings = std::move(native); context.bindings = std::move(linked);
}
void target_stage(Context& context, Reader& reader, Writer& writer) {
    struct TargetSection { i64 rva, original, selected, selected_original; bool discarded; };
    struct Symbol { u32 index; std::string name; i64 value; std::int32_t section, fallback; };
    std::vector<TargetSection> sections;
    auto n = count(reader, 36);
    for (u32 i = 0; i < n; ++i) {
        auto rva = reader.take<i64>(), original = reader.take<i64>(), selected = reader.take<i64>();
        auto selected_original = reader.take<i64>();
        auto discarded = reader.take<u32>() != 0; sections.push_back({rva, original, selected, selected_original, discarded});
    }
    std::map<u32, Symbol> symbols;
    auto symbol_count = count(reader, 28);
    for (u32 i = 0; i < symbol_count; ++i) {
        auto index = reader.take<u32>(); auto name = string(reader); auto value = reader.take<i64>();
        auto section = reader.take<std::int32_t>(), fallback = reader.take<std::int32_t>();
        if (section > static_cast<i64>(sections.size()) || section < -2 || !symbols.emplace(index, Symbol{index, name, value, section, fallback}).second)
            throw std::runtime_error("Invalid COFF symbol table for native resolution");
    }
    finish(reader);
    auto slots = symbols.empty() ? 0 : u64{symbols.rbegin()->first} + 1;
    if (slots > 10000000) throw std::runtime_error("COFF symbol index domain is too sparse");
    Bytes targets(static_cast<std::size_t>(slots * 16));
    for (const auto& [index, initial] : symbols) {
        const Symbol* symbol = &initial; std::set<u32> visited;
        while (symbol->fallback >= 0 && !context.bindings.contains(symbol->name)) {
            if (!visited.insert(symbol->index).second) { symbol = nullptr; break; }
            auto it = symbols.find(static_cast<u32>(symbol->fallback));
            if (it == symbols.end()) throw std::runtime_error("Invalid weak external fallback");
            symbol = &it->second;
        }
        if (!symbol) continue;
        u32 flags = 1; i64 value;
        if (symbol->section > 0) {
            const auto& s = sections[symbol->section - 1];
            if (s.discarded) {
                value = s.selected_original >= 0 ? s.selected_original : s.selected;
                if (value < 0) continue;
                flags |= s.selected_original >= 0 ? 4 : 0;
            }
            else { value = s.original >= 0 ? s.original : s.rva; if (value < 0) continue; flags |= s.original >= 0 ? 4 : 0; }
            value = add(value, symbol->value);
        } else if (symbol->section == -1) { value = symbol->value; flags |= 2; }
        else if (symbol->name.starts_with("replay_rva_")) {
            auto suffix = symbol->name.substr(11); std::size_t used = 0;
            if (suffix.empty() || suffix.size() > 8 || suffix.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                throw std::runtime_error("Invalid replay_rva_ symbol encoding");
            value = static_cast<i64>(std::stoull(suffix, &used, 16));
            if (value >= context.image_size) continue;
            flags |= 4;
        } else {
            auto bound = context.bindings.find(symbol->name); if (bound == context.bindings.end()) continue;
            auto old = context.native_bindings.find(symbol->name);
            value = old == context.native_bindings.end() ? bound->second : old->second;
            flags |= old == context.native_bindings.end() ? 0 : 4;
        }
        patch<i64>(targets, u64{index} * 16, value); patch<u32>(targets, u64{index} * 16 + 8, flags);
    }
    writer.data = std::move(targets);
}
struct OutputSection { std::string name; u32 rva, virtual_size, flags; Bytes data; u32 raw_at = 0, raw_size = 0; };
std::vector<OutputSection> read_sections(Reader& reader) {
    std::vector<OutputSection> result;
    auto n = count(reader, 28);
    for (u32 i = 0; i < n; ++i) {
        auto name = string(reader); auto rva = reader.take<u32>(), size = reader.take<u32>(), flags = reader.take<u32>();
        auto data = blob(reader);
        if (u64{rva} + std::max<u64>(size, data.size()) > std::numeric_limits<u32>::max())
            throw std::runtime_error("Invalid PE section virtual extent");
        result.push_back({name, rva, size, flags, std::move(data)});
    }
    return result;
}
void write_sections(Writer& writer, const std::vector<OutputSection>& sections) {
    writer.put<u32>(static_cast<u32>(sections.size()));
    for (const auto& s : sections) { writer.text(s.name); writer.put<u32>(s.rva); writer.put<u32>(s.virtual_size); writer.put<u32>(s.flags); writer.bytes(s.data); }
}
struct Directory { u32 rva, size; };
std::vector<Directory> read_directories(Reader& reader) {
    std::vector<Directory> result;
    auto n = count(reader, 8);
    if (n != 16) throw std::runtime_error("Replay PE requires 16 directories");
    for (u32 i = 0; i < n; ++i) { auto rva = reader.take<u32>(), size = reader.take<u32>(); result.push_back({rva, size}); }
    return result;
}
void write_directories(Writer& writer, const std::vector<Directory>& directories) {
    writer.put<u32>(static_cast<u32>(directories.size()));
    for (auto row : directories) { writer.put<u32>(row.rva); writer.put<u32>(row.size); }
}
u64 image_end(const std::vector<OutputSection>& sections) {
    u64 end = 0;
    for (const auto& s : sections) end = std::max(end, u64{s.rva} + std::max<u64>(s.virtual_size, s.data.size()));
    return end;
}
void directory_replace(std::vector<OutputSection>& sections, Directory& directory, const Bytes& data,
    const std::string& name, u32 flags, u32 alignment) {
    for (auto& s : sections) {
        if (directory.rva >= s.rva && directory.rva - s.rva <= s.data.size() && data.size() <= s.data.size() - (directory.rva - s.rva)) {
            std::copy(data.begin(), data.end(), s.data.begin() + directory.rva - s.rva);
            s.virtual_size = std::max(s.virtual_size, rva32(directory.rva - s.rva + static_cast<i64>(data.size())));
            directory.size = rva32(static_cast<i64>(data.size())); return;
        }
    }
    directory.rva = rva32(static_cast<i64>(aligned(image_end(sections), alignment)));
    directory.size = rva32(static_cast<i64>(data.size()));
    sections.push_back({name, directory.rva, directory.size, flags, data});
}
void tables_stage(Context& context, Reader& reader, Writer& writer) {
    auto alignment = reader.take<u32>(); auto directories = read_directories(reader); auto sections = read_sections(reader);
    auto original_entries = blob(reader); auto compiled = blob(reader); auto bases_count = count(reader, 8); std::vector<u64> bases;
    for (u32 i = 0; i < bases_count; ++i) bases.push_back(reader.take<u64>());
    finish(reader);
    auto pdata = std::find_if(sections.begin(), sections.end(), [](const auto& s) { return s.name == ".pdata"; });
    auto reloc = std::find_if(sections.begin(), sections.end(), [](const auto& s) { return s.name == ".reloc"; });
    if (pdata == sections.end() || reloc == sections.end()) throw std::runtime_error("Missing native PE loader tables");
    if (original_entries.size() != directories[3].size || original_entries.size() % 12 || compiled.size() % 12)
        throw std::runtime_error("Truncated runtime function table");
    using Entry = std::array<u32, 3>;
    std::vector<Entry> retained, removed, linked;
    Reader entries{original_entries.data(), original_entries.size()};
    while (entries.at < entries.size) {
        Entry e{entries.take<u32>(), entries.take<u32>(), entries.take<u32>()}; bool intersects = false, contained = false;
        // Replay has a proven zero-length native entry. Preserve native empty
        // records; newly compiled ranges below must still be nonempty.
        if (e[0] > e[1]) throw std::runtime_error("Invalid native runtime function range");
        for (const auto& r : context.replacements) {
            intersects |= e[0] < r.end && e[1] > r.begin;
            contained |= r.begin <= e[0] && e[1] <= r.end;
        }
        if (intersects) { if (!contained) throw std::runtime_error("Replacement intersects a shared unwind range; recover the complete function"); removed.push_back(e); }
        else { retained.push_back(e); linked.push_back({rva32(context.map(e[0])), rva32(context.map(e[1])), rva32(context.map(e[2]))}); }
    }
    Reader cpp{compiled.data(), compiled.size()};
    while (cpp.at < cpp.size) {
        Entry e{cpp.take<u32>(), cpp.take<u32>(), cpp.take<u32>()};
        if (e[0] >= e[1]) throw std::runtime_error("Invalid compiled runtime function range");
        linked.push_back(e);
    }
    std::sort(linked.begin(), linked.end());
    for (std::size_t i = 1; i < linked.size(); ++i) if (linked[i - 1][1] > linked[i][0]) throw std::runtime_error("Overlapping runtime function ranges");
    auto relocation_at = context.map(directories[5].rva) - reloc->rva;
    if (relocation_at < 0 || static_cast<u64>(relocation_at) > reloc->data.size() || directories[5].size > reloc->data.size() - relocation_at)
        throw std::runtime_error("Truncated native loader relocations");
    Reader old{reloc->data.data() + relocation_at, directories[5].size}; std::map<u32, std::set<u16>> pages;
    while (old.at < old.size) {
        auto page = old.take<u32>(), size = old.take<u32>();
        if (size < 8 || size % 2 || size - 8 > old.size - old.at || page % 4096)
            throw std::runtime_error("Invalid original base relocation block");
        for (u32 i = 0; i < (size - 8) / 2; ++i) {
            auto entry = old.take<u16>(); if (!(entry >> 12)) continue;
            auto at = add(page, entry & 4095); if (context.replaced(at)) continue;
            if ((entry >> 12) != 10) throw std::runtime_error("Unsupported native AMD64 loader relocation type");
            auto mapped = rva32(context.map(at)); pages[mapped & ~4095u].insert(static_cast<u16>((entry & 0xf000) | (mapped & 4095)));
        }
    }
    for (auto at : bases) { auto site = rva32(static_cast<i64>(at)); pages[site & ~4095u].insert(static_cast<u16>(0xa000 | (site & 4095))); }
    Writer relocation_data, unwind_data;
    for (const auto& [page, values] : pages) {
        relocation_data.put<u32>(page); relocation_data.put<u32>(8 + static_cast<u32>((values.size() + values.size() % 2) * 2));
        for (auto value : values) relocation_data.put<u16>(value);
        if (values.size() % 2) relocation_data.put<u16>(0);
    }
    for (const auto& e : linked) for (auto value : e) unwind_data.put<u32>(value);
    for (u32 i = 0; i < directories.size(); ++i) {
        if (i == 4 && (directories[i].rva || directories[i].size))
            throw std::runtime_error("Recovered certificate file offsets cannot be emitted as RVAs");
        if (directories[i].rva) directories[i].rva = rva32(context.map(directories[i].rva));
    }
    directory_replace(sections, directories[3], unwind_data.data, ".pdata2", 0x40000040, alignment);
    directory_replace(sections, directories[5], relocation_data.data, ".reloc2", 0x42000040, alignment);
    directories[6] = {0, 0};
    writer.put<u32>(static_cast<u32>(removed.size())); writer.put<u32>(static_cast<u32>(retained.size()));
    for (const auto& e : retained) for (auto value : e) writer.put<u32>(value);
    write_directories(writer, directories); write_sections(writer, sections);
}
void relative_stage(Context& context, Reader& reader, Writer& writer) {
    auto target = reader.take<i64>(), origin = reader.take<i64>(); auto width = reader.take<u32>(), shift = reader.take<u32>();
    auto subtract = reader.take<u32>() != 0, is_signed = reader.take<u32>() != 0; finish(reader);
    if ((width != 1 && width != 2 && width != 4 && width != 8) || shift >= 64) throw std::runtime_error("Unsupported relative table encoding");
    __int128 distance = __int128{context.resolve(target)} - context.map(origin);
    if (subtract) distance = -distance;
    const auto mask = (__int128{1} << shift) - 1;
    if (distance & mask) throw std::runtime_error("Shifted switch target is not representable by its table encoding");
    auto value = distance >> shift; auto bits = width * 8;
    auto minimum = is_signed ? -(__int128{1} << (bits - 1)) : 0;
    auto maximum = (__int128{1} << (bits - (is_signed ? 1 : 0))) - 1;
    if (value < minimum || value > maximum) throw std::runtime_error("Shifted switch table target is out of range");
    auto raw = static_cast<u64>(value);
    for (u32 i = 0; i < width; ++i) writer.put<u8>(static_cast<u8>(raw >> (i * 8)));
}
void pe_stage(Reader& reader, Writer& writer) {
    auto timestamp = reader.take<u32>(); auto characteristics = reader.take<u16>();
    auto identity = blob(reader); auto optional = blob(reader); auto directories = read_directories(reader);
    auto sections = read_sections(reader); finish(reader);
    if (identity.size() != 64 || optional.size() != 112 || sections.empty() || sections.size() > 96)
        throw std::runtime_error("Invalid fresh PE header inputs");
    auto section_alignment = static_cast<u32>(load(optional.data(), optional.size(), 32, 4));
    auto file_alignment = static_cast<u32>(load(optional.data(), optional.size(), 36, 4));
    if (section_alignment < file_alignment || file_alignment < 512 || file_alignment > 65536)
        throw std::runtime_error("Invalid PE file/section alignment");
    aligned(0, section_alignment); aligned(0, file_alignment);
    auto header_size = aligned(0x80 + 24 + 240 + 40 * sections.size(), file_alignment);
    u64 raw_at = header_size, code_size = 0, initialized_size = 0;
    std::vector<std::pair<u64, u64>> ranges;
    for (auto& s : sections) {
        if (s.name.size() > 8 || s.name.find('\0') != std::string::npos || s.rva % section_alignment || s.rva < aligned(header_size, section_alignment))
            throw std::runtime_error("Invalid PE output section name or alignment");
        if (s.virtual_size || !s.data.empty()) ranges.emplace_back(s.rva, u64{s.rva} + std::max<u64>(s.virtual_size, s.data.size()));
        s.raw_at = rva32(static_cast<i64>(raw_at)); s.raw_size = rva32(static_cast<i64>(aligned(s.data.size(), file_alignment)));
        raw_at += s.raw_size; rva32(static_cast<i64>(raw_at));
        if (s.flags & 0x20) code_size += s.raw_size;
        if (s.flags & 0x40) initialized_size += s.raw_size;
    }
    std::sort(ranges.begin(), ranges.end());
    for (std::size_t i = 1; i < ranges.size(); ++i) if (ranges[i - 1].second > ranges[i].first) throw std::runtime_error("Overlapping PE output sections");
    auto image_size = rva32(static_cast<i64>(aligned(image_end(sections), section_alignment)));
    Bytes image(static_cast<std::size_t>(raw_at)); image[0] = 'M'; image[1] = 'Z'; patch<u32>(image, 0x3c, 0x80);
    patch<u32>(identity, 44, image_size); std::copy(identity.begin(), identity.end(), image.begin() + 0x40);
    patch<u32>(image, 0x80, 0x00004550); patch<u16>(image, 0x84, 0x8664); patch<u16>(image, 0x86, static_cast<u16>(sections.size()));
    patch<u32>(image, 0x88, timestamp); patch<u16>(image, 0x94, 240); patch<u16>(image, 0x96, characteristics);
    patch<u16>(optional, 0, 0x20b); optional[2] = 22; optional[3] = 1;
    patch<u32>(optional, 4, rva32(static_cast<i64>(code_size))); patch<u32>(optional, 8, rva32(static_cast<i64>(initialized_size)));
    patch<u32>(optional, 56, image_size); patch<u32>(optional, 60, rva32(static_cast<i64>(header_size)));
    patch<u32>(optional, 64, 0); patch<u32>(optional, 108, 16);
    std::copy(optional.begin(), optional.end(), image.begin() + 0x98);
    for (u32 i = 0; i < directories.size(); ++i) { patch<u32>(image, 0x98 + 112 + i * 8, directories[i].rva); patch<u32>(image, 0x98 + 116 + i * 8, directories[i].size); }
    for (u32 i = 0; i < sections.size(); ++i) {
        const auto& s = sections[i]; u64 at = 0x98 + 240 + i * 40;
        std::copy(s.name.begin(), s.name.end(), image.begin() + at);
        patch<u32>(image, at + 8, s.virtual_size); patch<u32>(image, at + 12, s.rva);
        patch<u32>(image, at + 16, s.raw_size); patch<u32>(image, at + 20, s.raw_at); patch<u32>(image, at + 36, s.flags);
        std::copy(s.data.begin(), s.data.end(), image.begin() + s.raw_at);
    }
    writer.data = std::move(image);
}
void text_stage(Context& context, Reader& reader, Writer& writer) {
    auto mode = reader.take<u32>(), start = reader.take<u32>(), granularity = reader.take<u32>(); auto text = blob(reader);
    if (mode == 0) {
        finish(reader); u64 at = 0; i64 previous_delta = 0;
        for (auto [point, cumulative] : context.events) {
            if (point < start || static_cast<u64>(point - start) > text.size()) throw std::runtime_error("Insertion escapes native text");
            auto offset = static_cast<u64>(point - start);
            writer.data.insert(writer.data.end(), text.begin() + at, text.begin() + offset);
            writer.data.insert(writer.data.end(), static_cast<std::size_t>(cumulative - previous_delta), 0x90);
            previous_delta = cumulative; at = offset;
        }
        writer.data.insert(writer.data.end(), text.begin() + at, text.end()); return;
    }
    if (mode != 1) throw std::runtime_error("Unknown native text link pass");
    auto n = count(reader, 32);
    for (u32 i = 0; i < n; ++i) {
        auto site = reader.take<i64>(), target = reader.take<i64>(); auto size = reader.take<u32>(), opcode = reader.take<u32>(); auto prefix = blob(reader);
        if (context.replaced(site)) continue;
        auto mapped = context.map(site); if (mapped < start) throw std::runtime_error("Branch precedes output text");
        auto at = static_cast<u64>(mapped - start);
        if (!size) {
            auto original_prefix = prefix_at(text, at); auto short_size = original_prefix.size() + 2;
            auto displacement = add(context.resolve(target), -add(mapped, static_cast<i64>(short_size)));
            if (displacement < -128 || displacement > 127) throw std::runtime_error("Unrelaxed short branch is out of range");
            patch<u8>(text, at + short_size - 1, static_cast<u8>(displacement));
        } else {
            Bytes code = prefix;
            if (opcode == 0xeb) code.push_back(0xe9);
            else if (opcode >= 0x70 && opcode <= 0x7f) { code.push_back(0x0f); code.push_back(static_cast<u8>(opcode + 0x10)); }
            else if (opcode >= 0xe0 && opcode <= 0xe3) code.insert(code.end(), {static_cast<u8>(opcode), 2, 0xeb, 5, 0xe9});
            else throw std::runtime_error("Unsupported relaxed short branch opcode");
            auto displacement = add(context.resolve(target), -add(mapped, static_cast<i64>(code.size() + 4)));
            if (displacement < std::numeric_limits<std::int32_t>::min() || displacement > std::numeric_limits<std::int32_t>::max()) throw std::runtime_error("Relaxed branch exceeds REL32 range");
            Writer relative; relative.put<std::int32_t>(static_cast<std::int32_t>(displacement)); code.insert(code.end(), relative.data.begin(), relative.data.end());
            auto extent = u64{size} + granularity;
            if (code.size() > extent || at > text.size() || extent > text.size() - at) throw std::runtime_error("Relaxed branch escapes reserved extent");
            std::fill(text.begin() + at, text.begin() + at + extent, 0x90); std::copy(code.begin(), code.end(), text.begin() + at);
        }
    }
    finish(reader); writer.data = std::move(text);
}
void unwind_stage(Context& context, Reader& reader, Writer& writer) {
    auto n = count(reader, 12); std::map<u32, std::vector<std::pair<u32, u32>>> owners;
    for (u32 i = 0; i < n; ++i) { auto begin = reader.take<u32>(), end = reader.take<u32>(), info = reader.take<u32>(); owners[info].emplace_back(begin, end); }
    auto sections = read_sections(reader); finish(reader);
    auto read = [&](u32 rva, u64 size) -> const u8* {
        const u8* found = nullptr;
        for (const auto& s : sections) if (rva >= s.rva && rva - s.rva <= s.data.size() && size <= s.data.size() - (rva - s.rva)) {
            if (found) throw std::runtime_error("Ambiguous native unwind metadata"); found = s.data.data() + rva - s.rva;
        }
        if (!found) throw std::runtime_error("Native unwind metadata escapes initialized source"); return found;
    };
    std::map<u32, u8> writes;
    for (const auto& [info, functions] : owners) {
        std::vector<bool> affected;
        for (auto [begin, end] : functions) affected.push_back(std::any_of(context.events.begin(), context.events.end(), [&](const auto& e) { return begin < e.first && e.first <= end; }));
        if (std::none_of(affected.begin(), affected.end(), [](bool value) { return value; })) continue;
        const auto* header = read(info, 4);
        if ((header[0] & 7) != 1) throw std::runtime_error("Relaxation inside a version-2 unwind function requires source reconstruction");
        const auto* codes = read(info + 4, header[2] * 2); std::vector<std::pair<u32, u8>> fields;
        for (u32 index = 0; index < header[2];) {
            fields.emplace_back(info + 4 + index * 2, codes[index * 2]);
            auto operation = codes[index * 2 + 1] & 15, argument = codes[index * 2 + 1] >> 4;
            u32 extra = operation == 1 ? (argument == 0 ? 1 : 2) : (operation == 4 || operation == 8 ? 1 : (operation == 5 || operation == 9 ? 2 : 0));
            if (index + 1 + extra > header[2]) throw std::runtime_error("Truncated native unwind operand slots");
            index += 1 + extra;
        }
        std::vector<std::pair<u32, i64>> expected;
        for (u32 i = 0; i < functions.size(); ++i) {
            auto begin = functions[i].first;
            auto offset = [&](u8 value) { return affected[i] ? add(context.map(begin + value), -context.map(begin)) : i64{value}; };
            std::vector<std::pair<u32, i64>> adjusted{{info + 1, offset(header[1])}};
            for (auto [field, value] : fields) adjusted.emplace_back(field, offset(value));
            if (i && expected != adjusted) throw std::runtime_error("Shared native unwind info needs separate source definitions after relaxation");
            expected = std::move(adjusted);
        }
        for (auto [field, value] : expected) {
            if (value < 0 || value > 255) throw std::runtime_error("Relaxed prologue exceeds the x64 unwind offset limit");
            if (*read(field, 1) != value) writes[field] = static_cast<u8>(value);
        }
    }
    writer.put<u32>(static_cast<u32>(writes.size()));
    for (auto [field, value] : writes) { writer.put<u32>(field); writer.put<u8>(value); }
}
void retained_stage(Context& context, Reader& reader, Writer& writer) {
    auto data = blob(reader); finish(reader);
    if (data.size() % 12) throw std::runtime_error("Truncated runtime function table");
    Reader entries{data.data(), data.size()}; Writer retained; u32 count = 0, removed = 0;
    while (entries.at < entries.size) {
        auto begin = entries.take<u32>(), end = entries.take<u32>(), info = entries.take<u32>();
        if (begin > end) throw std::runtime_error("Invalid native runtime function range");
        bool intersects = false, contained = false;
        for (const auto& r : context.replacements) { intersects |= begin < r.end && end > r.begin; contained |= r.begin <= begin && end <= r.end; }
        if (intersects) {
            if (!contained) throw std::runtime_error("Replacement intersects a shared unwind range; recover the complete function");
            ++removed;
        } else { ++count; retained.put<u32>(begin); retained.put<u32>(end); retained.put<u32>(info); }
    }
    writer.put<u32>(removed); writer.put<u32>(count); writer.data.insert(writer.data.end(), retained.data.begin(), retained.data.end());
}
void common_stage(Reader& reader, Writer& writer) {
    auto native = bindings(reader);
    struct Common { u32 object, index; u64 size; std::string name; };
    std::set<std::string> strong;
    std::vector<Common> declarations;
    auto objects = count(reader, 4);
    for (u32 object = 0; object < objects; ++object) {
        auto symbols = count(reader, 32);
        for (u32 i = 0; i < symbols; ++i) {
            auto index = reader.take<u32>(); auto name = string(reader); auto value = reader.take<u64>();
            auto section = reader.take<std::int32_t>(); auto storage = reader.take<u32>(), discarded = reader.take<u32>();
            if (storage != 2) continue;
            if (section > 0 && !discarded) strong.insert(name);
            else if (section == 0 && value) {
                if (value > std::numeric_limits<u32>::max()) throw std::runtime_error("Common symbol exceeds PE extent domain");
                declarations.push_back({object, index, value, name});
            }
        }
    }
    finish(reader); std::vector<Common> allocations; std::unordered_map<std::string, u32> chosen;
    for (const auto& row : declarations) {
        if (strong.contains(row.name) || native.contains(row.name)) continue;
        auto [it, fresh] = chosen.emplace(row.name, static_cast<u32>(allocations.size()));
        if (fresh) allocations.push_back(row);
        else allocations[it->second].size = std::max(allocations[it->second].size, row.size);
    }
    writer.put<u32>(static_cast<u32>(allocations.size()));
    for (const auto& row : allocations) {
        u32 exponent = 1; while (exponent < 5 && (u64{1} << (exponent - 1)) < row.size) ++exponent;
        writer.put<u32>(row.object); writer.text(row.name); writer.put<u64>(row.size); writer.put<u32>(0xc0000080 | (exponent << 20));
    }
    writer.put<u32>(static_cast<u32>(declarations.size()));
    for (const auto& row : declarations) { writer.put<u32>(row.object); writer.put<u32>(row.index); }
}
void comdat_stage(Reader& reader, Writer& writer) {
    struct Symbol { std::string name; u32 value; std::int32_t section; u32 storage; };
    struct Object { std::string path; u32 timestamp; std::vector<u32> sections; std::map<u32, Symbol> symbols; };
    struct Relocation { u32 at, symbol, kind; };
    struct Section { u32 object, number, flags, selection, associated; Bytes data; std::vector<Relocation> relocations; bool discarded = false; std::int32_t winner = -1; };
    std::vector<Object> objects; std::vector<Section> sections;
    auto object_count = count(reader, 16);
    for (u32 i = 0; i < object_count; ++i) {
        Object object; object.path = string(reader); object.timestamp = reader.take<u32>(); auto n = count(reader, 24);
        for (u32 number = 1; number <= n; ++number) {
            Section section; section.object = i; section.number = number;
            section.flags = reader.take<u32>(); section.selection = reader.take<u32>(); section.associated = reader.take<u32>();
            section.data = blob(reader); auto relocations = count(reader, 12);
            for (u32 j = 0; j < relocations; ++j) {
                auto at = reader.take<u32>(), symbol = reader.take<u32>(), kind = reader.take<u32>(); section.relocations.push_back({at, symbol, kind});
            }
            object.sections.push_back(static_cast<u32>(sections.size())); sections.push_back(std::move(section));
        }
        auto symbols = count(reader, 24);
        for (u32 j = 0; j < symbols; ++j) {
            auto index = reader.take<u32>(); auto name = string(reader); auto value = reader.take<u32>();
            auto section = reader.take<std::int32_t>(); auto storage = reader.take<u32>();
            if (section > static_cast<i64>(object.sections.size()) || section < -2 || !object.symbols.emplace(index, Symbol{name, value, section, storage}).second)
                throw std::runtime_error("Invalid COMDAT symbol table");
        }
        objects.push_back(std::move(object));
    }
    finish(reader);
    auto keys = [&](const Object& object, u32 number) {
        std::vector<std::string> names;
        for (const auto& [index, symbol] : object.symbols) {
            (void)index;
            if (symbol.section == static_cast<i64>(number) && symbol.storage == 2 && symbol.value == 0) names.push_back(symbol.name);
        }
        return names;
    };
    std::map<std::string, std::vector<u32>> groups;
    for (u32 i = 0; i < sections.size(); ++i) {
        const auto& s = sections[i]; if (!(s.flags & 0x1000)) continue;
        if (s.selection < 1 || s.selection > 7) throw std::runtime_error("COMDAT selection record missing or invalid");
        if (s.selection == 5) continue;
        auto names = keys(objects[s.object], s.number);
        if (names.empty() && s.selection == 1) continue;
        if (names.size() != 1) throw std::runtime_error("Ambiguous COMDAT key in " + objects[s.object].path);
        groups[names[0]].push_back(i);
    }
    auto signature = [&](const Section& section) {
        Writer result; result.bytes(section.data); const auto& object = objects[section.object];
        for (const auto& relocation : section.relocations) {
            const auto found = object.symbols.find(relocation.symbol);
            if (found == object.symbols.end()) throw std::runtime_error("COMDAT relocation has no symbol");
            const auto& symbol = found->second;
            result.put<u32>(relocation.at); result.put<u32>(relocation.kind);
            auto names = symbol.section > 0 && symbol.storage != 2 ? keys(object, symbol.section) : std::vector<std::string>{symbol.name};
            if (names.size() == 1) { result.put<u32>(0); result.text(names[0]); }
            else { result.put<u32>(1); result.text(object.path); result.put<u32>(symbol.section); }
            result.put<u32>(symbol.value);
        }
        return result.data;
    };
    for (const auto& [key, entries] : groups) {
        auto winner = entries[0], mode = sections[winner].selection;
        for (auto candidate : entries) {
            const auto& s = sections[candidate];
            if (s.selection != mode) throw std::runtime_error("Conflicting COMDAT selection for " + key);
            if (entries.size() > 1 && mode == 1) throw std::runtime_error("Duplicate NODUPLICATES COMDAT: " + key);
            if (mode == 3 && s.data.size() != sections[winner].data.size()) throw std::runtime_error("COMDAT SAME_SIZE mismatch: " + key);
            if (mode == 4 && signature(s) != signature(sections[winner])) throw std::runtime_error("COMDAT EXACT_MATCH mismatch: " + key);
            if ((mode == 6 && s.data.size() > sections[winner].data.size()) ||
                (mode == 7 && objects[s.object].timestamp > objects[sections[winner].object].timestamp)) winner = candidate;
        }
        for (auto i : entries) if (i != winner) { sections[i].discarded = true; sections[i].winner = static_cast<std::int32_t>(winner); }
    }
    std::vector<u8> visited(sections.size());
    auto resolve = [&](auto&& self, u32 i) -> void {
        if (visited[i] == 1) throw std::runtime_error("Cyclic associative COMDAT graph");
        if (visited[i] == 2) return;
        visited[i] = 1; auto& s = sections[i];
        if (s.selection == 5) {
            const auto& object = objects[s.object];
            if (!s.associated || s.associated > object.sections.size() || s.associated == s.number) throw std::runtime_error("Invalid associative COMDAT parent");
            auto parent = object.sections[s.associated - 1]; self(self, parent); s.discarded = sections[parent].discarded;
        }
        visited[i] = 2;
    };
    for (u32 i = 0; i < sections.size(); ++i) resolve(resolve, i);
    writer.put<u32>(static_cast<u32>(sections.size()));
    for (const auto& s : sections) { writer.put<u32>(s.discarded); writer.put<std::int32_t>(s.winner); }
}
} // namespace

REPLAY_API u32 replay_linker_stages_abi() noexcept { return 1; }
REPLAY_API void replay_linker_release(u8* output) noexcept { delete[] output; }
REPLAY_API int replay_linker_stage(void* handle, u32 stage, const u8* input, u64 size,
    u8** output, u64* output_size, char* error, u64 capacity) noexcept {
    if (output) *output = nullptr;
    if (output_size) *output_size = 0;
    return checked(error, capacity, [&] {
        if ((!input && size) || !output || !output_size || (stage != 1 && stage != 6 && stage != 12 && stage != 13 && !handle)) throw std::runtime_error("Invalid native linker stage request");
        Reader reader{input, size}; Writer writer;
        auto* context = static_cast<Context*>(handle);
        switch (stage) {
        case 1: layout_stage(reader, writer); break;
        case 2: placement_stage(*context, reader, writer); break;
        case 3: target_stage(*context, reader, writer); break;
        case 4: tables_stage(*context, reader, writer); break;
        case 5: relative_stage(*context, reader, writer); break;
        case 6: pe_stage(reader, writer); break;
        case 7: text_stage(*context, reader, writer); break;
        case 8: unwind_stage(*context, reader, writer); break;
        case 9: bind_stage(*context, reader); break;
        case 11: retained_stage(*context, reader, writer); break;
        case 12: comdat_stage(reader, writer); break;
        case 13: common_stage(reader, writer); break;
        default: throw std::runtime_error("Unknown native linker stage");
        }
        auto result = std::make_unique<u8[]>(writer.data.size());
        std::copy(writer.data.begin(), writer.data.end(), result.get());
        *output_size = writer.data.size(); *output = result.release();
    });
}
