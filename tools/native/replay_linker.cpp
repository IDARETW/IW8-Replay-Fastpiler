// Replay AMD64 source linker. Catalog recovery supplies proven ownership;
// placement, relaxation, resolution, metadata and PE emission run here.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <memory>
#include <array>

#ifdef _WIN32
#define REPLAY_API extern "C" __declspec(dllexport)
#else
#define REPLAY_API extern "C" __attribute__((visibility("default")))
#endif

namespace {
using i64 = std::int64_t;
using u64 = std::uint64_t;
using u32 = std::uint32_t;
using u8 = std::uint8_t;

struct Reader {
    const u8* data;
    u64 size, at = 0;
    template<class T> T take() {
        if (at > size || sizeof(T) > size - at) throw std::runtime_error("Truncated native linker input");
        T value;
        std::memcpy(&value, data + at, sizeof(value));
        at += sizeof(value);
        return value;
    }
};

i64 add(i64 a, i64 b) {
    if ((b > 0 && a > std::numeric_limits<i64>::max() - b) ||
        (b < 0 && a < std::numeric_limits<i64>::min() - b))
        throw std::runtime_error("Native linker integer overflow");
    return a + b;
}

struct Range { i64 begin, end; bool retired; };
struct Context {
    i64 image_base, image_size, data_start, section_delta;
    std::vector<std::pair<i64, i64>> events, interiors, sections;
    std::vector<Range> replacements;
    mutable std::vector<u8> interior_used;
    std::unordered_map<std::string, i64> bindings, native_bindings;

    const Range* replaced(i64 rva) const {
        auto it = std::upper_bound(replacements.begin(), replacements.end(), rva,
            [](i64 v, const Range& r) { return v < r.begin; });
        if (it == replacements.begin()) return nullptr;
        --it;
        return rva < it->end ? &*it : nullptr;
    }
    i64 map(i64 rva) const {
        if (rva >= data_start) return add(rva, section_delta);
        auto it = std::upper_bound(events.begin(), events.end(), rva,
            [](i64 v, const auto& e) { return v < e.first; });
        return add(rva, it == events.begin() ? 0 : std::prev(it)->second);
    }
    i64 resolve(i64 rva) const {
        if (const auto* range = replaced(rva)) {
            if (range->retired) throw std::runtime_error("Reference targets retired function code");
            if (rva == range->begin) return map(rva);
            auto it = std::lower_bound(interiors.begin(), interiors.end(), rva,
                [](const auto& e, i64 v) { return e.first < v; });
            if (it != interiors.end() && it->first == rva) {
                interior_used[static_cast<std::size_t>(it - interiors.begin())] = 1;
                return it->second;
            }
            throw std::runtime_error("Reference into replaced function interior has no emitted instruction label");
        }
        return map(rva);
    }
};

void message(char* error, u64 capacity, const char* text) noexcept {
    if (error && capacity) {
        auto size = std::min<u64>(std::strlen(text), capacity - 1);
        std::memcpy(error, text, size);
        error[size] = 0;
    }
}

template<class F> int checked(char* error, u64 capacity, F&& operation) noexcept {
    try { operation(); return 1; }
    catch (const std::exception& e) { message(error, capacity, e.what()); }
    catch (...) { message(error, capacity, "Native linker failure"); }
    return 0;
}

u64 load(const u8* data, u64 size, u64 at, u32 width) {
    if (at > size || width > size - at) throw std::runtime_error("Relocation site outside section data");
    u64 value = 0;
    std::memcpy(&value, data + at, width);
    return value;
}
void store(u8* data, u64 size, u64 at, u32 width, i64 value) {
    if (width != 1 && width != 2 && width != 4 && width != 8)
        throw std::runtime_error("Unsupported reference width");
    if (at > size || width > size - at) throw std::runtime_error("Relocation write outside section data");
    if (value < 0 || (width < 8 && static_cast<u64>(value) >= (u64{1} << (width * 8))))
        throw std::runtime_error("Unsigned relocation overflow");
    const u64 unsigned_value = static_cast<u64>(value);
    std::memcpy(data + at, &unsigned_value, width);
}
} // namespace

REPLAY_API u32 replay_linker_abi() noexcept { return 1; }

REPLAY_API void* replay_linker_create(const u8* data, u64 size, char* error, u64 capacity) noexcept {
    Context* result = nullptr;
    if (!checked(error, capacity, [&] {
        Reader reader{data, size};
        if (reader.take<u64>() != 0x4b4e4c59414c5052ull || reader.take<u32>() != 1)
            throw std::runtime_error("Unsupported native linker plan"); // RPLAYLNK
        Context context{};
        context.image_base = reader.take<i64>(); context.image_size = reader.take<i64>();
        context.data_start = reader.take<i64>(); context.section_delta = reader.take<i64>();
        if (context.image_base < 0 || context.image_size <= 0 || context.data_start < 0 || context.section_delta < 0)
            throw std::runtime_error("Invalid native linker address domain");
        const auto event_count = reader.take<u32>(), replacement_count = reader.take<u32>();
        const auto interior_count = reader.take<u32>(), section_count = reader.take<u32>();
        // Validate the complete byte extent before allocating from supplied counts.
        if (u64{event_count} * 16 + u64{replacement_count} * 20 + u64{interior_count} * 16 + u64{section_count} * 16 != size - reader.at)
            throw std::runtime_error("Invalid native linker plan extent");
        for (u32 n = 0; n < event_count; ++n) {
            auto point = reader.take<i64>(), delta = reader.take<i64>();
            if (point < 0 || delta < 0 || (!context.events.empty() &&
                (point <= context.events.back().first || delta < context.events.back().second)))
                throw std::runtime_error("Invalid layout event order");
            context.events.emplace_back(point, delta);
        }
        for (u32 n = 0; n < replacement_count; ++n) {
            const auto begin = reader.take<i64>(), end = reader.take<i64>();
            const auto retired = reader.take<u32>();
            if (begin < 0 || end <= begin || retired > 1 || (!context.replacements.empty() && begin < context.replacements.back().end))
                throw std::runtime_error("Invalid native replacement range");
            context.replacements.push_back({begin, end, retired != 0});
        }
        for (u32 n = 0; n < interior_count; ++n) {
            auto old_rva = reader.take<i64>(), new_rva = reader.take<i64>();
            const auto* owner = context.replaced(old_rva);
            if (!owner || owner->retired || old_rva == owner->begin || new_rva < 0 ||
                (!context.interiors.empty() && old_rva <= context.interiors.back().first))
                throw std::runtime_error("Invalid compiler instruction label mapping");
            context.interiors.emplace_back(old_rva, new_rva);
        }
        for (u32 n = 0; n < section_count; ++n) {
            auto rva = reader.take<i64>(), extent = reader.take<i64>();
            if (rva < 0 || extent < 0) throw std::runtime_error("Invalid linked section");
            (void)add(rva, extent);
            context.sections.emplace_back(rva, extent);
        }
        context.interior_used.resize(context.interiors.size());
        result = new Context(std::move(context));
    })) return nullptr;
    return result;
}
REPLAY_API void replay_linker_destroy(void* handle) noexcept { delete static_cast<Context*>(handle); }
REPLAY_API u64 replay_linker_interior_uses(void* handle, u64* output, u64 capacity) noexcept {
    if (!handle) return 0;
    const auto& context = *static_cast<Context*>(handle);
    u64 count = 0;
    for (std::size_t n = 0; n < context.interiors.size(); ++n) {
        if (!context.interior_used[n]) continue;
        if (count < capacity) output[count] = static_cast<u64>(context.interiors[n].first);
        ++count;
    }
    return count;
}

// Targets have a fixed 16-byte wire record: signed value, flags, reserved.
// flags: 1 = resolved, 2 = absolute COFF symbol, 4 = original image address.
REPLAY_API int replay_linker_relocate(void* handle, u8* data, u64 size, i64 section_rva,
    i64 original_rva, const u8* relocations, u64 relocation_size, const u8* targets,
    u64 target_size, u64* counters, u64* base_sites, u64* base_count,
    char* error, u64 capacity) noexcept {
    return checked(error, capacity, [&] {
        if (!handle || relocation_size % 10 || target_size % 16 || !counters || !base_count)
            throw std::runtime_error("Invalid native COFF relocation request");
        auto& context = *static_cast<Context*>(handle);
        std::fill(counters, counters + 12, 0); *base_count = 0;
        Reader reloc{relocations, relocation_size};
        while (reloc.at < reloc.size) {
            auto offset = reloc.take<u32>(), index = reloc.take<u32>();
            const auto kind = reloc.take<std::uint16_t>();
            if (!kind || (original_rva >= 0 && context.replaced(add(original_rva, offset)))) continue;
            if (kind > 11) throw std::runtime_error("Unsupported AMD64 relocation " + std::to_string(kind));
            if (u64{index} >= target_size / 16) throw std::runtime_error("Invalid COFF symbol index");
            Reader symbol{targets + u64{index} * 16, 16};
            auto value = symbol.take<i64>(); const auto flags = symbol.take<u32>();
            if (!(flags & 1)) throw std::runtime_error("Unresolved COFF symbol index " + std::to_string(index));
            const bool absolute = flags & 2, original = flags & 4;
            i64 site = original_rva >= 0 ? context.map(add(original_rva, offset)) : add(section_rva, offset);
            if (kind >= 4 && kind <= 9) {
                const i64 addend = static_cast<std::int32_t>(load(data, size, offset, 4));
                auto target = original ? context.resolve(add(value, addend)) : add(value, addend);
                auto result = add(target, -add(site, kind)); // site + 4 + (kind - 4)
                if (result < std::numeric_limits<std::int32_t>::min() || result > std::numeric_limits<std::int32_t>::max())
                    throw std::runtime_error("REL32 cannot reach its linked target");
                const auto bits = static_cast<std::uint32_t>(result);
                std::memcpy(data + offset, &bits, 4);
            } else if (kind == 2 || kind == 3) {
                auto addend = static_cast<std::int32_t>(load(data, size, offset, 4));
                value = original ? context.resolve(add(value, addend)) : add(value, addend);
                if (kind == 2 && !absolute) {
                    value = add(value, context.image_base);
                    if (value < (i64{1} << 32)) throw std::runtime_error("ADDR32 image VA needs a HIGHLOW relocation; use a 64-bit pointer");
                }
                store(data, size, offset, 4, value);
            } else if (kind == 1) {
                auto addend = static_cast<i64>(load(data, size, offset, 8));
                // Absolute ADDR64 values may exceed INT64_MAX. Keep the signed
                // COFF addend, but check the final unsigned 64-bit domain.
                __int128 result = original ? context.resolve(add(value, addend)) : __int128{value} + addend;
                result += absolute ? 0 : context.image_base;
                if (result < 0 || result > std::numeric_limits<u64>::max())
                    throw std::runtime_error("ADDR64 relocation overflow");
                const auto bits = static_cast<u64>(result);
                std::memcpy(data + offset, &bits, 8);
                if (!absolute) base_sites[(*base_count)++] = static_cast<u64>(site);
            } else if (kind == 10 || kind == 11) {
                const i64 addend = kind == 10 ? static_cast<i64>(load(data, size, offset, 2)) :
                    static_cast<std::int32_t>(load(data, size, offset, 4));
                const auto anchor = original ? context.resolve(value) : value;
                if (kind == 11) value = original ? context.resolve(add(value, addend)) : add(value, addend);
                u32 found = 0, number = 0; i64 start = 0;
                for (u32 n = 0; n < context.sections.size(); ++n) {
                    const auto& s = context.sections[n];
                    if (s.first <= anchor && anchor < add(s.first, s.second)) { ++found; number = n + 1; start = s.first; }
                }
                if (absolute || found != 1) throw std::runtime_error("Section-relative relocation has no unique output section");
                store(data, size, offset, kind == 10 ? 2 : 4, kind == 10 ? add(number, addend) : add(value, -start));
            }
            ++counters[kind];
        }
    });
}

struct ReplaySectionView { u64 rva, size; u8* data; };
REPLAY_API int replay_linker_references(void* handle, ReplaySectionView* sections, u64 section_count,
    const u8* references, u64 size, int metadata, const u64* skipped, u64 skipped_count,
    u64* counters, char* error, u64 capacity) noexcept {
    return checked(error, capacity, [&] {
        if (!handle || size % 12 || !counters) throw std::runtime_error("Invalid native reference pass");
        auto& context = *static_cast<Context*>(handle);
        std::fill(counters, counters + 3, 0);
        if (skipped_count && !std::is_sorted(skipped, skipped + skipped_count)) throw std::runtime_error("Unsorted skipped metadata fields");
        Reader reader{references, size};
        while (reader.at < size) {
            auto at = reader.take<u32>(), target = reader.take<u32>(), width = reader.take<u32>();
            if (context.replaced(at) || (skipped_count && std::binary_search(skipped, skipped + skipped_count, at))) continue;
            auto resolved = context.resolve(target), site = context.map(at);
            i64 value = add(resolved, !metadata && width == 8 ? context.image_base : 0);
            ReplaySectionView* output = nullptr;
            for (u64 n = 0; n < section_count; ++n) {
                auto& section = sections[n];
                if (site >= 0 && static_cast<u64>(site) >= section.rva && static_cast<u64>(site) - section.rva <= section.size &&
                    width <= section.size - (static_cast<u64>(site) - section.rva)) {
                    if (output) throw std::runtime_error("Ambiguous initialized data reference destination");
                    output = &section;
                }
            }
            if (!output) throw std::runtime_error("Native data reference lies outside initialized output sections");
            store(output->data, output->size, static_cast<u64>(site) - output->rva, width, value);
            ++counters[width == 8 ? 0 : 1]; counters[2] += resolved != target;
        }
    });
}

#include "replay_link_stages.hpp"
