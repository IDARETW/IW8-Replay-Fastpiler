#include "stdafx.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>

FILE *LogFile = stderr;
bool gLogDebug = false;

struct dxbc_chunk { string tag; vector<byte> payload; };

static vector<byte> read_bytes(const string &path)
{
    std::ifstream input(path.c_str(), std::ios::binary);
    if (!input) throw std::runtime_error("cannot read: " + path);
    vector<char> raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    return vector<byte>(raw.begin(), raw.end());
}

static void write_bytes(const string &path, const vector<byte> &bytes)
{
    std::ofstream output(path.c_str(), std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("cannot write: " + path);
    if (!bytes.empty()) output.write((const char *)bytes.data(), bytes.size());
    if (!output) throw std::runtime_error("failed writing: " + path);
}

static uint32_t read_u32(const vector<byte> &bytes, size_t offset)
{
    return (uint32_t)bytes[offset] | ((uint32_t)bytes[offset + 1] << 8) |
           ((uint32_t)bytes[offset + 2] << 16) | ((uint32_t)bytes[offset + 3] << 24);
}

static bool parse_dxbc(const vector<byte> &bytes, vector<dxbc_chunk> *chunks, string *error)
{
    if (bytes.size() < 32 || memcmp(bytes.data(), "DXBC", 4)) {
        *error = "missing DXBC header"; return false;
    }
    if (read_u32(bytes, 24) != bytes.size()) { *error = "declared DXBC length mismatch"; return false; }
    uint32_t count = read_u32(bytes, 28);
    if (count > (bytes.size() - 32) / 4) { *error = "chunk directory exceeds container"; return false; }
    size_t directory_end = 32 + (size_t)count * 4;
    vector<pair<size_t, size_t>> extents;
    chunks->clear();
    for (uint32_t i = 0; i < count; ++i) {
        size_t offset = read_u32(bytes, 32 + (size_t)i * 4);
        if (offset < directory_end || offset > bytes.size() - 8) {
            *error = "chunk offset outside payload area"; return false;
        }
        uint32_t size = read_u32(bytes, offset + 4);
        if (size > bytes.size() - offset - 8) { *error = "chunk exceeds container"; return false; }
        size_t end = offset + 8 + size;
        for (const auto &prior : extents) {
            if (offset < prior.second && prior.first < end) { *error = "overlapping chunks"; return false; }
        }
        extents.push_back(make_pair(offset, end));
        dxbc_chunk chunk;
        chunk.tag.assign((const char *)&bytes[offset], 4);
        chunk.payload.assign(bytes.begin() + offset + 8, bytes.begin() + end);
        chunks->push_back(chunk);
    }
    return true;
}

static bool equivalent_tag(const string &a, const string &b)
{
    // Validation preserves the source's token-chunk tag through the reference
    // copy. Treating SHDR and SHEX as interchangeable would hide a changed
    // chunk identity even when the payload matched.
    return a == b;
}

static bool validate_shader_container(const vector<byte> &bytes, string *error)
{
    vector<dxbc_chunk> chunks;
    if (!parse_dxbc(bytes, &chunks, error)) return false;
    const dxbc_chunk *code = NULL;
    for (const auto &chunk : chunks) {
        if (chunk.tag != "SHDR" && chunk.tag != "SHEX") continue;
        if (code) { *error = "DXBC has duplicate SHDR/SHEX shader token chunks"; return false; }
        code = &chunk;
    }
    if (!code) { *error = "DXBC has no SHDR/SHEX shader token chunk"; return false; }
    if (code->payload.size() < 8 || code->payload.size() % 4) {
        *error = "DXBC shader token chunk has an invalid extent"; return false;
    }
    uint32_t version = read_u32(code->payload, 0);
    uint32_t token_count = read_u32(code->payload, 4);
    if (token_count != code->payload.size() / 4) {
        *error = "DXBC shader token count differs from its chunk extent"; return false;
    }
    uint32_t stage = version >> 16;
    uint32_t major = (version >> 4) & 0xf;
    uint32_t minor = version & 0xf;
    if (stage != 0 && stage != 1 && stage != 3 && stage != 4 && stage != 5) {
        *error = "DXBC shader stage is outside the supported Replay shader set"; return false;
    }
    if (major != 5 || minor > 1) {
        *error = "DXBC shader token version is outside the supported SM5.0/5.1 range"; return false;
    }
    return true;
}

static bool compare_validation_chunks(const vector<byte> &original, const vector<byte> &rebuilt, string *error)
{
    vector<dxbc_chunk> old_chunks, new_chunks;
    if (!parse_dxbc(original, &old_chunks, error)) return false;
    if (!parse_dxbc(rebuilt, &new_chunks, error)) return false;
    if (old_chunks.size() != new_chunks.size()) {
        *error = "rebuilt DXBC chunk count differs from the source"; return false;
    }
    vector<bool> matched(new_chunks.size(), false);
    for (const auto &old_chunk : old_chunks) {
        size_t found = new_chunks.size();
        for (size_t i = 0; i < new_chunks.size(); ++i) {
            if (!matched[i] && equivalent_tag(old_chunk.tag, new_chunks[i].tag) &&
                    old_chunk.payload == new_chunks[i].payload) { found = i; break; }
        }
        if (found == new_chunks.size()) {
            *error = "rebuilt shader is missing or changed chunk " + old_chunk.tag;
            return false;
        }
        matched[found] = true;
    }
    for (size_t i = 0; i < matched.size(); ++i) {
        if (!matched[i]) { *error = "rebuilt shader added an unverified chunk " + new_chunks[i].tag; return false; }
    }
    return true;
}

static bool validate_dxbc(const vector<byte> &bytes, string *error)
{
    vector<dxbc_chunk> chunks;
    return parse_dxbc(bytes, &chunks, error);
}

static bool verify_reflection_copy(const vector<byte> &reference, const vector<byte> &output, string *error)
{
    vector<dxbc_chunk> ref_chunks, out_chunks;
    if (!parse_dxbc(reference, &ref_chunks, error) || !parse_dxbc(output, &out_chunks, error)) return false;
    vector<size_t> ref_code, out_code;
    vector<bool> matched(out_chunks.size(), false);
    for (size_t i = 0; i < ref_chunks.size(); ++i)
        if (ref_chunks[i].tag == "SHDR" || ref_chunks[i].tag == "SHEX") ref_code.push_back(i);
    for (size_t i = 0; i < out_chunks.size(); ++i)
        if (out_chunks[i].tag == "SHDR" || out_chunks[i].tag == "SHEX") out_code.push_back(i);
    if (ref_code.size() != 1 || out_code.size() != 1) {
        *error = "reference and output must each contain one shader token chunk"; return false;
    }
    const vector<byte> &ref_tokens = ref_chunks[ref_code[0]].payload;
    const vector<byte> &out_tokens = out_chunks[out_code[0]].payload;
    if (ref_tokens.size() < 8 || out_tokens.size() < 8 ||
            read_u32(ref_tokens, 0) != read_u32(out_tokens, 0)) {
        *error = "output shader stage/version differs from its reflection reference"; return false;
    }
    for (size_t i = 0; i < ref_chunks.size(); ++i) {
        if (i == ref_code[0]) continue;
        size_t found = out_chunks.size();
        for (size_t j = 0; j < out_chunks.size(); ++j)
            if (!matched[j] && j != out_code[0] && ref_chunks[i].tag == out_chunks[j].tag &&
                    ref_chunks[i].payload == out_chunks[j].payload) { found = j; break; }
        if (found == out_chunks.size()) {
            *error = "copied reflection/signature chunk differs: " + ref_chunks[i].tag; return false;
        }
        matched[found] = true;
    }
    for (size_t j = 0; j < out_chunks.size(); ++j)
        if (j != out_code[0] && !matched[j]) {
            *error = "output added an unverified reflection/signature chunk: " + out_chunks[j].tag; return false;
        }
    return true;
}

static string with_suffix(const string &path, const char *suffix)
{
    size_t dot = path.find_last_of('.');
    size_t slash = path.find_last_of("\\/");
    if (dot != string::npos && (slash == string::npos || dot > slash)) return path.substr(0, dot) + suffix;
    return path + suffix;
}

static int run_disassemble(const string &path, bool validate)
{
    vector<byte> original = read_bytes(path), text;
    string error;
    if (!validate_shader_container(original, &error)) throw std::runtime_error("invalid DXBC input: " + error);
    HRESULT hr = disassembler(&original, &text, NULL, 1);
    if (FAILED(hr)) throw std::runtime_error("Flugan disassembly failed");
    if (validate) {
        vector<char> assembly(text.begin(), text.end());
        vector<byte> rebuilt;
        // Use the original as the section source so every non-code chunk stays
        // intact; -V then checks every chunk instead of waiving diagnostic chunks.
        rebuilt = AssembleFluganWithOptionalSignatureParsing(&assembly, false, &original);
        if (FAILED(hr)) throw std::runtime_error("source assembly validation failed");
        if (!compare_validation_chunks(original, rebuilt, &error))
            throw std::runtime_error("-V validation failed: " + error);
    }
    string output_path = with_suffix(path, ".asm");
    std::ofstream output(output_path.c_str(), std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("cannot write: " + output_path);
    if (!text.empty()) output.write((const char *)text.data(), text.size());
    if (!output) throw std::runtime_error("failed writing: " + output_path);
    return 0;
}

static int run_assemble(const string &path, const string &reflection_path)
{
    vector<byte> raw = read_bytes(path), output;
    vector<char> assembly(raw.begin(), raw.end());
    if (reflection_path.empty()) {
        HRESULT hr = AssembleFluganWithSignatureParsing(&assembly, &output);
        if (FAILED(hr)) throw std::runtime_error("Flugan assembly failed");
    } else {
        vector<byte> reference = read_bytes(reflection_path);
        string error;
        if (!validate_shader_container(reference, &error)) throw std::runtime_error("invalid reflection reference: " + error);
        output = AssembleFluganWithOptionalSignatureParsing(&assembly, false, &reference);
    }
    string error;
    if (!validate_shader_container(output, &error)) throw std::runtime_error("assembler emitted invalid DXBC: " + error);
    if (!reflection_path.empty()) {
        vector<byte> reference = read_bytes(reflection_path);
        if (!verify_reflection_copy(reference, output, &error))
            throw std::runtime_error("--copy-reflection validation failed: " + error);
    }
    vector<byte> disassembled;
    if (FAILED(disassembler(&output, &disassembled, NULL, 0)))
        throw std::runtime_error("assembler output is not accepted by the source disassembler");
    string output_path = with_suffix(path, ".shdr");
    write_bytes(output_path, output);
    return 0;
}

static void usage()
{
    fprintf(stderr, "usage: cmd_Decompiler-dxbc-prototype [-d] [-V] [--copy-reflection reference.dxbc] [-a] file...\\n");
}

int main(int argc, char **argv)
{
    bool disassemble = false, assemble = false, validate = false;
    string reflection;
    vector<string> files;
    for (int i = 1; i < argc; ++i) {
        string arg(argv[i]);
        if (arg == "-d" || arg == "--disassemble" || arg == "--disassemble-flugan") disassemble = true;
        else if (arg == "-a" || arg == "--assemble") assemble = true;
        else if (arg == "-V" || arg == "--validate") validate = true;
        else if (arg == "--copy-reflection") {
            if (++i >= argc) { usage(); return 2; }
            reflection = argv[i];
        } else if (!arg.empty() && arg[0] == '-') { usage(); return 2; }
        else files.push_back(arg);
    }
    if (files.empty() || (!disassemble && !assemble)) { usage(); return 2; }
    int result = 0;
    for (const string &file : files) {
        try {
            if (disassemble) result |= run_disassemble(file, validate);
            if (assemble) result |= run_assemble(file, reflection);
        } catch (AssemblerParseError &error) {
            fprintf(stderr, "%s\\n", error.what()); result = 1;
        } catch (const std::exception &error) {
            fprintf(stderr, "%s\\n", error.what()); result = 1;
        }
        if (result) break;
    }
    return result;
}
