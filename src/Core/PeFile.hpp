#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace gadgets {

// Minimal read-only PE view: architecture, image base and executable
// sections mapped to raw file bytes. Used by the mutation pass and as a
// single source of truth for architecture detection.
struct ExecSection {
    uint32_t rva = 0;              // section RVA
    std::vector<uint8_t> bytes;    // raw section bytes (SizeOfRawData worth)
};

struct PeInfo {
    enum class Arch { X86, X64 };
    Arch arch = Arch::X64;
    uint64_t imageBase = 0;
    std::vector<ExecSection> sections;   // executable sections only
    std::string error;                   // empty when parsed successfully

    bool Ok() const { return error.empty(); }
    uint64_t RvaToVa(uint64_t rva) const { return imageBase + rva; }
};

PeInfo ParsePeFile(const std::filesystem::path& path);

} // namespace gadgets
