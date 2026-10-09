#include "PeFile.hpp"

#include <cstring>
#include <fstream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace gadgets {

PeInfo ParsePeFile(const std::filesystem::path& path) {
    PeInfo info;

    // std::ifstream has an MSVC wide-path overload via std::filesystem::path,
    // so Unicode paths work here.
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        info.error = "cannot open file";
        return info;
    }

    // Read the whole file once; PE files we handle comfortably fit memory and
    // the mutation pass needs random access to section bytes anyway.
    file.seekg(0, std::ios::end);
    const std::streamoff fileSize = file.tellg();
    if (fileSize < static_cast<std::streamoff>(sizeof(IMAGE_DOS_HEADER))) {
        info.error = "file too small for DOS header";
        return info;
    }
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> raw(static_cast<size_t>(fileSize));
    file.read(reinterpret_cast<char*>(raw.data()), fileSize);
    if (!file && file.gcount() != fileSize) {
        info.error = "short read";
        return info;
    }

    const auto ReadStruct = [&raw](size_t offset) -> const void* {
        return offset <= raw.size() ? raw.data() + offset : nullptr;
    };

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        info.error = "bad DOS signature";
        return info;
    }

    const size_t peOffset = static_cast<size_t>(dos->e_lfanew);
    if (peOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > raw.size()) {
        info.error = "e_lfanew out of range";
        return info;
    }

    const uint32_t peSig = *reinterpret_cast<const uint32_t*>(
        reinterpret_cast<const uint8_t*>(ReadStruct(peOffset)));
    if (peSig != IMAGE_NT_SIGNATURE) {
        info.error = "bad PE signature";
        return info;
    }

    const size_t fileHeaderOff = peOffset + sizeof(uint32_t);
    auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        ReadStruct(fileHeaderOff));

    const size_t optionalOff = fileHeaderOff + sizeof(IMAGE_FILE_HEADER);
    if (optionalOff + sizeof(uint16_t) > raw.size()) {
        info.error = "optional header out of range";
        return info;
    }

    const uint16_t optMagic = *reinterpret_cast<const uint16_t*>(
        ReadStruct(optionalOff));

    size_t sectionOff = 0;
    if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (optionalOff + sizeof(IMAGE_OPTIONAL_HEADER64) > raw.size()) {
            info.error = "optional header (64) out of range";
            return info;
        }
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
            ReadStruct(optionalOff));
        info.arch = PeInfo::Arch::X64;
        info.imageBase = opt->ImageBase;
        sectionOff = optionalOff + fileHeader->SizeOfOptionalHeader;
    } else if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (optionalOff + sizeof(IMAGE_OPTIONAL_HEADER32) > raw.size()) {
            info.error = "optional header (32) out of range";
            return info;
        }
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
            ReadStruct(optionalOff));
        info.arch = PeInfo::Arch::X86;
        info.imageBase = opt->ImageBase;
        sectionOff = optionalOff + fileHeader->SizeOfOptionalHeader;
    } else {
        info.error = "unknown optional header magic";
        return info;
    }

    if (sectionOff + sizeof(IMAGE_SECTION_HEADER) > raw.size() ||
        fileHeader->NumberOfSections == 0) {
        info.error = "section table out of range";
        return info;
    }

    for (uint16_t i = 0; i < fileHeader->NumberOfSections; ++i) {
        const size_t off = sectionOff + static_cast<size_t>(i) * sizeof(IMAGE_SECTION_HEADER);
        if (off + sizeof(IMAGE_SECTION_HEADER) > raw.size())
            break;

        auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(ReadStruct(off));
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        ExecSection es;
        es.rva = sec->VirtualAddress;

        // Use VirtualSize as the meaningful byte count (SizeOfRawData may
        // include padding), but never read past the raw data we have.
        size_t meaningful = static_cast<size_t>(sec->Misc.VirtualSize);
        if (meaningful == 0)
            meaningful = static_cast<size_t>(sec->SizeOfRawData);

        const size_t rawStart = static_cast<size_t>(sec->PointerToRawData);
        if (rawStart >= raw.size()) {
            info.error = "section raw pointer out of range";
            return info;
        }
        const size_t avail = std::min(std::min(meaningful, static_cast<size_t>(sec->SizeOfRawData)),
                                      raw.size() - rawStart);

        es.bytes.assign(raw.begin() + static_cast<ptrdiff_t>(rawStart),
                        raw.begin() + static_cast<ptrdiff_t>(rawStart + avail));
        info.sections.push_back(std::move(es));
    }

    if (info.sections.empty())
        info.error = "no executable sections";

    return info;
}

} // namespace gadgets
