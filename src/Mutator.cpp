#include "Mutator.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <unordered_set>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <capstone/capstone.h>

namespace gadgets {

namespace {

struct PeSection {
    uint64_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawOffset;
    uint32_t rawSize;
    std::vector<uint8_t> data;
};

struct PeImage {
    uint64_t imageBase;
    std::vector<PeSection> sections;
};

bool LoadPeImage(const std::filesystem::path& path, PeImage& image) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
        return false;

    auto fileSize = static_cast<size_t>(file.tellg());
    file.seekg(0);

    std::vector<uint8_t> raw(fileSize);
    file.read(reinterpret_cast<char*>(raw.data()), fileSize);
    if (!file)
        return false;

    if (fileSize < sizeof(IMAGE_DOS_HEADER))
        return false;

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    auto peOffset = static_cast<size_t>(dos->e_lfanew);
    if (peOffset + sizeof(uint32_t) > fileSize)
        return false;

    auto peSignature = *reinterpret_cast<const uint32_t*>(raw.data() + peOffset);
    if (peSignature != IMAGE_NT_SIGNATURE)
        return false;

    auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        raw.data() + peOffset + sizeof(uint32_t));

    size_t optionalOffset = peOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
    auto optionalMagic = *reinterpret_cast<const uint16_t*>(raw.data() + optionalOffset);

    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
            raw.data() + optionalOffset);
        image.imageBase = opt->ImageBase;
    } else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
            raw.data() + optionalOffset);
        image.imageBase = opt->ImageBase;
    } else {
        return false;
    }

    size_t sectionOffset = optionalOffset + fileHeader->SizeOfOptionalHeader;
    uint16_t numSections = fileHeader->NumberOfSections;

    for (uint16_t i = 0; i < numSections; ++i) {
        if (sectionOffset + sizeof(IMAGE_SECTION_HEADER) > fileSize)
            break;

        auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            raw.data() + sectionOffset);

        // Only load executable sections
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            PeSection ps;
            ps.virtualAddress = sec->VirtualAddress;
            ps.virtualSize = sec->Misc.VirtualSize;
            ps.rawOffset = sec->PointerToRawData;
            ps.rawSize = sec->SizeOfRawData;

            size_t copySize = std::min(static_cast<size_t>(ps.rawSize),
                                       fileSize - ps.rawOffset);
            ps.data.resize(copySize);
            std::memcpy(ps.data.data(), raw.data() + ps.rawOffset, copySize);

            image.sections.push_back(std::move(ps));
        }

        sectionOffset += sizeof(IMAGE_SECTION_HEADER);
    }

    return !image.sections.empty();
}

// Given an RVA, find the section containing it and return a pointer to the raw bytes
const uint8_t* ResolveRva(const PeImage& image, uint64_t rva, size_t& bytesAvailable) {
    for (const auto& sec : image.sections) {
        if (rva >= sec.virtualAddress &&
            rva < sec.virtualAddress + sec.data.size()) {
            size_t offset = static_cast<size_t>(rva - sec.virtualAddress);
            bytesAvailable = sec.data.size() - offset;
            return sec.data.data() + offset;
        }
    }
    bytesAvailable = 0;
    return nullptr;
}

bool ContainsBadBytes(const uint8_t* data, size_t len,
                      const std::vector<uint8_t>& badBytes) {
    for (size_t i = 0; i < len; ++i) {
        for (auto bad : badBytes) {
            if (data[i] == bad)
                return true;
        }
    }
    return false;
}

bool IsTerminatingInsn(const cs_insn* insn) {
    // ret, retn, retf
    if (insn->id == X86_INS_RET || insn->id == X86_INS_RETF ||
        insn->id == X86_INS_RETFQ)
        return true;
    return false;
}

struct MutatedGadget {
    uint64_t address;
    std::string disassembly;
    std::vector<uint8_t> bytes;
};

} // namespace

std::vector<ModuleGadgets> MutateGadgets(const std::vector<ModuleGadgets>& originals,
                                         const MutationConfig& config,
                                         ProgressCallback onProgress,
                                         LogCallback onLog) {
    std::vector<ModuleGadgets> results;
    int moduleIdx = 0;
    int totalModules = static_cast<int>(originals.size());

    for (const auto& mod : originals) {
        onProgress("Mutating: " + mod.moduleName, moduleIdx, totalModules);

        PeImage image;
        if (!LoadPeImage(mod.filePath, image)) {
            onLog("[MUTATE] Failed to load PE: " + mod.moduleName);
            ++moduleIdx;
            continue;
        }

        // Determine architecture from PE (check if 64-bit)
        cs_mode mode = CS_MODE_32;
        {
            std::ifstream f(mod.filePath, std::ios::binary);
            IMAGE_DOS_HEADER dos;
            f.read(reinterpret_cast<char*>(&dos), sizeof(dos));
            f.seekg(dos.e_lfanew + sizeof(uint32_t));
            IMAGE_FILE_HEADER fh;
            f.read(reinterpret_cast<char*>(&fh), sizeof(fh));
            if (fh.Machine == IMAGE_FILE_MACHINE_AMD64)
                mode = CS_MODE_64;
        }

        csh handle;
        if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
            onLog("[MUTATE] Failed to init disassembler for " + mod.moduleName);
            ++moduleIdx;
            continue;
        }
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        // Collect existing disassembly strings for dedup
        std::unordered_set<std::string> existingGadgets;
        for (const auto& g : mod.gadgets)
            existingGadgets.insert(g.disassembly);

        std::vector<MutatedGadget> mutated;
        std::unordered_set<std::string> mutatedSet;

        for (const auto& gadget : mod.gadgets) {
            uint64_t rva = gadget.address - image.imageBase;

            for (uint32_t offset = 1; offset <= config.maxOffset; ++offset) {
                if (rva < offset)
                    continue;

                uint64_t tryRva = rva - offset;
                size_t available = 0;
                const uint8_t* code = ResolveRva(image, tryRva, available);
                if (code == nullptr || available < 2)
                    continue;

                // Limit disassembly window
                size_t maxBytes = std::min(available, static_cast<size_t>(32));

                cs_insn* insns = nullptr;
                size_t count = cs_disasm(handle, code, maxBytes,
                                         image.imageBase + tryRva, 0, &insns);
                if (count == 0)
                    continue;

                // Walk instructions, looking for a valid gadget ending with ret
                std::string disasm;
                size_t totalBytes = 0;
                bool valid = false;
                uint32_t insnCount = 0;

                for (size_t i = 0; i < count && insnCount < config.maxGadgetLen; ++i) {
                    if (insnCount > 0)
                        disasm += " ; ";
                    disasm += insns[i].mnemonic;
                    if (insns[i].op_str[0] != '\0') {
                        disasm += " ";
                        disasm += insns[i].op_str;
                    }
                    totalBytes += insns[i].size;
                    ++insnCount;

                    if (IsTerminatingInsn(&insns[i])) {
                        valid = true;
                        break;
                    }
                }

                if (valid && insnCount >= 2) {
                    // Check bad bytes
                    if (!config.badBytes.empty() &&
                        ContainsBadBytes(code, totalBytes, config.badBytes)) {
                        cs_free(insns, count);
                        continue;
                    }

                    // Dedup against originals and other mutations
                    if (existingGadgets.count(disasm) == 0 &&
                        mutatedSet.count(disasm) == 0) {
                        MutatedGadget mg;
                        mg.address = image.imageBase + tryRva;
                        mg.disassembly = disasm;
                        mg.bytes.assign(code, code + totalBytes);
                        mutated.push_back(std::move(mg));
                        mutatedSet.insert(disasm);
                    }
                }

                cs_free(insns, count);
            }
        }

        if (!mutated.empty()) {
            ModuleGadgets result;
            result.moduleName = mod.moduleName;
            result.filePath = mod.filePath;
            result.gadgets.reserve(mutated.size());
            for (auto& mg : mutated) {
                librp::GadgetResult gr;
                gr.address = mg.address;
                gr.disassembly = std::move(mg.disassembly);
                gr.bytes = std::move(mg.bytes);
                gr.numOccurrences = 1;
                result.gadgets.push_back(std::move(gr));
            }
            results.push_back(std::move(result));
            onLog("[MUTATE] " + mod.moduleName + ": " +
                  std::to_string(mutated.size()) + " new gadgets from mutation");
        }

        cs_close(&handle);
        ++moduleIdx;
    }

    onProgress("Mutation complete.", totalModules, totalModules);
    return results;
}

} // namespace gadgets
