#include "Scanner.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <unordered_set>

namespace gadgets {

namespace {

constexpr std::string_view kPeExtensions[] = {
    ".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl", ".efi"
};

bool IsPeExtension(const std::filesystem::path& path) {
    auto ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (auto validExt : kPeExtensions) {
        if (ext == validExt)
            return true;
    }
    return false;
}

} // namespace

std::vector<std::filesystem::path> FindPeFiles(const std::filesystem::path& folder,
                                               bool recursive) {
    std::vector<std::filesystem::path> files;

    auto addIfPe = [&](const std::filesystem::directory_entry& entry) {
        if (entry.is_regular_file() && IsPeExtension(entry.path()))
            files.push_back(entry.path());
    };

    if (recursive) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(folder))
            addIfPe(entry);
    } else {
        for (const auto& entry : std::filesystem::directory_iterator(folder))
            addIfPe(entry);
    }

    std::sort(files.begin(), files.end());
    return files;
}

bool ValidatePeMagic(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return false;

    uint16_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    return file.good() && magic == 0x5A4D; // "MZ"
}

std::vector<ModuleGadgets> ScanFolder(const ScanConfig& config,
                                      ProgressCallback onProgress,
                                      LogCallback onLog) {
    auto files = FindPeFiles(config.folderPath, config.includeSubfolders);
    const int total = static_cast<int>(files.size());
    onLog("Found " + std::to_string(total) + " PE file(s) in folder.");

    std::vector<ModuleGadgets> results;

    for (int i = 0; i < total; ++i) {
        const auto& filePath = files[i];
        auto fileName = filePath.filename().string();
        onProgress("Scanning: " + fileName, i, total);

        if (!ValidatePeMagic(filePath)) {
            onLog("[SKIP] " + fileName + " - invalid PE header");
            continue;
        }

        auto result = librp::FindGadgets(filePath.string(), config.searchOptions);
        if (!librp::Succeeded(result)) {
            onLog("[ERROR] " + fileName + ": " + librp::GetError(result));
            continue;
        }

        auto& gadgetList = librp::GetValue(result);
        onLog("[OK] " + fileName + ": " + std::to_string(gadgetList.size()) + " gadgets");

        if (!gadgetList.empty()) {
            ModuleGadgets mg;
            mg.moduleName = fileName;
            mg.filePath = filePath;
            mg.gadgets = std::move(gadgetList);
            results.push_back(std::move(mg));
        }
    }

    onProgress("Scan complete.", total, total);
    return results;
}

void WriteGadgetFile(const std::filesystem::path& outputPath,
                     const std::vector<ModuleGadgets>& results,
                     bool mutated) {
    std::ofstream out(outputPath);
    if (!out)
        return;

    size_t totalGadgets = 0;
    for (const auto& mod : results)
        totalGadgets += mod.gadgets.size();

    out << "; Total Gadgets output\n";
    out << "; Total modules: " << results.size() << "\n";
    out << "; Total gadgets: " << totalGadgets << "\n\n";

    for (const auto& mod : results) {
        std::string prefix = mutated
            ? "[" + mod.moduleName + ":mutated]"
            : "[" + mod.moduleName + "]";

        out << "; --- " << prefix << " (" << mod.gadgets.size() << " gadgets) ---\n";

        for (const auto& g : mod.gadgets) {
            char addrBuf[32];
            std::snprintf(addrBuf, sizeof(addrBuf), "0x%08llx",
                          static_cast<unsigned long long>(g.address));
            out << prefix << " " << addrBuf << ": "
                << g.disassembly << " (" << g.numOccurrences << " found)\n";
        }
        out << "\n";
    }
}

} // namespace gadgets
