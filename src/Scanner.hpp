#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include <librp.hpp>

namespace gadgets {

struct ModuleGadgets {
    std::string moduleName;
    std::filesystem::path filePath;
    std::vector<librp::GadgetResult> gadgets;
};

struct ScanConfig {
    std::filesystem::path folderPath;
    std::filesystem::path outputPath;
    librp::SearchOptions searchOptions;
    bool includeSubfolders = false;
};

using ProgressCallback = std::function<void(const std::string& status, int current, int total)>;
using LogCallback = std::function<void(const std::string& message)>;

std::vector<std::filesystem::path> FindPeFiles(const std::filesystem::path& folder,
                                               bool recursive);

bool ValidatePeMagic(const std::filesystem::path& path);

std::vector<ModuleGadgets> ScanFolder(const ScanConfig& config,
                                      ProgressCallback onProgress,
                                      LogCallback onLog);

void WriteGadgetFile(const std::filesystem::path& outputPath,
                     const std::vector<ModuleGadgets>& results,
                     bool mutated = false);

} // namespace gadgets
