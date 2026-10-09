#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "Types.hpp"

namespace gadgets {

// Persisted application settings (INI under %APPDATA%\TotalGadgets).
struct Settings {
    ScanOptions scan;
    MutationOptions mutation;
    OutputFormat format = OutputFormat::Text;
    OutputMode mode = OutputMode::SingleFile;
    std::wstring lastOutput;
    std::vector<std::wstring> mruFolders;   // most recent first

    void Load();
    void Save() const;

    void PushMruFolder(const std::wstring& folder);

    static std::filesystem::path FilePath();

private:
    static constexpr size_t kMaxMru = 8;
};

} // namespace gadgets
