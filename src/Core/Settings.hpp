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

    // Window placement (dialog units of the restored window).
    int winX = -1, winY = -1, winCx = 0, winCy = 0;
    bool winMaximized = false;

    // Results list column widths (dialog pixels), -1 = default.
    static constexpr int kColumnCount = 6;
    int columnWidths[kColumnCount] = {-1, -1, -1, -1, -1, -1};

    // Post-scan behavior.
    bool openWhenDone = false;

    void Load();
    void Save() const;

    void PushMruFolder(const std::wstring& folder);

    static std::filesystem::path FilePath();

    static constexpr size_t kMaxMru = 8;
};

} // namespace gadgets
