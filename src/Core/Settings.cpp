#include "Settings.hpp"

#include <algorithm>
#include <cstdio>

#include "Util.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <shlobj.h>

namespace gadgets {

namespace {

std::wstring RegPath() {
    wchar_t dir[MAX_PATH * 2] = {};
    if (FAILED(::SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, dir)))
        return L"TotalGadgets_settings.ini";
    std::filesystem::path p = dir;
    p /= L"TotalGadgets";
    std::error_code ec;
    std::filesystem::create_directories(p, ec);
    p /= L"settings.ini";
    return p.wstring();
}

std::wstring ReadStr(const wchar_t* section, const wchar_t* key, const wchar_t* def) {
    wchar_t buf[1024] = {};
    ::GetPrivateProfileStringW(section, key, def, buf, 1024, RegPath().c_str());
    return buf;
}

int ReadInt(const wchar_t* section, const wchar_t* key, int def) {
    return ::GetPrivateProfileIntW(section, key, def, RegPath().c_str());
}

void WriteStr(const wchar_t* section, const wchar_t* key, const std::wstring& v) {
    ::WritePrivateProfileStringW(section, key, v.c_str(), RegPath().c_str());
}

void WriteInt(const wchar_t* section, const wchar_t* key, int v) {
    WriteStr(section, key, std::to_wstring(v));
}

} // namespace

std::filesystem::path Settings::FilePath() {
    return RegPath();
}

void Settings::Load() {
    constexpr wchar_t kScan[] = L"Scan";
    constexpr wchar_t kMutation[] = L"Mutation";
    constexpr wchar_t kOutput[] = L"Output";
    constexpr wchar_t kMru[] = L"MRU";

    scan.maxGadgetLen = static_cast<uint32_t>(
        std::max(1, ReadInt(kScan, L"MaxLen", static_cast<int>(scan.maxGadgetLen))));
    scan.threads = static_cast<uint32_t>(ReadInt(kScan, L"Threads", 0));
    scan.uniqueOnly = ReadInt(kScan, L"Unique", 0) != 0;
    scan.allowBranches = ReadInt(kScan, L"Branches", 0) != 0;
    scan.recursive = ReadInt(kScan, L"Recursive", 0) != 0;
    scan.includeElf = ReadInt(kScan, L"Elf", 0) != 0;

    std::vector<uint8_t> bytes;
    std::string bad = util::ToUtf8(ReadStr(kScan, L"BadBytes", L""));
    if (!bad.empty())
        util::ParseHexBytes(bad, scan.badBytes);

    mutation.enabled = ReadInt(kMutation, L"Enabled", 0) != 0;
    mutation.lookback = static_cast<uint32_t>(
        std::max(1, ReadInt(kMutation, L"Lookback",
                            static_cast<int>(mutation.lookback))));
    mutation.allowBranches = ReadInt(kMutation, L"Branches", 0) != 0;

    const std::wstring fmt = ReadStr(kOutput, L"Format", L"text");
    format = (fmt == L"json")  ? OutputFormat::Json
             : (fmt == L"csv") ? OutputFormat::Csv
                               : OutputFormat::Text;
    const std::wstring modeStr = ReadStr(kOutput, L"Mode", L"single");
    this->mode = (modeStr == L"split") ? OutputMode::PerModule
                                       : OutputMode::SingleFile;
    lastOutput = ReadStr(kOutput, L"LastOutput", L"");

    mruFolders.clear();
    const int count = ReadInt(kMru, L"Count", 0);
    for (int i = 0; i < count && i < static_cast<int>(kMaxMru); ++i)
        mruFolders.push_back(ReadStr(kMru, (L"Folder" + std::to_wstring(i)).c_str(), L""));
}

void Settings::Save() const {
    constexpr wchar_t kScan[] = L"Scan";
    constexpr wchar_t kMutation[] = L"Mutation";
    constexpr wchar_t kOutput[] = L"Output";
    constexpr wchar_t kMru[] = L"MRU";

    WriteInt(kScan, L"MaxLen", static_cast<int>(scan.maxGadgetLen));
    WriteInt(kScan, L"Threads", static_cast<int>(scan.threads));
    WriteInt(kScan, L"Unique", scan.uniqueOnly ? 1 : 0);
    WriteInt(kScan, L"Branches", scan.allowBranches ? 1 : 0);
    WriteInt(kScan, L"Recursive", scan.recursive ? 1 : 0);
    WriteInt(kScan, L"Elf", scan.includeElf ? 1 : 0);

    std::string hex;
    for (uint8_t b : scan.badBytes) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%02x ", b);
        hex += buf;
    }
    WriteStr(kScan, L"BadBytes", util::ToWide(hex));

    WriteInt(kMutation, L"Enabled", mutation.enabled ? 1 : 0);
    WriteInt(kMutation, L"Lookback", static_cast<int>(mutation.lookback));
    WriteInt(kMutation, L"Branches", mutation.allowBranches ? 1 : 0);

    WriteStr(kOutput, L"Format",
             format == OutputFormat::Json   ? L"json"
             : format == OutputFormat::Csv  ? L"csv"
                                            : L"text");
    WriteStr(kOutput, L"Mode", mode == OutputMode::PerModule ? L"split" : L"single");
    WriteStr(kOutput, L"LastOutput", lastOutput);

    WriteInt(kMru, L"Count", static_cast<int>(mruFolders.size()));
    for (size_t i = 0; i < mruFolders.size(); ++i)
        WriteStr(kMru, (L"Folder" + std::to_wstring(i)).c_str(), mruFolders[i]);
}

void Settings::PushMruFolder(const std::wstring& folder) {
    mruFolders.erase(std::remove(mruFolders.begin(), mruFolders.end(), folder),
                     mruFolders.end());
    mruFolders.insert(mruFolders.begin(), folder);
    if (mruFolders.size() > kMaxMru)
        mruFolders.resize(kMaxMru);
}

} // namespace gadgets
