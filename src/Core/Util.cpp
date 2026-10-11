#include "Util.hpp"

#include <atomic>
#include <cstdlib>

#include "Types.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace gadgets::util {

// --- Strings ---------------------------------------------------------------

std::wstring ToWide(std::string_view utf8) {
    if (utf8.empty())
        return {};
    int len = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
                                    static_cast<int>(utf8.size()), nullptr, 0);
    std::wstring wide(static_cast<size_t>(len), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()),
                          wide.data(), len);
    return wide;
}

std::string ToUtf8(std::wstring_view wide) {
    if (wide.empty())
        return {};
    int len = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                                    static_cast<int>(wide.size()), nullptr, 0,
                                    nullptr, nullptr);
    std::string utf8(static_cast<size_t>(len), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                          utf8.data(), len, nullptr, nullptr);
    return utf8;
}

std::string ToLower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

namespace {

// ASCII-only case-folding table. Disassembly, module names and addresses are
// all ASCII, so this avoids a locale-aware tolower call per byte.
struct LowerLut {
    unsigned char v[256];
    constexpr LowerLut() : v{} {
        for (int i = 0; i < 256; ++i)
            v[i] = static_cast<unsigned char>(
                (i >= 'A' && i <= 'Z') ? i + 32 : i);
    }
};
constexpr LowerLut kLower{};

} // namespace

bool IContains(std::string_view hay, std::string_view needle) {
    if (needle.empty())
        return true;
    if (needle.size() > hay.size())
        return false;
    const unsigned char first = kLower.v[static_cast<unsigned char>(needle[0])];
    const size_t last = hay.size() - needle.size();
    for (size_t i = 0; i <= last; ++i) {
        if (kLower.v[static_cast<unsigned char>(hay[i])] != first)
            continue;
        size_t j = 1;
        while (j < needle.size() &&
               kLower.v[static_cast<unsigned char>(hay[i + j])] ==
                   kLower.v[static_cast<unsigned char>(needle[j])])
            ++j;
        if (j == needle.size())
            return true;
    }
    return false;
}

std::string NormalizeDisasm(std::string s) {
    while (!s.empty()) {
        const char c = s.back();
        if (c == ' ' || c == ';')
            s.pop_back();
        else
            break;
    }
    return s;
}

// --- Hex -------------------------------------------------------------------

namespace {

int HexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

bool ParseHexBytes(std::string_view input, std::vector<uint8_t>& out) {
    out.clear();
    bool ok = true;
    size_t i = 0;
    const size_t n = input.size();
    while (i < n) {
        while (i < n && (input[i] == ' ' || input[i] == ',' || input[i] == ';' ||
                         input[i] == '\t'))
            ++i;
        if (i >= n)
            break;
        if (input[i] == '0' && i + 1 < n &&
            (input[i + 1] == 'x' || input[i + 1] == 'X')) {
            i += 2;
        }
        int hi = HexDigit(input[i]);
        if (hi < 0) {
            ok = false;
            break;
        }
        int lo = -1;
        if (i + 1 < n) {
            lo = HexDigit(input[i + 1]);
        }
        if (lo >= 0 &&
            !(i + 2 < n && HexDigit(input[i + 2]) >= 0 &&
              input[i + 2] != ' ' && input[i + 2] != ',')) {
            // two-digit token
            out.push_back(static_cast<uint8_t>((hi << 4) | lo));
            i += 2;
        } else if (lo < 0 || input[i + 1] == ' ' || input[i + 1] == ',') {
            // single-digit token
            out.push_back(static_cast<uint8_t>(hi));
            i += 1;
        } else {
            // three or more digits jammed together: consume in pairs
            out.push_back(static_cast<uint8_t>((hi << 4) | lo));
            i += 2;
            while (i + 1 < n && HexDigit(input[i]) >= 0 && HexDigit(input[i + 1]) >= 0) {
                out.push_back(static_cast<uint8_t>(
                    (HexDigit(input[i]) << 4) | HexDigit(input[i + 1])));
                i += 2;
            }
        }
    }
    return ok;
}

std::string BytesToHex(const uint8_t* data, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 3);
    for (size_t i = 0; i < len; ++i) {
        if (i)
            out += ' ';
        out += kHex[data[i] >> 4];
        out += kHex[data[i] & 0xF];
    }
    return out;
}

std::string FormatAddress(uint64_t address, bool is64) {
    char buf[32];
    if (is64)
        std::snprintf(buf, sizeof(buf), "0x%016llx",
                      static_cast<unsigned long long>(address));
    else
        std::snprintf(buf, sizeof(buf), "0x%08llx",
                      static_cast<unsigned long long>(address));
    return buf;
}

// --- Paths -----------------------------------------------------------------

bool HasPeExtension(const std::filesystem::path& p) {
    static constexpr std::string_view kExts[] = {
        ".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl", ".efi", ".scr", ".acm"
    };
    std::string ext = ToLower(p.extension().string());
    for (auto e : kExts)
        if (ext == e)
            return true;
    return false;
}

namespace {

template <typename T>
bool ReadAt(HANDLE file, int64_t offset, T& out) {
    LARGE_INTEGER li;
    li.QuadPart = offset;
    DWORD read_ = 0;
    if (!::SetFilePointerEx(file, li, nullptr, FILE_BEGIN))
        return false;
    if (!::ReadFile(file, &out, sizeof(T), &read_, nullptr) || read_ != sizeof(T))
        return false;
    return true;
}

} // namespace

util::BinarySniff SniffBinary(const std::filesystem::path& p) {
    BinarySniff sniff;

    // One open, short reads, one close. The previous implementation opened
    // the file up to three times per candidate (magic, PE machine, ELF
    // machine) and the engine then statted the file again for its size.
    HANDLE file = ::CreateFileW(p.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL |
                                                   FILE_FLAG_SEQUENTIAL_SCAN,
                                nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return sniff;

    LARGE_INTEGER size{};
    if (::GetFileSizeEx(file, &size))
        sniff.fileSize = static_cast<uint64_t>(size.QuadPart);

    uint8_t magic[8] = {};
    DWORD read_ = 0;
    if (!::ReadFile(file, magic, sizeof(magic), &read_, nullptr) || read_ < 4) {
        ::CloseHandle(file);
        return sniff; // kind stays Unknown
    }

    if (magic[0] == 'M' && magic[1] == 'Z') {
        int32_t lfanew = 0;
        uint32_t peSig = 0;
        uint16_t machine = 0;
        const bool ok = ReadAt<int32_t>(file, 0x3C, lfanew) &&
                        lfanew > 0 && lfanew < 0x100000 &&
                        ReadAt<uint32_t>(file, lfanew, peSig) &&
                        peSig == 0x00004550 &&
                        ReadAt<uint16_t>(file, lfanew + 4, machine);
        if (ok) {
            switch (machine) {
            case 0x8664: sniff.arch = kArchX64; break;
            case 0x014c: sniff.arch = kArchX86; break;
            case 0x01c0: sniff.arch = kArchArm; break;
            case 0xaa64: sniff.arch = kArchArm64; break;
            default: break;
            }
        }
        ::CloseHandle(file);
        sniff.kind = BinaryKind::Pe;
        return sniff;
    }

    if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' &&
        magic[3] == 'F') {
        const uint8_t cls = magic[4];
        const uint8_t dataEnc = magic[5];
        uint16_t machine = 0;
        if (ReadAt<uint16_t>(file, 18, machine)) {
            const uint16_t m = (dataEnc == 1) ? machine : _byteswap_ushort(machine);
            // 3 = x86, 62 = x86-64, 40 = arm, 183 = aarch64
            if (m == 3) sniff.arch = cls == 2 ? kArchX64 : kArchX86;
            else if (m == 62) sniff.arch = kArchX64;
            else if (m == 40) sniff.arch = kArchArm;
            else if (m == 183) sniff.arch = kArchArm64;
        }
        ::CloseHandle(file);
        sniff.kind = BinaryKind::Elf;
        return sniff;
    }

    ::CloseHandle(file);

    const uint32_t m32 = (static_cast<uint32_t>(magic[0]) << 24) |
                         (static_cast<uint32_t>(magic[1]) << 16) |
                         (static_cast<uint32_t>(magic[2]) << 8) |
                         static_cast<uint32_t>(magic[3]);
    switch (m32) {
    case 0xfeedface:
    case 0xcefaedfe:
    case 0xfeedfacf:
    case 0xcffaedfe:
        sniff.kind = BinaryKind::MachO;
        break;
    default:
        break;
    }
    return sniff;
}

BinaryKind SniffBinaryKind(const std::filesystem::path& p, std::string& archOut) {
    archOut = kArchUnknown;
    const BinarySniff sniff = SniffBinary(p);
    if (!sniff.arch.empty())
        archOut = sniff.arch;
    return sniff.kind;
}

std::string ToLibrpPath(const std::filesystem::path& p, std::filesystem::path& staged) {
    staged.clear();
    std::string narrow = p.string(); // native narrow (ACP) conversion; may throw

    // Fast path: plain ASCII (no high bytes) always round-trips exactly.
    bool ascii = true;
    for (unsigned char c : narrow)
        if (c >= 0x80) { ascii = false; break; }
    if (ascii)
        return narrow;

    // Verify the narrow string round-trips back to the same wide path.
    int wideLen = ::MultiByteToWideChar(CP_ACP, 0, narrow.c_str(), -1, nullptr, 0);
    std::wstring back(static_cast<size_t>(wideLen > 0 ? wideLen - 1 : 0), L'\0');
    if (wideLen > 0)
        ::MultiByteToWideChar(CP_ACP, 0, narrow.c_str(), -1, back.data(), wideLen);

    if (back == p.wstring())
        return narrow;

    // Lossy path: stage an ASCII-named copy in %TEMP% and hand that to librp.
    wchar_t tempDir[MAX_PATH * 2] = {};
    ::GetTempPathW(static_cast<DWORD>(std::size(tempDir)), tempDir);
    std::filesystem::path staging = tempDir;
    staging /= L"TotalGadgets";
    std::error_code ec;
    std::filesystem::create_directories(staging, ec);
    if (ec)
        return narrow; // best effort; librp will fail with a clear error

    static std::atomic<uint64_t> counter{0};
    staged = staging /
             (L"stage_" + std::to_wstring(::GetCurrentProcessId()) + L"_" +
              std::to_wstring(counter.fetch_add(1)) + p.extension().wstring());
    if (!::CopyFileW(p.c_str(), staged.c_str(), FALSE))
        return narrow;

    return staged.string();
}

// --- Formatting ------------------------------------------------------------

std::string HumanBytes(uint64_t bytes) {
    char buf[32];
    if (bytes >= 1024ull * 1024 * 1024)
        std::snprintf(buf, sizeof(buf), "%.2f GB", bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024ull * 1024)
        std::snprintf(buf, sizeof(buf), "%.1f MB", bytes / (1024.0 * 1024));
    else if (bytes >= 1024)
        std::snprintf(buf, sizeof(buf), "%.1f KB", bytes / 1024.0);
    else
        std::snprintf(buf, sizeof(buf), "%llu B",
                      static_cast<unsigned long long>(bytes));
    return buf;
}

std::string FormatElapsed(double seconds) {
    char buf[32];
    auto total = static_cast<uint64_t>(seconds);
    if (total < 60) {
        std::snprintf(buf, sizeof(buf), "%llus",
                      static_cast<unsigned long long>(total));
    } else if (total < 3600) {
        std::snprintf(buf, sizeof(buf), "%llum %02llus",
                      static_cast<unsigned long long>(total / 60),
                      static_cast<unsigned long long>(total % 60));
    } else {
        std::snprintf(buf, sizeof(buf), "%lluh %02llum",
                      static_cast<unsigned long long>(total / 3600),
                      static_cast<unsigned long long>((total % 3600) / 60));
    }
    return buf;
}

std::string FormatCount(uint64_t n) {
    // Digit grouping: "1,234,567" (shell-style counts).
    char raw[24];
    std::snprintf(raw, sizeof(raw), "%llu",
                  static_cast<unsigned long long>(n));
    const size_t len = std::strlen(raw);
    std::string out;
    out.reserve(len + len / 3);
    for (size_t i = 0; i < len; ++i) {
        if (i > 0 && (len - i) % 3 == 0)
            out += ',';
        out += raw[i];
    }
    return out;
}

} // namespace gadgets::util
