#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace gadgets::util {

// --- Strings ---------------------------------------------------------------

std::wstring ToWide(std::string_view utf8);
std::string ToUtf8(std::wstring_view wide);

// Case-insensitive ASCII substring test.
bool IContains(std::string_view hay, std::string_view needle);
std::string ToLower(std::string_view s);

// --- Hex -------------------------------------------------------------------

// Parses hex byte tokens ("00 0a 0d", "0a,0d", "0a0d" also accepted).
// Returns false if any token is malformed; out is filled with successfully
// parsed bytes up to the first bad token.
bool ParseHexBytes(std::string_view input, std::vector<uint8_t>& out);

std::string BytesToHex(const uint8_t* data, size_t len);

// Formats an address the way rp++ does: 0x%08x for 32-bit, 0x%016x for 64-bit.
std::string FormatAddress(uint64_t address, bool is64);

// Strips trailing separators/whitespace so BeaEngine ("a ; b ; ") and
// capstone ("a ; b") disassembly strings compare equal.
std::string NormalizeDisasm(std::string s);

// --- Paths -----------------------------------------------------------------

// Extensions considered PE binaries on disk.
bool HasPeExtension(const std::filesystem::path& p);

enum class BinaryKind { Unknown, Pe, Elf, MachO };

// What a quick header sniff learns about a file.
struct BinarySniff {
    BinaryKind kind = BinaryKind::Unknown;
    std::string arch;      // kArch* constant, "?" when unknown
    uint64_t fileSize = 0; // valid whenever the file could be opened
};

// Reads only the header fields needed to classify the binary: one file
// open, a few short reads. Never reads section data.
BinarySniff SniffBinary(const std::filesystem::path& p);

// Legacy wrapper kept for callers that only need the kind.
BinaryKind SniffBinaryKind(const std::filesystem::path& p, std::string& archOut);


// Returns a narrow path usable by librp (which opens via std::ifstream on a
// narrow string). If the wide path cannot be represented in the ANSI code
// page, the file is staged to a generated ASCII temp path; the caller must
// keep `staged` alive for the duration of the librp call.
std::string ToLibrpPath(const std::filesystem::path& p, std::filesystem::path& staged);

// --- Formatting ------------------------------------------------------------

std::string HumanBytes(uint64_t bytes);
std::string FormatElapsed(double seconds); // "5s", "1m 02s", "1h 03m"
std::string FormatCount(uint64_t n);       // "1,234,567"

} // namespace gadgets::util
