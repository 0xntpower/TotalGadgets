#include "SelfTest.hpp"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <unordered_set>

#include "Engine.hpp"
#include "Mutator.hpp"
#include "PeFile.hpp"
#include "Sink.hpp"
#include "Util.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace gadgets {

namespace {

struct Fail {
    std::vector<std::string>* out;
    void operator()(std::string msg) const { out->push_back(std::move(msg)); }
};

// ---------------------------------------------------------------------------
// Synthetic PE builder (minimal single-.text image)
// ---------------------------------------------------------------------------

#pragma pack(push, 1)
struct SyntheticPe {
    IMAGE_DOS_HEADER dos;
    uint32_t peSig;
    IMAGE_FILE_HEADER fileHeader;
    IMAGE_OPTIONAL_HEADER64 opt64;
    IMAGE_SECTION_HEADER section;
};
#pragma pack(pop)

std::vector<uint8_t> BuildPe(bool x64, uint64_t imageBase,
                             const std::vector<uint8_t>& text) {
    std::vector<uint8_t> raw(sizeof(SyntheticPe) + text.size(), 0);
    auto* pe = reinterpret_cast<SyntheticPe*>(raw.data());

    pe->dos.e_magic = IMAGE_DOS_SIGNATURE;
    pe->dos.e_lfanew = offsetof(SyntheticPe, peSig);

    pe->peSig = IMAGE_NT_SIGNATURE;
    pe->fileHeader.Machine = x64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    pe->fileHeader.NumberOfSections = 1;
    pe->fileHeader.SizeOfOptionalHeader = x64 ? sizeof(IMAGE_OPTIONAL_HEADER64)
                                              : sizeof(IMAGE_OPTIONAL_HEADER32);
    pe->fileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;

    // Overlay the right optional header for 32-bit (the struct has the 64-bit
    // one; sizes differ, so patch the layout manually below).
    const size_t optOff = offsetof(SyntheticPe, opt64);
    const size_t secOff = offsetof(SyntheticPe, section);
    const size_t headerSize = x64 ? sizeof(SyntheticPe)
                                  : optOff + sizeof(IMAGE_OPTIONAL_HEADER32) +
                                        (secOff - optOff - sizeof(IMAGE_OPTIONAL_HEADER64));

    if (x64) {
        pe->opt64.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        pe->opt64.ImageBase = imageBase;
        pe->opt64.SectionAlignment = 0x1000;
        pe->opt64.FileAlignment = 0x200;
        pe->opt64.SizeOfHeaders = static_cast<uint32_t>(headerSize);
        pe->opt64.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    } else {
        // Layout the 32-bit optional header inside the same buffer.
        auto* opt32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(raw.data() + optOff);
        opt32->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        opt32->ImageBase = static_cast<uint32_t>(imageBase);
        opt32->SectionAlignment = 0x1000;
        opt32->FileAlignment = 0x200;
        opt32->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        // Move the section header down to follow the shorter optional header.
        std::memmove(raw.data() + optOff + sizeof(IMAGE_OPTIONAL_HEADER32),
                     raw.data() + secOff, sizeof(IMAGE_SECTION_HEADER));
        pe->fileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
        raw.resize(optOff + sizeof(IMAGE_OPTIONAL_HEADER32) +
                   sizeof(IMAGE_SECTION_HEADER) + text.size());
    }

    auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        raw.data() + (x64 ? secOff : optOff + sizeof(IMAGE_OPTIONAL_HEADER32)));
    std::memcpy(sec->Name, ".text", 5);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = static_cast<uint32_t>(text.size());
    sec->SizeOfRawData = static_cast<uint32_t>(text.size());
    sec->PointerToRawData = static_cast<uint32_t>(
        (x64 ? sizeof(SyntheticPe)
             : optOff + sizeof(IMAGE_OPTIONAL_HEADER32) + sizeof(IMAGE_SECTION_HEADER)));
    sec->Characteristics =
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    std::memcpy(raw.data() + sec->PointerToRawData, text.data(), text.size());
    return raw;
}

std::filesystem::path WriteTempFile(const std::wstring& name,
                                    const std::vector<uint8_t>& bytes) {
    wchar_t tempDir[MAX_PATH * 2] = {};
    ::GetTempPathW(static_cast<DWORD>(std::size(tempDir)), tempDir);
    auto dir = std::filesystem::path(tempDir) / L"TotalGadgetsSelfTest";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    auto path = dir / name;
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    return path;
}

// Deterministic gadget soup: aligned gadgets + misalignment fodder.
std::vector<uint8_t> SampleText() {
    return {
        // 0x00: xor rax, rax ; ret                       (aligned gadget)
        0x48, 0x31, 0xC0, 0xC3,
        // 0x04: pop rax ; pop rbx ; ret                  (aligned gadget)
        0x58, 0x5B, 0xC3,
        // 0x07: jmp rbx                                  (aligned ending)
        0xFF, 0xE3,
        // 0x09: mov eax, 0xc3c3c3c3 ; xor rax, rax ; ret (imm swallows nothing; aligned)
        0xB8, 0xC3, 0xC3, 0xC3, 0xC3,
        0x48, 0x31, 0xC0, 0xC3,
        // 0x12: misalignment fodder: 41 58 C3  -> back-1 from C3 gives
        //       58 C3 ("pop rax ; ret") which the main pass also finds;
        //       back-2 gives 41 58 C3 ("pop r8 ; ret") - x64-only novelty
        0x41, 0x58, 0xC3,
        // 0x15: call rax ending
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,
        // 0x1B: syscall ending (x64)
        0x48, 0x31, 0xC0,
        0x0F, 0x05,
        // padding
        0x90, 0x90, 0x90, 0x90,
    };
}

} // namespace

std::vector<std::string> RunSelfTest() {
    std::vector<std::string> failures;
    Fail fail{&failures};

    const std::vector<uint8_t> text = SampleText();

    // ------------------------------------------------------------------
    // 1. Engine end-to-end (x64): scan + mutation + sinks, all formats
    // ------------------------------------------------------------------
    {
        const uint64_t kBase = 0x180000000;
        auto peBytes = BuildPe(true, kBase, text);
        auto dir = WriteTempFile(L"selftest64.dll", peBytes).parent_path();

        RunConfig cfg;
        cfg.scan.maxGadgetLen = 5;
        cfg.scan.threads = 2;
        cfg.mutation.enabled = true;
        cfg.mutation.lookback = 4;
        cfg.output.path = dir / L"out64.txt";
        cfg.output.format = OutputFormat::Text;

        StopToken stop;
        Engine engine(cfg, stop, {});
        auto stats = engine.Run({dir});

        if (stats.filesFound != 1)
            fail("x64: expected 1 file found, got " + std::to_string(stats.filesFound));
        if (stats.filesScanned != 1)
            fail("x64: expected 1 file scanned, got " +
                 std::to_string(stats.filesScanned));
        if (stats.filesFailed != 0)
            fail("x64: scan reported failures");
        if (stats.gadgetsFound == 0)
            fail("x64: main pass found no gadgets");

        const auto& results = engine.Results();
        if (results.size() != 1 || results[0].arch != kArchX64)
            fail("x64: module result missing or arch wrong");
        if (results[0].imageBase != kBase)
            fail("x64: image base not picked up");
        for (const auto& g : results[0].gadgets) {
            if (g.address < kBase + 0x1000 || g.address >= kBase + 0x1000 + text.size())
                fail("x64: gadget address outside .text: " +
                     util::FormatAddress(g.address, true));
        }

        // Mutation invariants: no dupes vs main pass, addresses in range,
        // every mutated gadget has >= 2 instructions.
        std::unordered_set<std::string> mainDisasms;
        for (const auto& g : results[0].gadgets)
            mainDisasms.insert(g.disassembly);

        for (const auto& mod : engine.MutatedResults()) {
            for (const auto& g : mod.gadgets) {
                if (mainDisasms.count(g.disassembly))
                    fail("x64: mutated gadget duplicates main pass: " + g.disassembly);
                if (g.address < kBase + 0x1000 ||
                    g.address >= kBase + 0x1000 + text.size())
                    fail("x64: mutated address outside .text: " +
                         util::FormatAddress(g.address, true));
                if (g.disassembly.find(" ; ") == std::string::npos)
                    fail("x64: mutated gadget shorter than 2 insns: " + g.disassembly);
            }
        }

        // Text sink output sanity.
        std::ifstream in(cfg.output.path);
        std::string content((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
        if (content.find("[selftest64.dll]") == std::string::npos)
            fail("x64: text output missing module prefix");
        if (content.find("0x0000000180") == std::string::npos)
            fail("x64: text output missing 64-bit-width addresses");
        if (content.find("; Total gadgets: ") == std::string::npos)
            fail("x64: text output missing trailer");
    }

    // ------------------------------------------------------------------
    // 2. x86 engine pass + address width
    // ------------------------------------------------------------------
    {
        const uint32_t kBase32 = 0x400000;
        auto peBytes = BuildPe(false, kBase32, text);
        auto path = WriteTempFile(L"selftest32.dll", peBytes);

        RunConfig cfg;
        cfg.mutation.enabled = false;
        cfg.output.path = path.parent_path() / L"out32.txt";
        cfg.output.format = OutputFormat::Text;

        StopToken stop;
        Engine engine(cfg, stop, {});
        auto stats = engine.Run({path});

        if (stats.filesScanned != 1)
            fail("x86: expected 1 file scanned, got " +
                 std::to_string(stats.filesScanned));
        const auto& results = engine.Results();
        if (results.empty() || results[0].arch != kArchX86)
            fail("x86: arch not detected as x86");
        if (!results.empty() && results[0].imageBase != kBase32)
            fail("x86: image base wrong: " +
                 std::to_string(results[0].imageBase));

        std::ifstream in(cfg.output.path);
        std::string content((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
        if (content.find("0x0040") == std::string::npos)
            fail("x86: text output missing 32-bit-width addresses");
    }
    // ------------------------------------------------------------------
    // 3. JSON + CSV sinks
    // ------------------------------------------------------------------
    {
        auto peBytes = BuildPe(true, 0x180000000, text);
        auto path = WriteTempFile(L"selftest_fmt.dll", peBytes);

        RunConfig cfg;
        cfg.mutation.enabled = false;
        cfg.output.format = OutputFormat::Json;
        cfg.output.path = path.parent_path() / L"out.json";
        {
            StopToken stop;
            Engine engine(cfg, stop, {});
            engine.Run({path});
        }
        std::ifstream in(cfg.output.path);
        std::string content((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
        if (content.rfind("{\"generator\"", 0) != 0)
            fail("json: bad document start");
        if (content.find("\"modules\":[") == std::string::npos)
            fail("json: modules array missing");
        if (content.find("\"disassembly\"") == std::string::npos)
            fail("json: gadget objects missing");
        if (content.find("\"totalGadgets\":") == std::string::npos)
            fail("json: totals missing");

        cfg.output.format = OutputFormat::Csv;
        cfg.output.path = path.parent_path() / L"out.csv";
        {
            StopToken stop;
            Engine engine(cfg, stop, {});
            engine.Run({path});
        }
        std::ifstream in2(cfg.output.path);
        std::string csv((std::istreambuf_iterator<char>(in2)),
                        std::istreambuf_iterator<char>());
        if (csv.compare(0, 6, "module") != 0)
            fail("csv: header missing");
        const size_t rows = std::count(csv.begin(), csv.end(), '\n');
        if (rows < 2)
            fail("csv: no data rows");
    }

    // ------------------------------------------------------------------
    // 4. Bad-byte filtering
    // ------------------------------------------------------------------
    {
        auto peBytes = BuildPe(true, 0x180000000, text);
        auto path = WriteTempFile(L"selftest_bad.dll", peBytes);

        // Discover the "pop rax ; pop rbx ; ret" gadget's address first.
        uint64_t popGadgetVa = 0;
        {
            RunConfig cfg;
            cfg.mutation.enabled = false;
            cfg.output.path = path.parent_path() / L"out_bad_probe.txt";
            StopToken stop;
            Engine engine(cfg, stop, {});
            engine.Run({path});
            for (const auto& mod : engine.Results())
                for (const auto& g : mod.gadgets)
                    if (g.disassembly.rfind("pop rax ; pop rbx ; ret", 0) == 0)
                        popGadgetVa = g.address;
        }
        if (popGadgetVa == 0) {
            fail("badbytes: probe could not find the pop gadget");
        } else {
            // librp semantics: bad bytes are checked against the gadget's
            // low-4 address bytes. Pick one of those bytes as the filter.
            const uint8_t bad = static_cast<uint8_t>(popGadgetVa & 0xff);
            RunConfig cfg;
            cfg.scan.badBytes = {bad};
            cfg.mutation.enabled = false;
            cfg.output.path = path.parent_path() / L"out_bad.txt";

            StopToken stop;
            Engine engine(cfg, stop, {});
            engine.Run({path});

            for (const auto& mod : engine.Results())
                for (const auto& g : mod.gadgets)
                    if (g.address == popGadgetVa)
                        fail("badbytes: gadget at filtered address leaked: " +
                             util::FormatAddress(g.address, true));
        }
    }

    // ------------------------------------------------------------------
    // 5. Cancellation: pre-set token aborts before scanning
    // ------------------------------------------------------------------
    {
        auto peBytes = BuildPe(true, 0x180000000, text);
        auto path = WriteTempFile(L"selftest_cancel.dll", peBytes);

        RunConfig cfg;
        cfg.mutation.enabled = false;
        cfg.output.path = path.parent_path() / L"out_cancel.txt";

        StopToken stop;
        stop.Stop();
        Engine engine(cfg, stop, {});
        auto stats = engine.Run({path});
        if (!stats.cancelled)
            fail("cancel: stats.cancelled not set");
        if (stats.filesScanned != 0)
            fail("cancel: files were scanned despite pre-set stop token");
    }

    // ------------------------------------------------------------------
    // 6. ParseHexBytes
    // ------------------------------------------------------------------
    {
        std::vector<uint8_t> out;
        if (!util::ParseHexBytes("00 0a 0d", out) || out.size() != 3 ||
            out[0] != 0x00 || out[1] != 0x0A || out[2] != 0x0D)
            fail("hex: simple parse failed");
        if (!util::ParseHexBytes("ff", out) || out.size() != 1 || out[0] != 0xFF)
            fail("hex: single byte parse failed");
        if (util::ParseHexBytes("zz", out))
            fail("hex: garbage accepted");
    }

    // Cleanup
    {
        std::error_code ec;
        wchar_t tempDir[MAX_PATH * 2] = {};
        ::GetTempPathW(static_cast<DWORD>(std::size(tempDir)), tempDir);
        std::filesystem::remove_all(
            std::filesystem::path(tempDir) / L"TotalGadgetsSelfTest", ec);
    }

    return failures;
}

} // namespace gadgets
