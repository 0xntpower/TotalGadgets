#include "Cli.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <mutex>

#include "Core/Engine.hpp"
#include "Core/SelfTest.hpp"
#include "Core/Sink.hpp"
#include "Core/Util.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace gadgets {

namespace {

constexpr const char* kVersion = "2.0.0";

void PrintUsage() {
    std::cout <<
        "Total Gadgets v" << kVersion << " - bulk ROP gadget extraction\n"
        "\n"
        "Usage:\n"
        "  TotalGadgets --cli [options] <folder-or-file> [folder-or-file ...]\n"
        "  TotalGadgets --selftest\n"
        "\n"
        "Options:\n"
        "  -o, --output <path>   Output file (or directory with --split)\n"
        "                        Default: gadgets.txt in the current directory\n"
        "  -f, --format <fmt>    text | json | csv           (default: text)\n"
        "  -r, --recursive       Scan subfolders\n"
        "  -l, --max-len <n>     Max instructions per gadget (default 5)\n"
        "  -t, --threads <n>     Parallelism (default: half the CPU cores)\n"
        "  -u, --unique          Unique gadgets only\n"
        "  -b, --bad-bytes <hex> Space-separated bytes to reject, e.g. \"00 0a\"\n"
        "      --allow-branches  Allow branch instructions inside gadgets\n"
        "      --elf             Also accept ELF binaries (by magic sniffing)\n"
        "  -m, --mutate [=<n>]   Capstone second-decoder pass; n = lookback bytes\n"
        "                        (default 16). Writes <out>_mutated.<ext> unless --split\n"
        "      --mutate-branches Allow branches inside mutated gadgets\n"
        "  -q, --quiet           No per-file log output\n"
        "  -v, --version         Print version\n"
        "  -h, --help            This help\n"
        "\n"
        "Exit codes: 0 ok, 1 scan/write errors, 2 usage error, 130 cancelled (Ctrl+C).\n";
}

struct Args {
    std::vector<std::filesystem::path> targets;
    std::filesystem::path output = "gadgets.txt";
    OutputFormat format = OutputFormat::Text;
    OutputMode mode = OutputMode::SingleFile;
    ScanOptions scan;
    MutationOptions mutation;
    bool outputSet = false;
    bool quiet = false;
    bool selftest = false;
    bool help = false;
    bool version = false;
};

bool ParseArgs(int argc, wchar_t* argv[], Args& a, std::string& err) {
    bool hadMutateValue = false;

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];

        auto nextValue = [&](const wchar_t* what) -> std::wstring {
            if (i + 1 >= argc) {
                err = util::ToUtf8(std::wstring(what)) + " expects a value";
                return {};
            }
            return argv[++i];
        };

        if (arg == L"--cli") {
            // Dispatch marker from WinMain; not an option itself.
        } else if (arg == L"-h" || arg == L"--help") {
            a.help = true;
        } else if (arg == L"-v" || arg == L"--version") {
            a.version = true;
        } else if (arg == L"--selftest") {
            a.selftest = true;
        } else if (arg == L"-o" || arg == L"--output") {
            a.output = nextValue(L"--output");
            a.outputSet = true;
        } else if (arg == L"-f" || arg == L"--format") {
            const auto fmt = util::ToLower(util::ToUtf8(nextValue(L"--format")));
            if (fmt == "text") a.format = OutputFormat::Text;
            else if (fmt == "json") a.format = OutputFormat::Json;
            else if (fmt == "csv") a.format = OutputFormat::Csv;
            else { err = "unknown format: " + fmt; return false; }
        } else if (arg == L"--split") {
            a.mode = OutputMode::PerModule;
        } else if (arg == L"-r" || arg == L"--recursive") {
            a.scan.recursive = true;
        } else if (arg == L"-l" || arg == L"--max-len") {
            a.scan.maxGadgetLen = static_cast<uint32_t>(
                wcstoul(nextValue(L"--max-len").c_str(), nullptr, 10));
            if (a.scan.maxGadgetLen == 0 || a.scan.maxGadgetLen > 50) {
                err = "--max-len must be 1..50";
                return false;
            }
        } else if (arg == L"-t" || arg == L"--threads") {
            a.scan.threads = static_cast<uint32_t>(
                wcstoul(nextValue(L"--threads").c_str(), nullptr, 10));
            if (a.scan.threads == 0 || a.scan.threads > 64) {
                err = "--threads must be 1..64";
                return false;
            }
        } else if (arg == L"-u" || arg == L"--unique") {
            a.scan.uniqueOnly = true;
        } else if (arg == L"-b" || arg == L"--bad-bytes") {
            const auto bytes = nextValue(L"--bad-bytes");
            if (!util::ParseHexBytes(util::ToUtf8(bytes), a.scan.badBytes) ||
                a.scan.badBytes.empty()) {
                err = "--bad-bytes expects hex bytes like \"00 0a\"";
                return false;
            }
        } else if (arg == L"--allow-branches") {
            a.scan.allowBranches = true;
        } else if (arg == L"--elf") {
            a.scan.includeElf = true;
        } else if (arg == L"-m" || arg == L"--mutate" ||
                   arg.rfind(L"-m=", 0) == 0 ||
                   arg.rfind(L"--mutate=", 0) == 0) {
            a.mutation.enabled = true;
            const size_t eq = arg.find(L'=');
            if (eq != std::wstring::npos) {
                a.mutation.lookback =
                    static_cast<uint32_t>(wcstoul(arg.c_str() + eq + 1, nullptr, 10));
                hadMutateValue = true;
                if (a.mutation.lookback == 0 || a.mutation.lookback > 64) {
                    err = "--mutate lookback must be 1..64";
                    return false;
                }
            }
        } else if (arg == L"--mutate-branches") {
            a.mutation.allowBranches = true;
        } else if (arg == L"-q" || arg == L"--quiet") {
            a.quiet = true;
        } else if (!arg.empty() && arg[0] == L'-') {
            err = "unknown option: " + util::ToUtf8(arg);
            return false;
        } else {
            a.targets.push_back(arg);
        }
    }

    if (a.mutation.enabled && !hadMutateValue)
        a.mutation.lookback = 16;

    if (a.mode == OutputMode::PerModule && !a.outputSet) {
        err = "--split requires --output <directory>";
        return false;
    }

    return err.empty();
}

int RunSelfTestCli() {
    std::cout << "Running self-test..." << std::endl;
    auto failures = RunSelfTest();
    if (failures.empty()) {
        std::cout << "All self-test checks passed." << std::endl;
        return 0;
    }
    for (const auto& f : failures)
        std::cout << "FAIL: " << f << std::endl;
    std::cout << failures.size() << " check(s) failed." << std::endl;
    return 1;
}

} // namespace

int CliMain(int argc, wchar_t* argv[]) {
    Args a;
    std::string err;
    if (!ParseArgs(argc, argv, a, err)) {
        std::cerr << "error: " << err << "\n\n";
        PrintUsage();
        return 2;
    }
    if (a.help) {
        PrintUsage();
        return 0;
    }
    if (a.version) {
        std::cout << "Total Gadgets v" << kVersion << std::endl;
        return 0;
    }
    if (a.selftest)
        return RunSelfTestCli();

    if (a.targets.empty()) {
        std::cerr << "error: no input targets given\n\n";
        PrintUsage();
        return 2;
    }

    StopToken stop;
    static StopToken* g_stop = &stop;
    ::SetConsoleCtrlHandler(
        [](DWORD type) -> BOOL {
            if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
                if (g_stop)
                    g_stop->Stop();
                return TRUE;
            }
            return FALSE;
        },
        TRUE);

    const bool isConsole = ::GetConsoleWindow() != nullptr;
    std::mutex printMu;
    std::string lastStatus;

    RunConfig cfg;
    cfg.scan = a.scan;
    cfg.mutation = a.mutation;
    cfg.output.path = a.output;
    cfg.output.format = a.format;
    cfg.output.mode = a.mode;

    Engine engine(cfg, stop, {});
    const Engine* enginePtr = &engine;

    RunCallbacks cbs;
    cbs.onLog = [&](const std::string& msg) {
        if (a.quiet || !isConsole)
            return;
        std::lock_guard<std::mutex> lock(printMu);
        if (!lastStatus.empty()) { // wipe the progress line
            std::cout << "\r" << std::string(lastStatus.size(), ' ') << "\r";
            lastStatus.clear();
        }
        std::cout << msg << "\n";
    };
    cbs.onProgressChanged = [&, enginePtr] {
        if (a.quiet || !isConsole)
            return;
        std::lock_guard<std::mutex> lock(printMu);
        const auto snap = enginePtr->Snapshot();
        if (snap.filesTotal == 0)
            return;
        const int pct = snap.bytesTotal > 0
                            ? static_cast<int>(snap.bytesDone * 100 / snap.bytesTotal)
                            : 0;
        std::string line = "  [" + std::to_string(pct) + "%] " +
                           std::to_string(snap.filesDone) + "/" +
                           std::to_string(snap.filesTotal) + " files, " +
                           std::to_string(snap.gadgetsFound) + " gadgets";
        if (snap.phase == Phase::Mutating)
            line += " (mutating)";
        if (!snap.currentFile.empty())
            line += " - " + util::ToUtf8(snap.currentFile);
        if (line.size() > 100)
            line.resize(100);
        std::cout << "\r" << line;
        if (line.size() < lastStatus.size())
            std::cout << std::string(lastStatus.size() - line.size(), ' ');
        std::cout.flush();
        lastStatus = line;
    };
    engine.SetCallbacks(cbs);

    if (!a.quiet)
        std::cout << "Total Gadgets v" << kVersion << " - scanning "
                  << a.targets.size() << " target(s)\n";

    auto stats = engine.Run(a.targets);

    if (!a.quiet && !lastStatus.empty())
        std::cout << "\n";

    if (stats.cancelled) {
        std::cout << "Cancelled. Partial output written.\n";
        return 130;
    }

    std::cout << "Modules scanned: " << stats.filesScanned
              << ", gadgets: " << stats.gadgetsFound;
    if (a.mutation.enabled)
        std::cout << ", mutated: " << stats.mutatedFound;
    std::cout << "\n";

    if (stats.filesFailed > 0 || !stats.outputWritten) {
        std::cerr << "Completed with errors.\n";
        return 1;
    }
    return 0;
}

} // namespace gadgets
