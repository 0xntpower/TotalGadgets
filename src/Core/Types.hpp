#pragma once

#include <functional>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

#include <librp.hpp>

namespace gadgets {

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

class StopToken {
public:
    void Stop() { stop_.store(true, std::memory_order_relaxed); }
    bool Stopped() const { return stop_.load(std::memory_order_relaxed); }
    void Reset() { stop_.store(false, std::memory_order_relaxed); }

private:
    std::atomic<bool> stop_{false};
};

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

struct ScanOptions {
    uint32_t maxGadgetLen = 5;
    uint32_t threads = 0; // 0 = auto (half the hardware threads, 1..16)
    bool uniqueOnly = false;
    bool allowBranches = false;   // allow mid-gadget branches in the librp pass
    bool recursive = false;
    bool includeElf = false;      // accept ELF / Mach-O files, not just PE extensions
    std::vector<uint8_t> badBytes;
};

struct MutationOptions {
    bool enabled = false;
    uint32_t lookback = 16;       // bytes to walk back from each terminator
    uint32_t maxGadgetLen = 5;    // instruction cap for mutated gadgets
    bool allowBranches = false;   // allow mid-gadget branches in the mutation pass
};

enum class OutputFormat { Text, Json, Csv };
enum class OutputMode { SingleFile, PerModule };

struct OutputOptions {
    std::filesystem::path path;   // output file (SingleFile) or directory (PerModule)
    OutputFormat format = OutputFormat::Text;
    OutputMode mode = OutputMode::SingleFile;
};

struct RunConfig {
    ScanOptions scan;
    MutationOptions mutation;
    OutputOptions output;
};

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

inline constexpr const char* kArchX86 = "x86";
inline constexpr const char* kArchX64 = "x64";
inline constexpr const char* kArchArm = "arm";
inline constexpr const char* kArchArm64 = "arm64";
inline constexpr const char* kArchUnknown = "?";

struct ModuleGadgets {
    std::string moduleName;                // display name (original file name)
    std::filesystem::path filePath;        // original path (may be a staged temp copy)
    std::string arch = kArchUnknown;       // discovered architecture
    uint64_t imageBase = 0;
    std::vector<librp::GadgetResult> gadgets;
};

// ---------------------------------------------------------------------------
// Progress / stats
// ---------------------------------------------------------------------------

enum class Phase { Idle, Enumerating, Scanning, Mutating, Done, Cancelled, Failed };

struct ProgressSnapshot {
    Phase phase = Phase::Idle;
    std::wstring currentFile;
    uint32_t filesDone = 0;
    uint32_t filesTotal = 0;
    uint64_t bytesDone = 0;
    uint64_t bytesTotal = 0;
    size_t gadgetsFound = 0;
    size_t mutatedFound = 0;
};

struct ScanStats {
    uint32_t filesFound = 0;
    uint32_t filesScanned = 0;
    uint32_t filesSkipped = 0;    // invalid magic / unsupported
    uint32_t filesFailed = 0;     // librp errors
    uint64_t bytesScanned = 0;
    size_t gadgetsFound = 0;
    size_t mutatedFound = 0;
    bool cancelled = false;
    bool outputWritten = false;
};

struct RunCallbacks {
    // Called from worker threads whenever progress changes. Consumers should
    // only set a dirty flag / signal a condition variable, not touch UI.
    std::function<void()> onProgressChanged;
    // Called from worker threads for informational lines (UTF-8).
    std::function<void(const std::string&)> onLog;
};

// ---------------------------------------------------------------------------
// Progress tracker (internal shared state between engine and its consumers)
// ---------------------------------------------------------------------------

class ProgressTracker {
public:
    void SetPhase(Phase p) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            snap_.phase = p;
        }
        Notify();
    }
    void SetTotal(uint32_t files, uint64_t bytes) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            snap_.filesTotal = files;
            snap_.bytesTotal = bytes;
        }
        Notify();
    }
    void SetCurrentFile(const std::wstring& name) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            snap_.currentFile = name;
        }
        Notify();
    }
    void AddFileDone(uint64_t bytes, size_t gadgets) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            snap_.filesDone++;
            snap_.bytesDone += bytes;
            snap_.gadgetsFound += gadgets;
        }
        Notify();
    }
    void SetGadgets(size_t total) {
        std::lock_guard<std::mutex> lock(mu_);
        snap_.gadgetsFound = total;
    }
    void SetMutated(size_t total) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            snap_.mutatedFound = total;
        }
        Notify();
    }
    void Reset() {
        std::lock_guard<std::mutex> lock(mu_);
        snap_ = ProgressSnapshot{};
    }

    ProgressSnapshot Snapshot() const {
        std::lock_guard<std::mutex> lock(mu_);
        return snap_;
    }

    void SetNotify(std::function<void()> fn) { notify_ = std::move(fn); }

private:
    void Notify() {
        if (notify_)
            notify_();
    }

    mutable std::mutex mu_;
    ProgressSnapshot snap_;
    std::function<void()> notify_;
};

} // namespace gadgets
