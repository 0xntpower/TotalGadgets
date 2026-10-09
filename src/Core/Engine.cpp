#include "Engine.hpp"

#include <atomic>
#include <mutex>
#include <thread>

#include "Mutator.hpp"
#include "PeFile.hpp"
#include "Sink.hpp"
#include "Util.hpp"

namespace gadgets {

Engine::Engine(RunConfig config, StopToken& stop, RunCallbacks callbacks)
    : config_(std::move(config)), stop_(stop), cbs_(std::move(callbacks)) {
    if (config_.scan.threads == 0)
        config_.scan.threads = DefaultThreads();
    config_.scan.threads = std::clamp<uint32_t>(config_.scan.threads, 1, 64);
    if (config_.mutation.maxGadgetLen == 0)
        config_.mutation.maxGadgetLen = config_.scan.maxGadgetLen;
    config_.mutation.lookback = std::clamp<uint32_t>(config_.mutation.lookback, 1, 64);

    progress_.SetNotify([this] {
        if (cbs_.onProgressChanged)
            cbs_.onProgressChanged();
    });
}

Engine::~Engine() = default;

uint32_t Engine::DefaultThreads() {
    const unsigned hw = std::thread::hardware_concurrency();
    return std::clamp<unsigned>(hw / 2, 1, 16);
}

std::vector<std::filesystem::path>
Engine::EnumerateFiles(const std::vector<std::filesystem::path>& targets,
                       ScanStats& stats) {
    progress_.SetPhase(Phase::Enumerating);

    std::vector<std::filesystem::path> files;
    std::error_code ec;

    for (const auto& target : targets) {
        if (stop_.Stopped())
            break;

        if (std::filesystem::is_regular_file(target, ec)) {
            files.push_back(target);
            continue;
        }
        if (!std::filesystem::is_directory(target, ec)) {
            Log("[SKIP] not a file or folder: " + util::ToUtf8(target.wstring()));
            continue;
        }

        const auto addDir = [&](const std::filesystem::directory_entry& entry) {
            if (!entry.is_regular_file(ec))
                return;
            const auto& p = entry.path();
            if (util::HasPeExtension(p))
                files.push_back(p);
            else if (config_.scan.includeElf) {
                std::string arch;
                if (util::SniffBinaryKind(p, arch) == util::BinaryKind::Elf)
                    files.push_back(p);
            }
        };

        if (config_.scan.recursive) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(
                     target, std::filesystem::directory_options::skip_permission_denied,
                     ec))
                addDir(entry);
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(
                     target, std::filesystem::directory_options::skip_permission_denied,
                     ec))
                addDir(entry);
        }
    }

    // Dedupe + stable order for reproducible runs.
    std::sort(files.begin(), files.end());
    files.erase(std::unique(files.begin(), files.end()), files.end());

    stats.filesFound = static_cast<uint32_t>(files.size());
    return files;
}

void Engine::ScanPhase(const std::vector<std::filesystem::path>& files,
                       ScanStats& stats) {
    progress_.SetPhase(Phase::Scanning);

    // Byte-weighted totals for smooth progress.
    uint64_t totalBytes = 0;
    for (const auto& f : files) {
        std::error_code ec;
        totalBytes += std::filesystem::file_size(f, ec);
    }
    progress_.SetTotal(static_cast<uint32_t>(files.size()), totalBytes);

    // One file: give the whole thread budget to librp's internal parallelism.
    // Many files: parallelize at the file level, keep librp single-threaded.
    const uint32_t workers =
        files.size() == 1 ? 1 : std::min<uint32_t>(config_.scan.threads,
                                                   static_cast<uint32_t>(files.size()));
    const uint32_t librpThreads = files.size() == 1 ? config_.scan.threads : 1;

    std::atomic<uint32_t> nextFile{0};
    std::mutex resultsMu;
    std::mutex logMu;

    auto worker = [&]() {
        for (;;) {
            if (stop_.Stopped())
                return;

            const uint32_t idx = nextFile.fetch_add(1, std::memory_order_relaxed);
            if (idx >= files.size())
                return;

            const auto& filePath = files[idx];
            const std::string name = util::ToUtf8(filePath.filename().wstring());
            progress_.SetCurrentFile(filePath.filename().wstring());

            // Validate magic before spending time on a full parse.
            std::string sniffArch;
            const auto kind = util::SniffBinaryKind(filePath, sniffArch);
            if (kind == util::BinaryKind::Unknown) {
                std::lock_guard<std::mutex> lock(logMu);
                Log("[SKIP] " + name + " - unsupported binary format");
                stats.filesSkipped++;
                continue;
            }

            std::error_code ec;
            const uint64_t fileSize = std::filesystem::file_size(filePath, ec);

            // librp takes a narrow path; stage Unicode-hostile paths.
            std::filesystem::path staged;
            std::string librpPath;
            try {
                librpPath = util::ToLibrpPath(filePath, staged);
            } catch (const std::exception&) {
                std::lock_guard<std::mutex> lock(logMu);
                Log("[SKIP] " + name + " - path cannot be encoded");
                stats.filesSkipped++;
                continue;
            }
            if (!staged.empty()) {
                std::lock_guard<std::mutex> lock(resultsMu);
                stagedFiles_.push_back(staged);
            }

            librp::SearchOptions opts;
            opts.maxGadgetLen = config_.scan.maxGadgetLen;
            opts.maxThreads = librpThreads;
            opts.uniqueOnly = config_.scan.uniqueOnly;
            opts.allowBranches = config_.scan.allowBranches;
            opts.badBytes = config_.scan.badBytes;

            auto result = librp::FindGadgets(librpPath, opts);

            ModuleGadgets mg;
            mg.moduleName = name;
            mg.filePath = filePath;
            mg.arch = sniffArch.empty() ? kArchUnknown : sniffArch;

            if (!librp::Succeeded(result)) {
                std::lock_guard<std::mutex> lock(logMu);
                Log("[ERROR] " + name + ": " + librp::GetError(result));
                stats.filesFailed++;
                progress_.AddFileDone(fileSize, 0);
                continue;
            }

            mg.gadgets = std::move(librp::GetValue(result));

            // PE metadata for the mutation pass + address-width formatting.
            if (kind == util::BinaryKind::Pe) {
                PeInfo pe = ParsePeFile(staged.empty() ? filePath : staged);
                if (pe.Ok()) {
                    mg.imageBase = pe.imageBase;
                    mg.arch = pe.arch == PeInfo::Arch::X64 ? kArchX64 : kArchX86;
                }
            }

            {
                std::lock_guard<std::mutex> lock(logMu);
                Log("[OK] " + name + " (" + mg.arch + ", " +
                    util::HumanBytes(fileSize) + "): " +
                    std::to_string(mg.gadgets.size()) + " gadgets");
            }

            size_t gadgetCount = mg.gadgets.size();
            {
                // Sink writes and result bookkeeping share ordering.
                std::lock_guard<std::mutex> lock(sinkMu_);
                if (sink_) {
                    std::string err = sink_->WriteModule(mg, false);
                    if (!err.empty()) {
                        std::lock_guard<std::mutex> lock2(logMu);
                        Log("[ERROR] output: " + err);
                    }
                }
                if (!mg.gadgets.empty())
                    results_.push_back(std::move(mg));
            }

            stats.filesScanned++;
            stats.bytesScanned += fileSize;
            stats.gadgetsFound += gadgetCount;
            progress_.AddFileDone(fileSize, gadgetCount);
        }
    };

    if (workers == 1) {
        worker();
    } else {
        std::vector<std::thread> pool;
        pool.reserve(workers - 1);
        for (uint32_t i = 1; i < workers; ++i)
            pool.emplace_back(worker);
        worker();
        for (auto& t : pool)
            t.join();
    }
}

void Engine::MutationPhase(ScanStats& stats) {
    if (!config_.mutation.enabled || stop_.Stopped())
        return;
    progress_.SetPhase(Phase::Mutating);
    Log("");
    Log("Mutation pass (capstone second-decoder) starting...");

    // PE-only: the mutation engine maps VAs through PE sections.
    std::vector<ModuleGadgets*> candidates;
    for (auto& mod : results_) {
        if (mod.arch == kArchX86 || mod.arch == kArchX64)
            candidates.push_back(&mod);
    }

    progress_.SetTotal(static_cast<uint32_t>(candidates.size()), 0);
    progress_.SetCurrentFile(L"");

    std::atomic<size_t> next{0};
    std::mutex logMu;
    auto worker = [&]() {
        for (;;) {
            if (stop_.Stopped())
                return;
            const size_t idx = next.fetch_add(1, std::memory_order_relaxed);
            if (idx >= candidates.size())
                return;

            ModuleGadgets* mod = candidates[idx];
            progress_.SetCurrentFile(util::ToWide(mod->moduleName));

            auto done = [&] { progress_.AddFileDone(0, 0); };

            // Stage the path if librp's narrow boundary requires it.
            std::filesystem::path staged;
            std::string librpPath;
            try {
                librpPath = util::ToLibrpPath(mod->filePath, staged);
            } catch (const std::exception&) {
                std::lock_guard<std::mutex> lock(logMu);
                Log("[MUTATE] " + mod->moduleName + " - path cannot be encoded");
                done();
                continue;
            }
            if (!staged.empty()) {
                std::lock_guard<std::mutex> lock(sinkMu_);
                stagedFiles_.push_back(staged);
            }

            PeInfo pe = ParsePeFile(staged.empty() ? mod->filePath : staged);
            if (!pe.Ok()) {
                std::lock_guard<std::mutex> lock(logMu);
                Log("[MUTATE] " + mod->moduleName + " - " + pe.error);
                done();
                continue;
            }

            std::unordered_set<std::string> existing;
            existing.reserve(mod->gadgets.size() * 2);
            for (const auto& g : mod->gadgets)
                existing.insert(util::NormalizeDisasm(g.disassembly));

            auto found = MutateModule(pe, config_.mutation, config_.scan.badBytes,
                                      existing, config_.scan.threads, stop_);
            if (found.empty()) {
                done();
                continue;
            }

            ModuleGadgets out;
            out.moduleName = mod->moduleName;
            out.filePath = mod->filePath;
            out.arch = mod->arch;
            out.imageBase = mod->imageBase;
            out.gadgets = std::move(found);

            size_t count = out.gadgets.size();
            {
                std::lock_guard<std::mutex> lock(sinkMu_);
                if (mutatedSink_) {
                    std::string err = mutatedSink_->WriteModule(out, true);
                    if (!err.empty()) {
                        std::lock_guard<std::mutex> lock2(logMu);
                        Log("[ERROR] output: " + err);
                    }
                }
                mutated_.push_back(std::move(out));
            }

            stats.mutatedFound += count;
            progress_.SetMutated(stats.mutatedFound);
            done();
            {
                std::lock_guard<std::mutex> lock(logMu);
                Log("[MUTATE] " + mod->moduleName + ": " + std::to_string(count) +
                    " new gadget(s) capstone found beyond the main pass");
            }
        }
    };


    const uint32_t workers =
        std::min<uint32_t>(config_.scan.threads,
                           std::max<uint32_t>(1, static_cast<uint32_t>(candidates.size())));
    if (workers == 1) {
        worker();
    } else {
        std::vector<std::thread> pool;
        pool.reserve(workers - 1);
        for (uint32_t i = 1; i < workers; ++i)
            pool.emplace_back(worker);
        worker();
        for (auto& t : pool)
            t.join();
    }

    if (stop_.Stopped())
        return;

    Log("Mutation pass complete: " + std::to_string(stats.mutatedFound) +
        " new gadget(s) total.");
}

void Engine::CleanupStaged() {
    std::error_code ec;
    for (const auto& p : stagedFiles_)
        std::filesystem::remove(p, ec);
    stagedFiles_.clear();
}

ScanStats Engine::Run(const std::vector<std::filesystem::path>& targets) {
    ScanStats stats;
    progress_.Reset();
    results_.clear();
    mutated_.clear();
    stagedFiles_.clear();

    if (targets.empty()) {
        Log("No input targets given.");
        progress_.SetPhase(Phase::Failed);
        return stats;
    }

    // Create sinks up front so a bad output path fails fast.
    std::string sinkErr;
    sink_ = CreateSink(config_.output, false, sinkErr);
    if (!sink_) {
        Log("[ERROR] " + sinkErr);
        progress_.SetPhase(Phase::Failed);
        return stats;
    }
    if (config_.mutation.enabled) {
        mutatedSink_ = CreateSink(config_.output, true, sinkErr);
        if (!mutatedSink_) {
            Log("[ERROR] " + sinkErr);
            progress_.SetPhase(Phase::Failed);
            return stats;
        }
    }

    auto files = EnumerateFiles(targets, stats);
    Log("Found " + std::to_string(files.size()) + " binary file(s).");

    if (files.empty()) {
        stats.cancelled = stop_.Stopped();
        sink_->Finish(stats.cancelled, 0, 0);
        stats.outputWritten = true;
        progress_.SetPhase(stats.cancelled ? Phase::Cancelled : Phase::Done);
        return stats;
    }

    ScanPhase(files, stats);
    MutationPhase(stats);

    const bool cancelled = stop_.Stopped();
    stats.cancelled = cancelled;

    {
        std::lock_guard<std::mutex> lock(sinkMu_);
        std::string err = sink_->Finish(cancelled, sink_->ModulesWritten(),
                                        sink_->GadgetsWritten());
        if (!err.empty())
            Log("[ERROR] output: " + err);
        else
            stats.outputWritten = true;
    }
    if (mutatedSink_) {
        std::lock_guard<std::mutex> lock(sinkMu_);
        std::string err = mutatedSink_->Finish(cancelled, mutatedSink_->ModulesWritten(),
                                               mutatedSink_->GadgetsWritten());
        if (!err.empty())
            Log("[ERROR] output: " + err);
    }

    CleanupStaged();

    Log(std::string(cancelled ? "Scan cancelled. Partial output written."
                              : "Scan complete.") +
        " Modules: " + std::to_string(stats.filesScanned) + ", gadgets: " +
        std::to_string(stats.gadgetsFound) +
        (config_.mutation.enabled
             ? ", mutated: " + std::to_string(stats.mutatedFound)
             : "") +
        ".");
    progress_.SetPhase(cancelled ? Phase::Cancelled : Phase::Done);
    return stats;
}

} // namespace gadgets
