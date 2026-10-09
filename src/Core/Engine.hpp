#pragma once

#include <memory>
#include <string>
#include <vector>

#include "Types.hpp"

namespace gadgets {

// Orchestrates: enumeration -> parallel scan (librp) -> optional mutation
// pass -> streaming output. One Engine instance per run; Run() blocks until
// done or cancelled.
class Engine {
public:
    Engine(RunConfig config, StopToken& stop, RunCallbacks callbacks);

    // `targets` are files and/or folders; folders are expanded per
    // ScanOptions. Returns final stats. Safe to call from a worker thread.
    ScanStats Run(const std::vector<std::filesystem::path>& targets);

    // Results kept in memory for the GUI (main pass + mutation pass).
    const std::vector<ModuleGadgets>& Results() const { return results_; }
    const std::vector<ModuleGadgets>& MutatedResults() const { return mutated_; }

    ProgressSnapshot Snapshot() const { return progress_.Snapshot(); }

    // Replaces callbacks after construction (used when callbacks need a
    void SetCallbacks(RunCallbacks cbs) { cbs_ = std::move(cbs); }
    static uint32_t DefaultThreads();

    // Defined in the .cpp so the sink type is complete at destruction.
    ~Engine();

private:
    std::vector<std::filesystem::path> EnumerateFiles(
        const std::vector<std::filesystem::path>& targets, ScanStats& stats);
    void ScanPhase(const std::vector<std::filesystem::path>& files, ScanStats& stats);
    void MutationPhase(ScanStats& stats);
    void CleanupStaged();

    void Log(const std::string& msg) {
        if (cbs_.onLog)
            cbs_.onLog(msg);
    }

    RunConfig config_;
    StopToken& stop_;
    RunCallbacks cbs_;
    ProgressTracker progress_;
    std::vector<ModuleGadgets> results_;
    std::vector<ModuleGadgets> mutated_;
    std::vector<std::filesystem::path> stagedFiles_;
    std::mutex sinkMu_;
    std::unique_ptr<class IGadgetSink> sink_;
    std::unique_ptr<class IGadgetSink> mutatedSink_;
};

} // namespace gadgets
