#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <librp.hpp>

#include "Scanner.hpp"

namespace gadgets {

struct MutationConfig {
    uint32_t maxOffset = 4;
    uint32_t maxGadgetLen = 5;
    std::vector<uint8_t> badBytes;
};

using LogCallback = std::function<void(const std::string& message)>;
using ProgressCallback = std::function<void(const std::string& status, int current, int total)>;

std::vector<ModuleGadgets> MutateGadgets(const std::vector<ModuleGadgets>& originals,
                                         const MutationConfig& config,
                                         ProgressCallback onProgress,
                                         LogCallback onLog);

} // namespace gadgets
