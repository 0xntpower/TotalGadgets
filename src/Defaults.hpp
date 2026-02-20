#pragma once

#include <cstdint>

namespace gadgets {

// Search options
constexpr uint32_t kDefaultMaxGadgetLen = 5;
constexpr uint32_t kDefaultMaxThreads = 2;

// Mutation
constexpr uint32_t kDefaultMutationOffset = 3;
constexpr uint32_t kMinMutationOffset = 1;
constexpr uint32_t kMaxMutationOffset = 8;

// Timer
constexpr uint32_t kElapsedTimerIntervalMs = 500;

// Log font
constexpr int kLogFontSize = -13;
constexpr const wchar_t* kLogFontName = L"Consolas";

} // namespace gadgets
