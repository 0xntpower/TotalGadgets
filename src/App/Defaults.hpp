#pragma once

#include <cstdint>

namespace gadgets {

// UI timer cadence while a scan runs (progress + log drain).
constexpr uint32_t kUiTimerIntervalMs = 100;
constexpr UINT_PTR kUiTimerId = 1;

// Filter debounce: re-filtering a million-row list per keystroke would freeze
// the UI; the filter is applied this long after the last edit.
constexpr UINT_PTR kFilterDebounceId = 2;
constexpr UINT kFilterDebounceMs = 150;

// Fonts
constexpr int kMonoFontSize = -13;
constexpr const wchar_t* kMonoFontName = L"Consolas";

// Mutation lookback bounds surfaced by the GUI.
constexpr uint32_t kDefaultMutationLookback = 16;

} // namespace gadgets
