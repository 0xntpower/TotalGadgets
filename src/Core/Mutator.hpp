#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include <librp.hpp>

#include "PeFile.hpp"
#include "Types.hpp"

namespace gadgets {

// Mutation 2.0 — second-decoder discovery pass.
//
// Anchors at EVERY terminal-instruction candidate in every executable section
// (ret / ret imm / call reg|mem-reg / jmp reg|mem-reg / syscall / int 0x80 /
// int 0x2e), then disassembles backward windows with capstone. A mutated
// gadget is a sequence that decodes cleanly from a misaligned start and lands
// exactly on the anchor as its final instruction. Results are deduplicated
// against the main pass, so anything reported here was found by capstone but
// not by the main (BeaEngine-based) pass — the genuine "second opinion".
//
// Thread-safe: no globals; parallelism is internal over anchors.
std::vector<librp::GadgetResult>
MutateModule(const PeInfo& pe, const MutationOptions& opts,
             const std::vector<uint8_t>& badBytes,
             const std::unordered_set<std::string>& existingDisasms,
             uint32_t threads, StopToken& stop);

} // namespace gadgets
