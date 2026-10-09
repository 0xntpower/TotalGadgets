#include "Mutator.hpp"

#include <algorithm>
#include <atomic>
#include <thread>

#include <capstone/capstone.h>

#include "Util.hpp"

namespace gadgets {

namespace {

// ---------------------------------------------------------------------------
// Terminator classification (mirrors librp's intelbeaengine ending rules)
// ---------------------------------------------------------------------------

bool IsGoodEnding(const cs_insn& insn) {
    switch (insn.id) {
    case X86_INS_RET:
    case X86_INS_SYSCALL:
        return true;
    case X86_INS_INT: {
        // accept int 0x80 / int 0x2e only
        return insn.op_str[0] != '\0' &&
               (std::string(insn.op_str) == "0x80" ||
                std::string(insn.op_str) == "0x2e");
    }
    case X86_INS_JMP:
    case X86_INS_CALL: {
        // register or memory-through-register targets only; reject
        // immediates (direct calls/jumps) and rip-relative / absolute
        // memory targets (they resolve at decode time -> not position
        // independent gadgets).
        if (insn.detail == nullptr || insn.detail->x86.op_count == 0)
            return false;
        const auto& op = insn.detail->x86.operands[0];
        if (op.type == X86_OP_REG)
            return true;
        if (op.type == X86_OP_MEM) {
            const bool hasBase = op.mem.base != X86_REG_INVALID;
            const bool ripRelative = op.mem.base == X86_REG_RIP;
            return hasBase && !ripRelative;
        }
        return false;
    }
    default:
        return false;
    }
}

bool IsBranchy(const cs_insn& insn) {
    if (insn.detail == nullptr)
        return false;
    const auto groups = insn.detail->groups;
    for (uint8_t i = 0; i < insn.detail->groups_count; ++i) {
        switch (groups[i]) {
        case CS_GRP_JUMP:
        case CS_GRP_CALL:
        case CS_GRP_RET:
        case CS_GRP_INT:
        case CS_GRP_IRET:
            return true;
        default:
            break;
        }
    }
    return false;
}

// rp++/librp semantics: bad bytes may not appear in the gadget's ADDRESS
// (checked over the low 4 bytes, exactly like librp's
// does_badbytes_filter_apply).
bool AddressHasBadBytes(uint64_t va, const std::vector<uint8_t>& badBytes) {
    for (uint8_t bad : badBytes) {
        if (bad == ((va >> 24) & 0xff) || bad == ((va >> 16) & 0xff) ||
            bad == ((va >> 8) & 0xff) || bad == (va & 0xff))
            return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Anchor enumeration
// ---------------------------------------------------------------------------

struct Anchor {
    const uint8_t* sectionData;   // base of the section's bytes
    size_t sectionSize;
    uint64_t sectionVa;           // VA of section start
    size_t offset;                // anchor offset within section
};

// Collects candidate terminal offsets. Deliberately over-inclusive: the
// capstone decode pass validates each candidate, bad patterns cost nothing.
std::vector<Anchor> CollectAnchors(const PeInfo& pe) {
    std::vector<Anchor> anchors;

    for (const auto& sec : pe.sections) {
        const uint8_t* data = sec.bytes.data();
        const size_t size = sec.bytes.size();
        const uint64_t secVa = pe.imageBase + sec.rva;

        auto push = [&](size_t off) {
            anchors.push_back({data, size, secVa, off});
        };

        for (size_t i = 0; i < size; ++i) {
            const uint8_t b = data[i];
            switch (b) {
            case 0xC3: // ret
            case 0xC2: // ret imm16
                push(i);
                break;
            case 0xFF: { // call/jmp reg, [reg] when /2 or /4
                if (i + 1 < size) {
                    const uint8_t modrm = data[i + 1];
                    const uint8_t reg = (modrm >> 3) & 7;
                    if (reg == 2 || reg == 4)
                        push(i);
                }
                break;
            }
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F: { // REX + FF /2,/4
                if (pe.arch == PeInfo::Arch::X64 && i + 2 < size &&
                    data[i + 1] == 0xFF) {
                    const uint8_t modrm = data[i + 2];
                    const uint8_t reg = (modrm >> 3) & 7;
                    if (reg == 2 || reg == 4)
                        push(i);
                }
                break;
            }
            case 0x0F:
                if (i + 1 < size && data[i + 1] == 0x05) // syscall
                    push(i);
                break;
            case 0xCD:
                if (i + 1 < size && (data[i + 1] == 0x80 || data[i + 1] == 0x2E))
                    push(i);
                break;
            default:
                break;
            }
        }
    }

    return anchors;
}

// ---------------------------------------------------------------------------
// Single-anchor mutation: try every start within `lookback` bytes back
// ---------------------------------------------------------------------------

struct Found {
    uint64_t address;
    std::string disasm;
    std::vector<uint8_t> bytes;
};

void MutateAroundAnchor(const Anchor& a, csh handle, const MutationOptions& opts,
                        const std::vector<uint8_t>& badBytes,
                        std::vector<Found>& out) {
    const uint64_t termVa = a.sectionVa + a.offset;

    const size_t maxBack = std::min<size_t>(opts.lookback, a.offset);
    for (size_t back = 1; back <= maxBack; ++back) {
        const size_t start = a.offset - back;
        // Decode window: from start, enough bytes to reach past the anchor.
        size_t window = std::min(a.sectionSize - start, back + 16);

        cs_insn* insns = nullptr;
        const size_t count =
            cs_disasm(handle, a.sectionData + start, window, a.sectionVa + start, 0, &insns);
        if (count == 0)
            continue;

        std::string disasm;
        size_t totalBytes = 0;
        uint32_t insnCount = 0;
        bool valid = false;

        for (size_t i = 0; i < count; ++i) {
            const cs_insn& insn = insns[i];

            if (insn.address > termVa)
                break; // overshot the anchor

            if (insn.address == termVa) {
                // The anchor itself: it must be a valid ending and there must
                // be at least one instruction before it (a lone terminator is
                // the aligned gadget the main pass already reports).
                valid = (insnCount >= 1) && IsGoodEnding(insn);
                if (valid) {
                    disasm += " ; ";
                    disasm += insn.mnemonic;
                    if (insn.op_str[0] != '\0') {
                        disasm += ' ';
                        disasm += insn.op_str;
                    }
                    totalBytes += insn.size;
                    ++insnCount;
                }
                break;
            }

            // Mid-gadget instruction.
            if (!opts.allowBranches && IsBranchy(insn))
                break;
            if (insnCount >= opts.maxGadgetLen) {
                // no room left for the terminator
                break;
            }

            if (insnCount > 0)
                disasm += " ; ";
            disasm += insn.mnemonic;
            if (insn.op_str[0] != '\0') {
                disasm += ' ';
                disasm += insn.op_str;
            }
            totalBytes += insn.size;
            ++insnCount;
        }

        const uint64_t startVa = a.sectionVa + start;
        if (valid && insnCount >= 2 && insnCount <= opts.maxGadgetLen &&
            !AddressHasBadBytes(startVa, badBytes)) {
            out.push_back({a.sectionVa + start, std::move(disasm),
                           std::vector<uint8_t>(a.sectionData + start,
                                                a.sectionData + start + totalBytes)});
        }

        cs_free(insns, count);
    }
}

} // namespace

std::vector<librp::GadgetResult>
MutateModule(const PeInfo& pe, const MutationOptions& opts,
             const std::vector<uint8_t>& badBytes,
             const std::unordered_set<std::string>& existingDisasms,
             uint32_t threads, StopToken& stop) {
    const cs_mode mode =
        (pe.arch == PeInfo::Arch::X64) ? CS_MODE_64 : CS_MODE_32;

    auto anchors = CollectAnchors(pe);
    if (anchors.empty())
        return {};

    if (threads < 1)
        threads = 1;
    if (threads > static_cast<uint32_t>(anchors.size()))
        threads = static_cast<uint32_t>(anchors.size());

    std::vector<std::vector<Found>> perThread(threads);
    std::atomic<size_t> next{0};

    auto worker = [&](uint32_t tid) {
        csh handle = 0;
        if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
            return;
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        auto& out = perThread[tid];
        for (;;) {
            if (stop.Stopped())
                break;
            const size_t idx = next.fetch_add(1, std::memory_order_relaxed);
            if (idx >= anchors.size())
                break;
            MutateAroundAnchor(anchors[idx], handle, opts, badBytes, out);
        }

        cs_close(&handle);
    };

    if (threads == 1) {
        worker(0);
    } else {
        std::vector<std::thread> pool;
        pool.reserve(threads - 1);
        for (uint32_t t = 1; t < threads; ++t)
            pool.emplace_back(worker, t);
        worker(0);
        for (auto& t : pool)
            t.join();
    }

    // Merge, dedup against the main pass and across threads.
    std::vector<librp::GadgetResult> results;
    std::unordered_set<std::string> seen;
    for (auto& batch : perThread) {
        for (auto& f : batch) {
            if (existingDisasms.count(f.disasm) || !seen.insert(f.disasm).second)
                continue;
            librp::GadgetResult r;
            r.address = f.address;
            r.disassembly = std::move(f.disasm);
            r.bytes = std::move(f.bytes);
            r.numOccurrences = 1;
            results.push_back(std::move(r));
        }
    }

    // Deterministic output order (by address).
    std::sort(results.begin(), results.end(),
              [](const librp::GadgetResult& a, const librp::GadgetResult& b) {
                  return a.address < b.address;
              });
    return results;
}

} // namespace gadgets
