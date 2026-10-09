![Windows](https://img.shields.io/badge/platform-Windows-blue)
![C++20](https://img.shields.io/C%2B%2B-20-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green)

# Total Gadgets v2

Bulk ROP gadget extraction for Windows binaries — GUI and CLI in one executable.

Point it at a folder of DLLs/EXEs (or ELF binaries), extract every ROP gadget with
[librp](https://github.com/0xntpower/librp) (rp++ static library), browse the results
in-app with live filtering, and export as rp++-style text, JSON, or CSV.

Optionally run the **mutation pass**: a second-opinion scan with the capstone
disassembler anchored at *every* terminal instruction (ret / ret imm / call & jmp
through register / syscall / int 0x80 / int 0x2e). Anything it finds that the main
(BeaEngine-based) pass missed is reported as a *mutated* gadget — decoder
disagreements, deeper lookback, and looser branch policy all surface here. On a
stock System32 DLL sweep this typically yields **10–20% additional unique gadgets**.

## What's in v2

- **Parallel scanning** — file-level thread pool with byte-weighted progress,
  ETA, and throughput. One huge binary? The whole thread budget goes to librp's
  internal parallelism.
- **Cancellation everywhere** — Cancel button / Ctrl+C stop cleanly between
  files; output already streamed stays valid.
- **Streaming output** — modules are written as they complete; a cancelled or
  crashed run leaves a well-formed partial file.
- **Results browser** — virtual-mode list (handles millions of rows), live
  substring filter over disassembly / module / address, per-module and
  scan-vs-mutated breakdown, Ctrl+C to clipboard.
- **CLI mode** — same engine, scriptable: `TotalGadgets --cli ...` from any
  terminal (exit codes fit pipelines; Ctrl+C cancels gracefully).
- **Three formats** — rp++-style text (default), JSON (with bytes + counts),
  CSV. Single merged file or one file per module (`--split`).
- **Settings persistence + MRU** — options and recent folders survive restarts
  (`%LOCALAPPDATA%\TotalGadgets\settings.ini`).
- **Unicode-safe paths** — wide paths end-to-end; files librp can't address
  directly are transparently staged via an ASCII temp copy.
- **ELF support** — opt-in (`--elf`), detected by magic, scanned by librp.
- **Built-in self-test** — `TotalGadgets --selftest` exercises the engine,
  mutation pass, all sinks, bad-byte filtering, and cancellation against
  synthetic x64 + x86 PEs. No fixtures needed.

## Bad bytes semantics

Matches rp++/librp: a bad byte may not appear in a gadget's **address** (the low
4 address bytes are checked), not in its instruction bytes. Useful for the
classic "no null bytes in the chain" constraint.

## Build

Requires:
- MSVC toolchain
- [vcbuild](https://github.com/0xntpower/vcbuild) (included as submodule at `vcbuild/`)
- [librp](https://github.com/0xntpower/librp) static library (expected at `../librp/build-${ARCH}/Release/librp.lib`)
- [WTL 10](https://sourceforge.net/projects/wtl/) headers (expected at `../vcbuild/gui/external/Include/`)

```
git submodule update --init
python vcbuild/vcbuild.py
```

## CLI

```
TotalGadgets --cli [options] <folder-or-file> [folder-or-file ...]

  -o, --output <path>   Output file (or directory with --split)
  -f, --format <fmt>    text | json | csv           (default: text)
      --split           One output file per module
  -r, --recursive       Scan subfolders
  -l, --max-len <n>     Max instructions per gadget (default 5)
  -t, --threads <n>     Parallelism (default: half the CPU cores)
  -u, --unique          Unique gadgets only
  -b, --bad-bytes <hex> Bad bytes for gadget addresses, e.g. "00 0a"
      --allow-branches  Allow branch instructions inside gadgets
      --elf             Also accept ELF binaries
  -m, --mutate [=<n>]   Capstone second-decoder pass, n = lookback bytes (default 16)
      --mutate-branches Allow branches inside mutated gadgets
  -q, --quiet           No per-file log output
      --selftest        Run the built-in regression suite
```

Exit codes: `0` ok · `1` scan/write errors · `2` usage error · `130` cancelled.

Examples:

```
# Sweep a folder, find everything, JSON out
TotalGadgets --cli -r -f json -m -o out.json C:\dropped\sample

# Gadget chains without nulls in addresses
TotalGadgets --cli -u -b "00 0a" -o chain.txt ntdll.dll

# Regression-check the engine
TotalGadgets --selftest
```

## Architecture

```
src/
  Core/               UI-agnostic engine (no Windows UI types)
    Engine.*          orchestration: enumerate -> parallel scan -> mutate -> sink
    Mutator.*         capstone second-decoder pass (terminator-anchored)
    Sink.*            streaming text/JSON/CSV writers, merged or per-module
    PeFile.*          minimal PE parser (arch, image base, exec sections)
    Settings.*        INI persistence + MRU
    SelfTest.*        synthetic-PE regression suite
    Types.hpp         options, results, progress, StopToken
    Util.*            strings, hex, formatting, binary sniffing, path staging
  App/                frontends
    Main.cpp          WinMain; dispatches to CLI when arguments are present
    Cli.*             console frontend (progress line, Ctrl+C, exit codes)
    MainDlg.*         WTL GUI: options, progress, results grid, log
```

Both frontends share `Core/`; the GUI runs the engine on a worker thread with a
cooperative stop token, the CLI runs it inline.

## Notes & limits

- Mutation pass is PE-only (it maps VAs through PE sections); ELF modules are
  skipped in that phase and logged.
- `SearchBytes`/`SearchInt` from librp are not yet exposed in the UI — future work.
- Results are also kept in memory for the browser view; very large sweeps
  (millions of gadgets) use RAM proportional to output size. The CLI streams to
  disk regardless.

#### GUI
<img width="825" height="773" alt="image" src="https://github.com/user-attachments/assets/2fbe5a33-232a-434c-b231-ee04e1ccabe7" />
