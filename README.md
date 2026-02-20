![Windows](https://img.shields.io/badge/platform-Windows-blue)
![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green)

# Total Gadgets

Bulk ROP gadget extraction and mutation tool for Windows PE binaries. Point it at a folder of DLLs/EXEs, extract all ROP gadgets using [librp](https://github.com/0xntpower/librp), and output them in standard rp++ format. Optionally discover additional gadgets through instruction misalignment mutation — a technique that exploits x86/x64 variable-length encoding by disassembling at negative byte offsets from known gadget addresses.

## Build

Requires:
- [vcbuild](https://github.com/0xntpower/vcbuild) (included as submodule at `vcbuild/`)
- [librp](https://github.com/0xntpower/librp) built as a static library (expected at `../librp/build/Release/librp.lib`)
- [WTL 10](https://sourceforge.net/projects/wtl/) headers (expected at `../vcbuild/gui/external/Include/`)
- Visual Studio 2022 with MSVC toolchain

```
git submodule update --init
python vcbuild/vcbuild.py
```

#### GUI (WTL)
<img width="825" height="773" alt="image" src="https://github.com/user-attachments/assets/2fbe5a33-232a-434c-b231-ee04e1ccabe7" />
