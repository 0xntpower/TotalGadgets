#pragma once

namespace gadgets {

// Console frontend. Returns process exit code: 0 = ok, 1 = scan/write
// errors or failed selftest, 2 = usage error.
int CliMain(int argc, wchar_t* argv[]);

} // namespace gadgets
