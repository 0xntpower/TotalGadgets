#pragma once

#include <string>
#include <vector>

namespace gadgets {

// Runs the built-in regression suite against synthetic PE images. Each entry
// is a failure description; empty vector = all passed.
std::vector<std::string> RunSelfTest();

} // namespace gadgets
