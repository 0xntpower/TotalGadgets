#pragma once

#include <memory>
#include <string>

#include "Types.hpp"

namespace gadgets {

// Streaming gadget output. Modules are written as they complete (completion
// order); totals land in a trailer so partial output from a cancelled scan is
// still a well-formed file. All methods are thread-safe.
class IGadgetSink {
public:
    virtual ~IGadgetSink() = default;

    // Writes one module's gadgets. Returns a human-readable error string on
    // failure, empty on success.
    virtual std::string WriteModule(const ModuleGadgets& mod, bool mutated) = 0;

    // Finalizes the output (trailer/flush/close).
    virtual std::string Finish(bool cancelled, uint32_t modulesWritten,
                               size_t gadgetsWritten) = 0;

    uint32_t ModulesWritten() const { return modulesWritten_; }
    size_t GadgetsWritten() const { return gadgetsWritten_; }

protected:
    uint32_t modulesWritten_ = 0;
    size_t gadgetsWritten_ = 0;
};

// Creates a sink per OutputOptions. `mutated` selects the `_mutated` filename
// suffix (both modes). Returns nullptr with `error` set on unusable options.
std::unique_ptr<IGadgetSink> CreateSink(const OutputOptions& opts, bool mutated,
                                        std::string& error);

const wchar_t* ExtensionForFormat(OutputFormat format);

} // namespace gadgets
