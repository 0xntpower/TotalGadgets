#include "Sink.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>

#include "Util.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace gadgets {

namespace {

// Sink I/O buffer: one WriteFile-sized chunk per module instead of one per
// stream op. 1 MB keeps multi-hundred-thousand-gadget modules to a handful
// of syscalls.
constexpr size_t kIoBufferSize = 1 << 20;

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

std::string CsvEscape(const std::string& s) {
    if (s.find_first_of(",\"\n\r") == std::string::npos)
        return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"')
            out += "\"\"";
        else
            out += c;
    }
    out += '"';
    return out;
}

// Sanitizes a module name so it can be used as a file name in PerModule mode.
std::string SanitizeName(const std::string& name) {
    std::string out;
    out.reserve(name.size());
    for (char c : name) {
        if (c == '<' || c == '>' || c == ':' || c == '"' || c == '/' || c == '\\' ||
            c == '|' || c == '?' || c == '*')
            out += '_';
        else
            out += c;
    }
    return out.empty() ? "module" : out;
}

void AppendAddress(std::string& out, uint64_t address, bool is64) {
    char buf[24];
    if (is64)
        std::snprintf(buf, sizeof(buf), "0x%016llx",
                      static_cast<unsigned long long>(address));
    else
        std::snprintf(buf, sizeof(buf), "0x%08llx",
                      static_cast<unsigned long long>(address));
    out += buf;
}

// Opens an ofstream over a caller-owned I/O buffer. pubsetbuf before open is
// the only portable form; the buffer must outlive the stream. Sinks declare
// their buffer member before the stream so destruction order is safe.
bool OpenInto(std::ofstream& out, const std::filesystem::path& path,
              char* buf, size_t bufSize) {
    if (buf)
        out.rdbuf()->pubsetbuf(buf, static_cast<std::streamsize>(bufSize));
    out.open(path, std::ios::binary);
    return out.good();
}

// ---------------------------------------------------------------------------
// Shared module formatting (identical bytes for merged and split outputs)
// ---------------------------------------------------------------------------

std::string FormatTextHead(const ModuleGadgets& mod, bool mutated) {
    std::string head;
    head.reserve(mod.gadgets.size() * 96 + 64);

    std::string prefix = "[";
    prefix += mod.moduleName;
    prefix += mutated ? ":mutated]" : "]";
    const bool is64 = mod.arch != kArchX86 && mod.arch != kArchArm;

    head += "; --- ";
    head += prefix;
    head += " (";
    head += std::to_string(mod.gadgets.size());
    head += " gadgets) ---\n";
    for (const auto& g : mod.gadgets) {
        head += prefix;
        head += ' ';
        AppendAddress(head, g.address, is64);
        head += ": ";
        head += g.disassembly;
        head += " (";
        head += std::to_string(g.numOccurrences);
        head += " found)\n";
    }
    head += "\n";
    return head;
}

std::string FormatJsonHead(const ModuleGadgets& mod, bool mutated) {
    std::string head;
    head.reserve(mod.gadgets.size() * 128 + 128);

    if (mutated) {
        head += "{\"mutated\":true,\"name\":\"";
        head += JsonEscape(mod.moduleName);
        head += "\",\"path\":\"";
        head += JsonEscape(mod.filePath.string());
        head += "\"";
    } else {
        head += "{\"name\":\"";
        head += JsonEscape(mod.moduleName);
        head += "\",\"path\":\"";
        head += JsonEscape(mod.filePath.string());
        head += "\"";
    }
    head += ",\"arch\":\"";
    head += mod.arch;
    head += "\"";
    if (mod.imageBase) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(mod.imageBase));
        head += ",\"imageBase\":\"";
        head += buf;
        head += "\"";
    }
    head += ",\"gadgets\":[";
    for (size_t i = 0; i < mod.gadgets.size(); ++i) {
        const auto& g = mod.gadgets[i];
        if (i)
            head += ',';
        head += "{\"address\":";
        head += std::to_string(g.address);
        head += ",\"disassembly\":\"";
        head += JsonEscape(g.disassembly);
        head += "\",\"bytes\":\"";
        head += util::BytesToHex(g.bytes.data(), g.bytes.size());
        head += "\",\"count\":";
        head += std::to_string(g.numOccurrences);
        head += "}";
    }
    head += "]}";
    return head;
}

std::string FormatCsvHead(const ModuleGadgets& mod, bool mutated) {
    std::string head;
    head.reserve(mod.gadgets.size() * 96 + 32);

    const bool is64 = mod.arch != kArchX86 && mod.arch != kArchArm;
    const std::string moduleName = CsvEscape(mod.moduleName);
    const std::string mutFlag = mutated ? "yes" : "no";
    for (const auto& g : mod.gadgets) {
        head += moduleName;
        head += ',';
        head += mutFlag;
        head += ',';
        AppendAddress(head, g.address, is64);
        head += ',';
        head += CsvEscape(g.disassembly);
        head += ',';
        head += CsvEscape(util::BytesToHex(g.bytes.data(), g.bytes.size()));
        head += ',';
        head += std::to_string(g.numOccurrences);
        head += '\n';
    }
    return head;
}

// ---------------------------------------------------------------------------
// Text sink (rp++-style), merged or per-module
// ---------------------------------------------------------------------------

class TextSink final : public IGadgetSink {
public:
    explicit TextSink(const std::filesystem::path& path)
        : ioBuf_(kIoBufferSize) {
        if (!OpenInto(out_, path, ioBuf_.data(), ioBuf_.size()))
            failed_ = true;
        else
            out_ << "; Total Gadgets v2 output\n";
    }
    bool Failed() const { return failed_; }

    std::string WriteModule(const ModuleGadgets& mod, bool mutated) override {
        // Format without holding the lock, then write in one call.
        const std::string block = FormatTextHead(mod, mutated);

        std::lock_guard<std::mutex> lock(mu_);
        out_.write(block.data(), static_cast<std::streamsize>(block.size()));
        if (!out_.good())
            return "write error (disk full or path invalid)";
        ++modulesWritten_;
        gadgetsWritten_ += mod.gadgets.size();
        return {};
    }

    std::string Finish(bool cancelled, uint32_t, size_t) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (cancelled)
            out_ << "; NOTE: scan cancelled; output is partial\n";
        out_ << "; Total modules: " << modulesWritten_ << "\n";
        out_ << "; Total gadgets: " << gadgetsWritten_ << "\n";
        out_.flush();
        if (!out_.good())
            return "final write error";
        return {};
    }

private:
    std::mutex mu_;
    std::vector<char> ioBuf_;   // declared before out_: destroyed after it
    std::ofstream out_;
    bool failed_ = false;
};

// ---------------------------------------------------------------------------
// JSON sink, merged or per-module
// ---------------------------------------------------------------------------

class JsonSink final : public IGadgetSink {
public:
    explicit JsonSink(const std::filesystem::path& path)
        : ioBuf_(kIoBufferSize) {
        if (!OpenInto(out_, path, ioBuf_.data(), ioBuf_.size()))
            failed_ = true;
        else
            out_ << "{\"generator\":\"Total Gadgets v2\",\"modules\":[";
    }
    bool Failed() const { return failed_; }

    std::string WriteModule(const ModuleGadgets& mod, bool mutated) override {
        const std::string block = FormatJsonHead(mod, mutated);

        std::lock_guard<std::mutex> lock(mu_);
        out_.write(block.data(), static_cast<std::streamsize>(block.size()));
        if (!out_.good())
            return "write error (disk full or path invalid)";
        ++modulesWritten_;
        gadgetsWritten_ += mod.gadgets.size();
        return {};
    }

    std::string Finish(bool cancelled, uint32_t, size_t) override {
        std::lock_guard<std::mutex> lock(mu_);
        out_ << "],\"totalModules\":" << modulesWritten_
             << ",\"totalGadgets\":" << gadgetsWritten_;
        if (cancelled)
            out_ << ",\"cancelled\":true";
        out_ << "}\n";
        out_.flush();
        if (!out_.good())
            return "final write error";
        return {};
    }

private:
    std::mutex mu_;
    std::vector<char> ioBuf_;   // declared before out_: destroyed after it
    std::ofstream out_;
    bool failed_ = false;
};

// ---------------------------------------------------------------------------
// CSV sink, merged or per-module
// ---------------------------------------------------------------------------

class CsvSink final : public IGadgetSink {
public:
    explicit CsvSink(const std::filesystem::path& path)
        : ioBuf_(kIoBufferSize) {
        if (!OpenInto(out_, path, ioBuf_.data(), ioBuf_.size()))
            failed_ = true;
        else
            out_ << "module,mutated,address,disassembly,bytes,count\n";
    }
    bool Failed() const { return failed_; }

    std::string WriteModule(const ModuleGadgets& mod, bool mutated) override {
        const std::string block = FormatCsvHead(mod, mutated);

        std::lock_guard<std::mutex> lock(mu_);
        out_.write(block.data(), static_cast<std::streamsize>(block.size()));
        if (!out_.good())
            return "write error (disk full or path invalid)";
        ++modulesWritten_;
        gadgetsWritten_ += mod.gadgets.size();
        return {};
    }

    std::string Finish(bool, uint32_t, size_t) override {
        std::lock_guard<std::mutex> lock(mu_);
        out_.flush();
        if (!out_.good())
            return "final write error";
        return {};
    }

private:
    std::mutex mu_;
    std::vector<char> ioBuf_;   // declared before out_: destroyed after it
    std::ofstream out_;
    bool failed_ = false;
};

// ---------------------------------------------------------------------------
// Per-module splitter: opens one file per module
// ---------------------------------------------------------------------------

class SplitSink final : public IGadgetSink {
public:
    SplitSink(std::filesystem::path dir, OutputFormat format, std::wstring stemSuffix)
        : dir_(std::move(dir)), format_(format),
          stemSuffix_(std::move(stemSuffix)) {}

    std::string WriteModule(const ModuleGadgets& mod, bool mutated) override {
        std::lock_guard<std::mutex> lock(mu_);

        std::filesystem::path file = dir_ / (util::ToWide(SanitizeName(mod.moduleName)));
        if (!stemSuffix_.empty())
            file += stemSuffix_;
        file += ExtensionForFormat(format_);

        std::string head;
        std::string tail;
        switch (format_) {
        case OutputFormat::Text:
            head = "; Total Gadgets v2 output\n" + FormatTextHead(mod, mutated);
            tail = "; Total modules: 1\n; Total gadgets: " +
                   std::to_string(mod.gadgets.size()) + "\n";
            break;
        case OutputFormat::Json:
            head = "{\"generator\":\"Total Gadgets v2\",\"modules\":[" +
                   FormatJsonHead(mod, mutated);
            tail = "],\"totalModules\":1,\"totalGadgets\":" +
                   std::to_string(mod.gadgets.size()) + "}\n";
            break;
        case OutputFormat::Csv:
            head = "module,mutated,address,disassembly,bytes,count\n" +
                   FormatCsvHead(mod, mutated);
            break;
        }

        // One shared buffer, one file at a time (we hold the lock).
        std::ofstream out;
        if (!OpenInto(out, file, ioBuf_.data(), ioBuf_.size())) {
            out.clear();
            out.open(file, std::ios::binary); // retry default-buffered
            if (!out)
                return "cannot create " + util::ToUtf8(file.wstring());
        }
        out.write(head.data(), static_cast<std::streamsize>(head.size()));
        if (!tail.empty())
            out.write(tail.data(), static_cast<std::streamsize>(tail.size()));
        out.flush();
        if (!out.good())
            return "write error (disk full or path invalid)";

        ++modulesWritten_;
        gadgetsWritten_ += mod.gadgets.size();
        written_.push_back(std::move(file));
        return {};
    }

    std::string Finish(bool, uint32_t, size_t) override { return {}; }

private:
    std::mutex mu_;
    std::filesystem::path dir_;
    OutputFormat format_;
    std::wstring stemSuffix_;
    std::vector<char> ioBuf_;
    std::vector<std::filesystem::path> written_;
};

} // namespace

const wchar_t* ExtensionForFormat(OutputFormat format) {
    switch (format) {
    case OutputFormat::Text: return L".txt";
    case OutputFormat::Json: return L".json";
    case OutputFormat::Csv: return L".csv";
    }
    return L".txt";
}

std::unique_ptr<IGadgetSink> CreateSink(const OutputOptions& opts, bool mutated,
                                        std::string& error) {
    std::filesystem::path path = opts.path;

    if (opts.mode == OutputMode::PerModule) {
        std::error_code ec;
        std::filesystem::create_directories(path, ec);
        if (ec) {
            error = "cannot create output directory: " + util::ToUtf8(path.wstring());
            return nullptr;
        }
        return std::make_unique<SplitSink>(path, opts.format,
                                           mutated ? L"_mutated" : L"");
    }

    if (mutated) {
        auto stem = path.stem().wstring();
        auto ext = path.extension().wstring();
        if (ext.empty())
            ext = ExtensionForFormat(opts.format);
        path.replace_filename(stem + L"_mutated" + ext);
    }

    switch (opts.format) {
    case OutputFormat::Text: {
        auto sink = std::make_unique<TextSink>(path);
        if (sink->Failed()) {
            error = "cannot open output file: " + util::ToUtf8(path.wstring());
            return nullptr;
        }
        return sink;
    }
    case OutputFormat::Json: {
        auto sink = std::make_unique<JsonSink>(path);
        if (sink->Failed()) {
            error = "cannot open output file: " + util::ToUtf8(path.wstring());
            return nullptr;
        }
        return sink;
    }
    case OutputFormat::Csv: {
        auto sink = std::make_unique<CsvSink>(path);
        if (sink->Failed()) {
            error = "cannot open output file: " + util::ToUtf8(path.wstring());
            return nullptr;
        }
        return sink;
    }
    }

    error = "unknown format";
    return nullptr;
}

} // namespace gadgets
