#include "Sink.hpp"

#include <cstdio>
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

// ---------------------------------------------------------------------------
// Text sink (rp++-style), merged or per-module
// ---------------------------------------------------------------------------

class TextSink final : public IGadgetSink {
public:
    TextSink(std::ofstream out) : out_(std::move(out)) {
        out_ << "; Total Gadgets v2 output\n";
    }

    std::string WriteModule(const ModuleGadgets& mod, bool mutated) override {
        std::lock_guard<std::mutex> lock(mu_);

        const std::string prefix =
            mutated ? "[" + mod.moduleName + ":mutated]" : "[" + mod.moduleName + "]";
        const bool is64 = mod.arch != kArchX86 && mod.arch != kArchArm;

        out_ << "; --- " << prefix << " (" << mod.gadgets.size() << " gadgets) ---\n";
        for (const auto& g : mod.gadgets) {
            out_ << prefix << " " << util::FormatAddress(g.address, is64) << ": "
                 << g.disassembly << " (" << g.numOccurrences << " found)\n";
        }
        out_ << "\n";

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
    std::ofstream out_;
};

// ---------------------------------------------------------------------------
// JSON sink, merged or per-module
// ---------------------------------------------------------------------------

class JsonSink final : public IGadgetSink {
public:
    JsonSink(std::ofstream out) : out_(std::move(out)) {
        out_ << "{\"generator\":\"Total Gadgets v2\",\"modules\":[";
    }

    std::string WriteModule(const ModuleGadgets& mod, bool mutated) override {
        std::lock_guard<std::mutex> lock(mu_);

        if (modulesWritten_ > 0)
            out_ << ",";
        if (mutated)
            out_ << "{\"mutated\":true,\"name\":\"" << JsonEscape(mod.moduleName)
                 << "\",\"path\":\"" << JsonEscape(mod.filePath.string()) << "\"";
        else
            out_ << "{\"name\":\"" << JsonEscape(mod.moduleName) << "\",\"path\":\""
                 << JsonEscape(mod.filePath.string()) << "\"";
        out_ << ",\"arch\":\"" << mod.arch << "\"";
        if (mod.imageBase)
            out_ << ",\"imageBase\":\"0x" << std::hex << mod.imageBase << std::dec
                 << "\"";
        out_ << ",\"gadgets\":[";
        for (size_t i = 0; i < mod.gadgets.size(); ++i) {
            const auto& g = mod.gadgets[i];
            if (i)
                out_ << ",";
            out_ << "{\"address\":" << g.address << ",\"disassembly\":\""
                 << JsonEscape(g.disassembly) << "\",\"bytes\":\""
                 << util::BytesToHex(g.bytes.data(), g.bytes.size())
                 << "\",\"count\":" << g.numOccurrences << "}";
        }
        out_ << "]}";

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
    std::ofstream out_;
};

// ---------------------------------------------------------------------------
// CSV sink, merged or per-module
// ---------------------------------------------------------------------------

class CsvSink final : public IGadgetSink {
public:
    CsvSink(std::ofstream out) : out_(std::move(out)) {
        out_ << "module,mutated,address,disassembly,bytes,count\n";
    }

    std::string WriteModule(const ModuleGadgets& mod, bool mutated) override {
        std::lock_guard<std::mutex> lock(mu_);

        const bool is64 = mod.arch != kArchX86 && mod.arch != kArchArm;
        for (const auto& g : mod.gadgets) {
            out_ << CsvEscape(mod.moduleName) << ',' << (mutated ? "yes" : "no")
                 << ',' << util::FormatAddress(g.address, is64) << ','
                 << CsvEscape(g.disassembly) << ','
                 << CsvEscape(util::BytesToHex(g.bytes.data(), g.bytes.size())) << ','
                 << g.numOccurrences << '\n';
        }

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
    std::ofstream out_;
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

        std::ofstream out(file, std::ios::binary);
        if (!out)
            return "cannot create " + util::ToUtf8(file.wstring());

        std::string err;
        switch (format_) {
        case OutputFormat::Text: {
            TextSink sink(std::move(out));
            err = sink.WriteModule(mod, mutated);
            err = err.empty() ? sink.Finish(false, 0, 0) : err;
            break;
        }
        case OutputFormat::Json: {
            JsonSink sink(std::move(out));
            err = sink.WriteModule(mod, mutated);
            err = err.empty() ? sink.Finish(false, 0, 0) : err;
            break;
        }
        case OutputFormat::Csv: {
            CsvSink sink(std::move(out));
            err = sink.WriteModule(mod, mutated);
            err = err.empty() ? sink.Finish(false, 0, 0) : err;
            break;
        }
        }

        if (!err.empty())
            return err;
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
    std::vector<std::filesystem::path> written_;
};

std::ofstream OpenStream(const std::filesystem::path& path) {
    std::ofstream out(path, std::ios::binary);
    return out;
}

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

    std::ofstream out = OpenStream(path);
    if (!out) {
        error = "cannot open output file: " + util::ToUtf8(path.wstring());
        return nullptr;
    }

    switch (opts.format) {
    case OutputFormat::Text: return std::make_unique<TextSink>(std::move(out));
    case OutputFormat::Json: return std::make_unique<JsonSink>(std::move(out));
    case OutputFormat::Csv: return std::make_unique<CsvSink>(std::move(out));
    }

    error = "unknown format";
    return nullptr;
}

} // namespace gadgets
