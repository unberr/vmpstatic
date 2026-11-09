#include "detect.hpp"

#include "imports.hpp"
#include "strutil.hpp"

#include <cstdio>
#include <cstring>

namespace vmpstatic {
namespace {

std::string decimal(double v) {
    char buffer[24];
    std::snprintf(buffer, sizeof buffer, "%.2f", v);
    return buffer;
}

bool containsAscii(const std::vector<uint8_t>& data, const char* needle) {
    const size_t n = std::strlen(needle);
    if (n == 0 || data.size() < n) return false;
    const uint8_t* hay = data.data();
    for (size_t i = 0; i + n <= data.size(); ++i) {
        if (hay[i] == static_cast<uint8_t>(needle[0]) && std::memcmp(hay + i, needle, n) == 0) {
            return true;
        }
    }
    return false;
}

// Only reports a version when the file itself carries a literal banner; no guessing.
std::string versionFromLiteral(const std::vector<uint8_t>& data, std::string& evidence) {
    static const char kMarker[] = "VMProtect";
    const size_t markerLen = sizeof kMarker - 1;
    for (size_t i = 0; i + markerLen < data.size(); ++i) {
        if (std::memcmp(data.data() + i, kMarker, markerLen) != 0) continue;
        size_t p = i + markerLen;
        while (p < data.size() && (data[p] == ' ' || data[p] == ':')) ++p;
        const size_t start = p;
        size_t len = 0;
        while (p < data.size() && len < 12) {
            const uint8_t c = data[p];
            if (!((c >= '0' && c <= '9') || c == '.' || c == 'v' || c == 'V')) break;
            ++p;
            ++len;
        }
        if (len < 3) continue;
        const std::string value(reinterpret_cast<const char*>(data.data() + start), len);
        evidence = "literal '" + std::string(kMarker) + "' followed by '" + value +
                   "' at file offset " + hex(start);
        return value;
    }
    return {};
}

}  // namespace

const char* confidenceName(Confidence c) {
    switch (c) {
    case Confidence::High: return "High";
    case Confidence::Medium: return "Medium";
    case Confidence::Low: return "Low";
    case Confidence::None: break;
    }
    return "None";
}

Detection detect(const PeFile& pe) {
    Detection d;
    auto add = [&d](std::string name, int weight, std::string detail) {
        d.score += weight;
        d.signals.push_back({std::move(name), weight, std::move(detail)});
    };

    std::string vmpNames;
    for (size_t i = 0; i < pe.sections.size(); ++i) {
        if (!pe.sections[i].vmpName) continue;
        d.vmpSections.push_back(i);
        if (!vmpNames.empty()) vmpNames += ", ";
        vmpNames += pe.sections[i].name;
    }
    if (!d.vmpSections.empty()) add("vmp section names", 3, vmpNames);

    // vmpfix-shaped import resolver stubs corroborate VMProtect import hiding.
    const auto resolverCores = findResolverStubCores(pe, 32);
    if (!resolverCores.empty()) {
        add("import resolver stub cores", 2,
            std::to_string(resolverCores.size()) + " contiguous lea/mov/lea triple(s)");
    }

    const ImportTable imports = parseImports(pe);
    if (imports.entries.empty()) {
        add("no static imports", 2, imports.error.empty() ? "import directory empty" : imports.error);
    } else if (imports.entries.size() < 8) {
        add("few static imports", 1, std::to_string(imports.entries.size()) + " entries");
    }

    if (pe.dirs[1].present()) {
        const Section* s = sectionForRva(pe, pe.dirs[1].rva);
        if (s && s->entropy > 7.0) {
            add("import directory inside high-entropy section", 3,
                s->name + " entropy " + decimal(s->entropy));
        }
    }

    const Section* ep = sectionForRva(pe, pe.entryPoint);
    if (!ep) {
        add("entry point outside every section", 2, hex(pe.entryPoint));
    } else {
        if (&pe.sections[0] != ep && (ep->write || ep->entropy > 6.8)) {
            add("entry point outside first section", 2, ep->name);
        }
        if (ep->entropy > 6.8) add("entry section entropy above 6.8", 2, decimal(ep->entropy));
        if (ep->rawSize == 0) add("entry section has no raw data", 1, ep->name);
    }

    if (pe.hasOverlay() && pe.bytes.size() - pe.overlayOffset >= 0x1000) {
        add("appended data after last section", 1,
            std::to_string(pe.bytes.size() - pe.overlayOffset) + " bytes");
    }

    if (containsAscii(pe.bytes, "VMProtect")) {
        add("VMProtect literal present", 2, "string found in file");
    }

    if (d.score >= 7) {
        d.confidence = Confidence::High;
    } else if (d.score >= 4) {
        d.confidence = Confidence::Medium;
    } else if (d.score >= 2) {
        d.confidence = Confidence::Low;
    }

    const std::string version = versionFromLiteral(pe.bytes, d.versionEvidence);
    if (!version.empty()) d.version = version;
    return d;
}

}  // namespace vmpstatic
