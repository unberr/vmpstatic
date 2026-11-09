#include "report.hpp"

#include "disasm.hpp"
#include "strutil.hpp"

#include <cstdio>
#include <string>

namespace vmpstatic {
namespace {

std::string dec(uint64_t v) { return std::to_string(v); }

std::string fixed2(double v) {
    char buffer[24];
    std::snprintf(buffer, sizeof buffer, "%.2f", v);
    return buffer;
}

std::string quote(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char buffer[8];
                std::snprintf(buffer, sizeof buffer, "\\u%04X", c);
                out += buffer;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    out += '"';
    return out;
}

std::string flagsOf(const Section& s) {
    std::string flags;
    flags += s.read ? 'r' : '-';
    flags += s.write ? 'w' : '-';
    flags += s.exec ? 'x' : '-';
    return flags;
}

const char* const kLimitations[] = {
    "purely static: the input is never executed, loaded, or emulated",
    "OEP candidates are heuristics; pass --oep to override the selection",
    "VM handler devirtualization and IR recompilation are not implemented",
    "handler classes are coarse instruction categories, not devirtualized semantics",
    "encoded import slots are verified only when --catalog DLLs are supplied",
    "unpack restores only validated static LZMA section blocks; it does not rebuild imports",
    "the Authenticode signature of any produced file is invalid",
};

const char* const kDirectoryNames[16] = {
    "export", "import", "resource", "exception", "certificate", "base-relocation",
    "debug", "architecture", "global-pointer", "tls", "load-config", "bound-import",
    "iat", "delay-import", "clr", "reserved"};

}  // namespace

std::string renderJson(const Analysis& a, const std::string& path) {
    const PeFile& pe = *a.pe;
    std::string out;
    out.reserve(8192);
    out += "{\n";
    out += "  \"tool\": " + quote(std::string("vmpstatic ") + toolVersion()) + ",\n";
    out += "  \"file\": " + quote(path) + ",\n";
    out += "  \"disasm\": " + quote(disasmEngineName()) + ",\n";

    out += "  \"pe\": {\n";
    out += "    \"is64\": " + std::string(pe.is64 ? "true" : "false") + ",\n";
    out += "    \"machine\": " + quote(hex(pe.machine)) + ",\n";
    out += "    \"imageBase\": " + quote(hex(pe.imageBase)) + ",\n";
    out += "    \"entryPoint\": " + quote(hex(pe.entryPoint)) + ",\n";
    out += "    \"sizeOfImage\": " + dec(pe.sizeOfImage) + ",\n";
    out += "    \"sizeOfHeaders\": " + dec(pe.sizeOfHeaders) + ",\n";
    out += "    \"sectionAlignment\": " + dec(pe.sectionAlign) + ",\n";
    out += "    \"fileAlignment\": " + dec(pe.fileAlign) + ",\n";
    out += "    \"overlayOffset\": " + quote(hex(pe.overlayOffset)) + ",\n";
    out += "    \"overlaySize\": " + dec(pe.bytes.size() - pe.overlayOffset) + ",\n";
    out += "    \"dataDirectories\": [\n";
    for (size_t i = 0; i < 16; ++i) {
        const DataDir& d = pe.dirs[i];
        out += "      {\"index\": " + dec(i) + ", \"name\": " + quote(kDirectoryNames[i]) +
               ", \"address\": " + quote(hex(d.rva)) + ", \"size\": " + dec(d.size);
        if (i == 4) out += ", \"addressKind\": \"file-offset\"";
        else out += ", \"addressKind\": \"rva\"";
        out += "}";
        out += (i + 1 < 16) ? ",\n" : "\n";
    }
    out += "    ],\n    \"diagnostics\": [\n";
    for (size_t i = 0; i < pe.diagnostics.size(); ++i) {
        out += "      " + quote(pe.diagnostics[i]);
        out += (i + 1 < pe.diagnostics.size()) ? ",\n" : "\n";
    }
    out += "    ],\n    \"sections\": [\n";
    for (size_t i = 0; i < pe.sections.size(); ++i) {
        const Section& s = pe.sections[i];
        out += "      {\"name\": " + quote(s.name) + ", \"va\": " + quote(hex(s.va)) +
               ", \"virtualSize\": " + dec(s.vsize) + ", \"rawSize\": " + dec(s.rawSize) +
               ", \"rawPointer\": " + quote(hex(s.rawPtr)) + ", \"characteristics\": " +
               quote(hex(s.characteristics)) + ", \"executable\": " +
               (s.exec ? "true" : "false") + ", \"writable\": " + (s.write ? "true" : "false") +
               ", \"entropy\": " + fixed2(s.entropy) + ", \"vmpName\": " +
               (s.vmpName ? "true" : "false") + "}";
        out += (i + 1 < pe.sections.size()) ? ",\n" : "\n";
    }
    out += "    ]\n  },\n";

    out += "  \"detection\": {\n";
    out += "    \"confidence\": " + quote(confidenceName(a.detection.confidence)) + ",\n";
    out += "    \"score\": " + dec(a.detection.score) + ",\n";
    out += "    \"version\": " + quote(a.detection.version) + ",\n";
    out += "    \"versionEvidence\": " + quote(a.detection.versionEvidence) + ",\n";
    out += "    \"signals\": [\n";
    for (size_t i = 0; i < a.detection.signals.size(); ++i) {
        const Signal& s = a.detection.signals[i];
        out += "      {\"name\": " + quote(s.name) + ", \"weight\": " + dec(s.weight) +
               ", \"detail\": " + quote(s.detail) + "}";
        out += (i + 1 < a.detection.signals.size()) ? ",\n" : "\n";
    }
    out += "    ]\n  },\n";

    out += "  \"oep\": {\n";
    out += "    \"selected\": {\"rva\": " + quote(hex(a.selectedOep)) + ", \"method\": " +
           quote(oepMethodName(a.selectedMethod)) + ", \"confidence\": " +
           quote(confidenceName(a.selectedConfidence)) + ", \"evidence\": " +
           quote(a.selectedEvidence) + "},\n";
    out += "    \"candidates\": [\n";
    for (size_t i = 0; i < a.oepCandidates.size(); ++i) {
        const OepCandidate& c = a.oepCandidates[i];
        out += "      {\"rva\": " + quote(hex(c.rva)) + ", \"method\": " +
               quote(oepMethodName(c.method)) + ", \"confidence\": " +
               quote(confidenceName(c.confidence)) + ", \"evidence\": " + quote(c.evidence) +
               "}";
        out += (i + 1 < a.oepCandidates.size()) ? ",\n" : "\n";
    }
    out += "    ]\n  },\n";

    out += "  \"vm\": {\n";
    if (a.vmEntry) {
        out += "    \"entry\": {\"rva\": " + quote(hex(a.vmEntry->rva)) + ", \"confidence\": " +
               quote(confidenceName(a.vmEntry->confidence)) + ", \"evidence\": " +
               quote(a.vmEntry->evidence) + "},\n";
    } else {
        out += "    \"entry\": null,\n";
    }
    out += "    \"handlerTables\": [\n";
    for (size_t i = 0; i < a.handlerTables.size(); ++i) {
        const HandlerTable& t = a.handlerTables[i];
        out += "      {\"rva\": " + quote(hex(t.rva)) + ", \"section\": " + quote(t.section) +
               ", \"count\": " + dec(t.count) + ", \"confidence\": " +
               quote(confidenceName(t.confidence)) + ", \"handlers\": [\n";
        for (size_t j = 0; j < t.handlers.size(); ++j) {
            out += "        {\"rva\": " + quote(hex(t.handlers[j].rva)) + ", \"class\": " +
                   quote(t.handlers[j].cls) + ", \"detail\": " + quote(t.handlers[j].detail) +
                   "}";
            out += (j + 1 < t.handlers.size()) ? ",\n" : "\n";
        }
        out += "      ]}";
        out += (i + 1 < a.handlerTables.size()) ? ",\n" : "\n";
    }
    out += "    ],\n";
    out += "    \"dispatchers\": [\n";
    for (size_t i = 0; i < a.vmDispatchers.size(); ++i) {
        const VmDispatcher& d = a.vmDispatchers[i];
        out += "      {\"rva\": " + quote(hex(d.rva)) + ", \"pattern\": " + quote(d.pattern) +
               ", \"tableRva\": ";
        out += d.tableRva ? quote(hex(d.tableRva)) : "null";
        out += ", \"resolved\": " + std::string(d.resolved ? "true" : "false") +
               ", \"confidence\": " + quote(confidenceName(d.confidence)) + "}";
        out += (i + 1 < a.vmDispatchers.size()) ? ",\n" : "\n";
    }
    out += "    ]\n  },\n";

    out += "  \"packedSections\": {\n";
    out += "    \"format\": " + quote(packerFormatName(a.packerInfo.format)) + ",\n";
    out += "    \"uniqueTable\": " + std::string(a.packerInfo.unique() ? "true" : "false") + ",\n";
    out += "    \"candidateCount\": " + dec(a.packerInfo.candidates.size()) + ",\n";
    out += "    \"tableFileOffset\": " + quote(hex(a.packerInfo.tableFileOffset)) + ",\n";
    out += "    \"destinationKey\": " + quote(hex(a.packerInfo.destinationKey)) + ",\n";
    out += "    \"propertiesFileOffset\": " + quote(hex(a.packerInfo.lzmaPropertiesFileOffset)) + ",\n";
    out += "    \"properties\": [";
    for (size_t i = 0; i < a.packerInfo.lzmaProperties.size(); ++i) {
        if (i) out += ", ";
        out += dec(a.packerInfo.lzmaProperties[i]);
    }
    out += "],\n    \"diagnostic\": " + quote(a.packerInfo.diagnostic) + ",\n";
    out += "    \"blocks\": [\n";
    for (size_t i = 0; i < a.packerInfo.entries.size(); ++i) {
        const PackerInfoEntry& e = a.packerInfo.entries[i];
        out += "      {\"sourceRva\": " + quote(hex(e.sourceRva)) +
               ", \"destinationRva\": " + quote(hex(e.destinationRva)) + "}";
        out += (i + 1 < a.packerInfo.entries.size()) ? ",\n" : "\n";
    }
    out += "    ],\n    \"recovery\": {\"attempted\": " +
           std::string(a.packedRecovery.attempted ? "true" : "false") +
           ", \"recoveredBytes\": " + dec(a.packedRecovery.recoveredBytes) +
           ", \"diagnostic\": " + quote(a.packedRecovery.diagnostic) + ", \"blocks\": [\n";
    for (size_t i = 0; i < a.packedRecovery.blocks.size(); ++i) {
        const PackedBlockRecovery& b = a.packedRecovery.blocks[i];
        out += "      {\"sourceRva\": " + quote(hex(b.sourceRva)) +
               ", \"destinationRva\": " + quote(hex(b.destinationRva)) +
               ", \"recovered\": " + std::string(b.recovered ? "true" : "false") +
               ", \"compressedSize\": " + dec(b.compressedSize) +
               ", \"decompressedSize\": " + dec(b.decompressedSize) +
               ", \"error\": " + quote(b.error) + "}";
        out += (i + 1 < a.packedRecovery.blocks.size()) ? ",\n" : "\n";
    }
    out += "    ]}\n  },\n";

    out += "  \"imports\": {\n";
    out += "    \"directory\": {\"count\": " + dec(a.imports.entries.size()) + ", \"modules\": " +
           dec(a.imports.moduleCount) + ", \"error\": " + quote(a.imports.error) + "},\n";
    out += "    \"catalog\": {\"modules\": " + dec(a.catalogModules) + ", \"tables\": " +
           dec(a.catalogValidation.tables) + ", \"records\": " +
           dec(a.catalogValidation.records) + ", \"validated\": " +
           dec(a.catalogValidation.validated) + ", \"dropped\": " +
           dec(a.catalogValidation.dropped) + "},\n";
    out += "    \"entries\": [\n";
    for (size_t i = 0; i < a.imports.entries.size(); ++i) {
        const ImportEntry& e = a.imports.entries[i];
        out += "      {\"module\": " + quote(e.module) + ", \"name\": " + quote(e.name) +
               ", \"iatRva\": " + quote(hex(e.iatRva)) + "}";
        out += (i + 1 < a.imports.entries.size()) ? ",\n" : "\n";
    }
    out += "    ],\n";
    out += "    \"apiReferences\": [\n";
    for (size_t i = 0; i < a.apiReferences.size(); ++i) {
        const ApiReference& r = a.apiReferences[i];
        out += "      {\"siteRva\": " + quote(hex(r.siteRva)) + ", \"iatRva\": " +
               quote(hex(r.iatRva)) + ", \"module\": " + quote(r.module) + ", \"name\": " +
               quote(r.name) + ", \"byOrdinal\": " +
               std::string(r.byOrdinal ? "true" : "false") + ", \"packerSection\": " +
               std::string(r.packerSection ? "true" : "false") + "}";
        out += (i + 1 < a.apiReferences.size()) ? ",\n" : "\n";
    }
    out += "    ],\n";
    out += "    \"resolverStubCores\": [\n";
    for (size_t i = 0; i < a.resolverStubs.size(); ++i) {
        const ResolverStubCore& c = a.resolverStubs[i];
        out += "      {\"rva\": " + quote(hex(c.rva)) + ", \"reg\": " + dec(c.reg) +
               ", \"packerSection\": " + std::string(c.packerSection ? "true" : "false") + "}";
        out += (i + 1 < a.resolverStubs.size()) ? ",\n" : "\n";
    }
    out += "    ],\n";
    out += "    \"stringKeys\": [\n";
    for (size_t i = 0; i < a.stringKeys.size(); ++i) {
        out += "      {\"key\": " + quote(hex(a.stringKeys[i].key)) +
               ", \"matches\": " + dec(a.stringKeys[i].matches) + "}";
        out += (i + 1 < a.stringKeys.size()) ? ",\n" : "\n";
    }
    out += "    ],\n";
    out += "    \"encodedTables\": [\n";
    for (size_t i = 0; i < a.encodedTables.size(); ++i) {
        const EncodedImportTable& t = a.encodedTables[i];
        out += "      {\"tableRva\": " + quote(hex(t.tableRva)) + ", \"moduleNameRva\": " +
               quote(hex(t.moduleNameRva)) + ", \"module\": " + quote(t.module) +
               ", \"records\": [\n";
        for (size_t j = 0; j < t.records.size(); ++j) {
            const EncodedImportRecord& r = t.records[j];
            out += "        {\"name\": " + quote(r.name) + ", \"slotRva\": " +
                   quote(hex(r.slotRva)) + ", \"recordRva\": " + quote(hex(r.recordRva)) +
                   ", \"key\": " + quote(hex(static_cast<uint32_t>(r.key))) +
                   ", \"validated\": " + (r.validated ? "true" : "false");
            if (r.hasOrdinal) out += ", \"ordinal\": " + dec(r.ordinal);
            out += "}";
            out += (j + 1 < t.records.size()) ? ",\n" : "\n";
        }
        out += "      ]}";
        out += (i + 1 < a.encodedTables.size()) ? ",\n" : "\n";
    }
    out += "    ]\n  },\n";
    if (!a.imageError.empty()) out += "  \"imageError\": " + quote(a.imageError) + ",\n";

    out += "  \"limitations\": [\n";
    const size_t count = sizeof kLimitations / sizeof kLimitations[0];
    for (size_t i = 0; i < count; ++i) {
        out += "    " + quote(kLimitations[i]);
        out += (i + 1 < count) ? ",\n" : "\n";
    }
    out += "  ]\n}\n";
    return out;
}

std::string renderText(const Analysis& a, const std::string& path) {
    const PeFile& pe = *a.pe;
    std::string out;
    out += "file: " + path + "\n";
    out += std::string("format: ") + (pe.is64 ? "PE32+ (x86-64)" : "PE32 (x86)") +
           ", image base " + hex(pe.imageBase) + ", entry " + hex(pe.entryPoint) + ", " +
           dec(pe.sections.size()) + " sections\n";
    out += "detection: " + std::string(confidenceName(a.detection.confidence)) + " (score " +
           dec(a.detection.score) + ")\n";
    for (const Signal& s : a.detection.signals) {
        out += "  +" + dec(s.weight) + " " + s.name + ": " + s.detail + "\n";
    }
    if (a.detection.signals.empty()) out += "  no signals matched\n";
    out += "version: " + a.detection.version + " (" + a.detection.versionEvidence + ")\n";

    out += "sections:\n";
    for (const Section& s : pe.sections) {
        out += "  " + s.name + "  va " + hex(s.va) + "  vsize " + dec(s.vsize) + "  raw " +
               dec(s.rawSize) + "  " + flagsOf(s) + "  entropy " + fixed2(s.entropy);
        if (s.vmpName) out += "  [vmp]";
        out += "\n";
    }
    out += "PE diagnostics:\n";
    if (pe.diagnostics.empty()) out += "  none\n";
    for (const std::string& diagnostic : pe.diagnostics) out += "  warning: " + diagnostic + "\n";
    out += "packed sections: " + std::string(packerFormatName(a.packerInfo.format)) +
           ", " + dec(a.packerInfo.entries.size()) + " block descriptor(s), " +
           a.packerInfo.diagnostic + "\n";
    for (const PackerInfoEntry& entry : a.packerInfo.entries)
        out += "  source " + hex(entry.sourceRva) + " -> destination " +
               hex(entry.destinationRva) + "\n";
    if (a.packedRecovery.attempted) {
        out += "LZMA recovery: " + dec(a.packedRecovery.recoveredBytes) +
               " byte(s) restored\n";
        for (const PackedBlockRecovery& block : a.packedRecovery.blocks) {
            out += "  " + hex(block.sourceRva) + " -> " + hex(block.destinationRva) +
                   (block.recovered ? "  recovered " + dec(block.decompressedSize) + " bytes\n"
                                    : "  failed: " + block.error + "\n");
        }
    }
    out += "data directories:\n";
    for (size_t i = 0; i < 16; ++i) {
        const DataDir& d = pe.dirs[i];
        if (!d.present()) continue;
        out += "  " + std::string(kDirectoryNames[i]) + "  " +
               (i == 4 ? "file offset " : "rva ") + hex(d.rva) + "  size " + dec(d.size) + "\n";
    }

    out += "oep candidates:\n";
    if (a.oepCandidates.empty()) out += "  none\n";
    for (const OepCandidate& c : a.oepCandidates) {
        const bool selected = c.rva == a.selectedOep && c.method == a.selectedMethod;
        out += std::string("  ") + (selected ? "* " : "  ") + hex(c.rva) + "  " +
               oepMethodName(c.method) + "  " + confidenceName(c.confidence) + "  " +
               c.evidence + "\n";
    }

    if (a.vmEntry) {
        out += "vm entry: " + hex(a.vmEntry->rva) + "  " +
               confidenceName(a.vmEntry->confidence) + "  " + a.vmEntry->evidence + "\n";
    } else {
        out += "vm entry: not found\n";
    }
    out += "handler tables: " + dec(a.handlerTables.size()) + "\n";
    for (const HandlerTable& t : a.handlerTables) {
        out += "  table " + hex(t.rva) + " " + t.section + ", " + dec(t.count) +
               " handlers, " + confidenceName(t.confidence) + "\n";
        const size_t shown = t.handlers.size() < 16 ? t.handlers.size() : 16;
        for (size_t i = 0; i < shown; ++i) {
            const HandlerInfo& h = t.handlers[i];
            out += "    " + hex(h.rva) + "  " + h.cls + "  " + h.detail + "\n";
        }
        if (t.handlers.size() > shown) {
            out += "    ... " + dec(t.handlers.size() - shown) + " more\n";
        }
    }
    out += "dispatchers: " + dec(a.vmDispatchers.size()) + "\n";
    for (const VmDispatcher& d : a.vmDispatchers) {
        out += "  " + hex(d.rva) + "  " + d.pattern + "  ";
        out += d.resolved ? ("table " + hex(d.tableRva)) : std::string("table unresolved");
        out += std::string("  ") + confidenceName(d.confidence) + "\n";
    }

    out += "imports: ";
    if (a.imports.entries.empty()) {
        out += "none (" + a.imports.error + ")\n";
    } else {
        out += dec(a.imports.entries.size()) + " entries in " + dec(a.imports.moduleCount) +
               " modules\n";
    }
    if (a.catalogModules == 0) {
        out += "catalog: none supplied (encoded records unvalidated)\n";
    } else {
        out += "catalog: " + dec(a.catalogModules) + " modules, " +
               dec(a.catalogValidation.validated) + "/" + dec(a.catalogValidation.records) +
               " records validated, " + dec(a.catalogValidation.dropped) + " dropped\n";
    }

    out += "api references: " + dec(a.apiReferences.size()) + "\n";
    const size_t refsShown = a.apiReferences.size() < 32 ? a.apiReferences.size() : 32;
    for (size_t i = 0; i < refsShown; ++i) {
        const ApiReference& r = a.apiReferences[i];
        out += "  " + hex(r.siteRva) + " -> " + r.module + "!" +
               (r.byOrdinal ? ("#" + dec(r.ordinal)) : r.name);
        if (r.packerSection) out += "  (packer section)";
        out += "\n";
    }
    if (a.apiReferences.size() > refsShown) {
        out += "  ... " + dec(a.apiReferences.size() - refsShown) + " more\n";
    }

    out += "resolver stub cores: " + dec(a.resolverStubs.size()) +
           " (contiguous lea/mov/lea only; junk-separated variants not detected)\n";
    const size_t coresShown = a.resolverStubs.size() < 32 ? a.resolverStubs.size() : 32;
    static const char* kRegs[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi",
                                    "rdi", "r8", "r9", "r10", "r11",
                                    "r12", "r13", "r14", "r15"};
    for (size_t i = 0; i < coresShown; ++i) {
        const ResolverStubCore& c = a.resolverStubs[i];
        out += "  " + hex(c.rva) + " reg " + kRegs[c.reg & 15];
        if (c.packerSection) out += "  (packer section)";
        out += "\n";
    }
    if (a.resolverStubs.size() > coresShown) {
        out += "  ... " + dec(a.resolverStubs.size() - coresShown) + " more\n";
    }

    out += "string keys: ";
    if (a.stringKeys.empty()) {
        out += "none recovered\n";
    } else {
        out += "\n";
        for (const StringKey& k : a.stringKeys) {
            out += "  " + hex(k.key) + " (" + dec(k.matches) + " known-plaintext matches)\n";
        }
    }

    out += "encoded import tables: " + dec(a.encodedTables.size()) + "\n";
    for (const EncodedImportTable& t : a.encodedTables) {
        out += "  table " + hex(t.tableRva) + " module " + t.module + ", " +
               dec(t.records.size()) + " records\n";
        for (const EncodedImportRecord& r : t.records) {
            out += "    slot " + hex(r.slotRva) + "  " + r.name + "\n";
        }
    }

    out += "limitations:\n";
    for (const char* limitation : kLimitations) out += std::string("  - ") + limitation + "\n";
    return out;
}

}  // namespace vmpstatic
