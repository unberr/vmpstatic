#include "analysis.hpp"

namespace vmpstatic {

const char* toolVersion() { return "1.2.0"; }

Analysis analyze(const PeFile& pe, const AnalyzeOptions& options) {
    Analysis a;
    a.pe = &pe;
    a.detection = detect(pe);
    a.oepCandidates = findOepCandidates(pe, 32);
    a.vmEntry = findVmEntry(pe);
    a.handlerTables = findHandlerTables(pe, 8);
    a.vmDispatchers = findVmDispatchers(pe, 8);
    a.imports = parseImports(pe);
    a.packerInfo = discoverPackerInfo(pe);
    a.apiReferences = findApiReferences(pe, a.imports, 512);
    a.resolverStubs = findResolverStubCores(pe, 1024);

    std::vector<uint8_t> image;
    std::string error;
    if (fileToImage(pe, image, error)) {
        a.stringKeys = recoverStringKeys(pe);
        std::vector<uint32_t> keys;
        keys.reserve(a.stringKeys.size());
        for (const StringKey& k : a.stringKeys) keys.push_back(k.key);
        if (!keys.empty()) a.encodedTables = findEncodedImportTables(image, keys);
    } else {
        a.imageError = error;
        a.stringKeys = recoverStringKeys(pe);
    }

    if (options.catalog) {
        a.catalogModules = options.catalog->modules.size();
        a.catalogValidation = validateEncodedTables(a.encodedTables, *options.catalog);
    }

    if (options.hasManualOep) {
        uint32_t rva = 0;
        if (options.manualOep >= pe.imageBase) {
            if (!vaToRva(pe, options.manualOep, rva)) rva = pe.entryPoint;
        } else if (options.manualOep <= 0xFFFFFFFFull) {
            rva = static_cast<uint32_t>(options.manualOep);
        }
        a.selectedOep = rva;
        a.selectedMethod = OepMethod::Manual;
        a.selectedConfidence = Confidence::Medium;
        a.selectedEvidence = "user supplied via --oep";
        return a;
    }

    a.selectedOep = pe.entryPoint;
    a.selectedMethod = OepMethod::EntryPoint;
    a.selectedConfidence = Confidence::Low;
    a.selectedEvidence = "PE AddressOfEntryPoint; may still point at the packer stub";
    for (const OepCandidate& c : a.oepCandidates) {
        if (c.method == OepMethod::EntryPoint && c.rva == pe.entryPoint) {
            a.selectedConfidence = c.confidence;
            a.selectedEvidence = c.evidence;
            break;
        }
    }
    return a;
}

bool patchEntryPoint(std::vector<uint8_t>& image, const PeFile& pe, uint32_t rva) {
    const size_t at = pe.optionalHeaderOffset + 0x10;
    if (at + 4 > image.size() || rva >= pe.sizeOfImage) return false;
    for (size_t i = 0; i < 4; ++i) image[at + i] = static_cast<uint8_t>((rva >> (8 * i)) & 0xFF);
    return true;
}

}  // namespace vmpstatic
