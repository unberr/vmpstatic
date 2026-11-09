// Orchestrates the static pipeline: detection, OEP, VM structure, imports,
// resolver stubs, encoded tables.
#pragma once

#include "detect.hpp"
#include "imports.hpp"
#include "oep.hpp"
#include "packer.hpp"
#include "pe.hpp"
#include "vm.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vmpstatic {

struct AnalyzeOptions {
    uint64_t manualOep = 0;              // RVA/VA when supplied; zero is explicit too
    bool hasManualOep = false;
    const ExportCatalog* catalog = nullptr;  // optional, from --catalog DLLs
};

struct Analysis {
    const PeFile* pe = nullptr;
    Detection detection;
    std::vector<OepCandidate> oepCandidates;
    uint32_t selectedOep = 0;
    OepMethod selectedMethod = OepMethod::EntryPoint;
    Confidence selectedConfidence = Confidence::None;
    std::string selectedEvidence;
    std::optional<VmEntry> vmEntry;
    std::vector<HandlerTable> handlerTables;
    std::vector<VmDispatcher> vmDispatchers;
    ImportTable imports;
    std::vector<ApiReference> apiReferences;
    std::vector<ResolverStubCore> resolverStubs;
    std::vector<StringKey> stringKeys;
    std::vector<EncodedImportTable> encodedTables;
    CatalogValidation catalogValidation;
    size_t catalogModules = 0;
    PackerInfoDiscovery packerInfo;
    PackedSectionRecovery packedRecovery;
    std::string imageError;
};

// manualOep in options: 0 is a valid explicit RVA; main passes an explicit presence flag to distinguish it from absence.
Analysis analyze(const PeFile& pe, const AnalyzeOptions& options);

bool patchEntryPoint(std::vector<uint8_t>& image, const PeFile& pe, uint32_t rva);

const char* toolVersion();

}  // namespace vmpstatic
