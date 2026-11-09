// Packer-section classification and static OEP candidate discovery.
#pragma once

#include "detect.hpp"
#include "pe.hpp"

#include <string>
#include <vector>

namespace vmpstatic {

enum class OepMethod { Manual, EntryPoint, BranchScan, PrologueScan };
const char* oepMethodName(OepMethod m);

struct OepCandidate {
    uint32_t rva = 0;
    OepMethod method = OepMethod::EntryPoint;
    Confidence confidence = Confidence::None;
    std::string evidence;
};

// unpaki's rule: a section named "vmp*", or executable, at least one page, and not a
// known compiler/runtime section name.
bool isPackerSection(const Section& section);

bool looksLikePrologue(const uint8_t* data, size_t size);

std::vector<OepCandidate> findOepCandidates(const PeFile& pe, size_t maxResults);

}  // namespace vmpstatic
