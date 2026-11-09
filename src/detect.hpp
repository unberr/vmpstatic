// VMProtect fingerprinting: weighted signals, confidence, evidence-based version.
#pragma once

#include "pe.hpp"

#include <string>
#include <vector>

namespace vmpstatic {

enum class Confidence { None, Low, Medium, High };
const char* confidenceName(Confidence c);

struct Signal {
    std::string name;
    int weight = 0;
    std::string detail;
};

struct Detection {
    Confidence confidence = Confidence::None;
    int score = 0;
    std::vector<Signal> signals;
    std::vector<size_t> vmpSections;  // indices into PeFile::sections
    std::string version = "Unknown";
    std::string versionEvidence = "no version-specific marker found";
};

Detection detect(const PeFile& pe);

}  // namespace vmpstatic
