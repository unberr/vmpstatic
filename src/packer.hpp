// Static VMProtect PACKER_INFO discovery and section recovery.
// Metadata layout ported from the VMPStatic Go project; see
// third_party/VMPStatic-Go-MIT.txt for attribution.
#pragma once

#include "pe.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace vmpstatic {

enum class PackerFormat { Unknown, LegacyPlaintext, RotatingKey };

struct PackerInfoEntry {
    uint32_t sourceRva = 0;
    uint32_t destinationRva = 0;
};

struct PackerInfoCandidate {
    PackerFormat format = PackerFormat::Unknown;
    uint32_t tableFileOffset = 0;
    uint32_t destinationKey = 0;
    std::array<uint8_t, 5> lzmaProperties{};
    uint32_t lzmaPropertiesFileOffset = 0;
    std::vector<PackerInfoEntry> entries;
};

struct PackerInfoDiscovery {
    PackerFormat format = PackerFormat::Unknown;
    uint32_t tableFileOffset = 0;
    uint32_t destinationKey = 0;
    std::array<uint8_t, 5> lzmaProperties{};
    uint32_t lzmaPropertiesFileOffset = 0;
    std::vector<PackerInfoEntry> entries;
    std::vector<PackerInfoCandidate> candidates;
    std::string diagnostic;

    bool unique() const { return candidates.size() == 1; }
};

struct PackedBlockRecovery {
    uint32_t sourceRva = 0;
    uint32_t destinationRva = 0;
    size_t sourceFileOffset = 0;
    size_t sourceRangeSize = 0;
    size_t compressedSize = 0;
    size_t decompressedSize = 0;
    bool recovered = false;
    std::string error;
};

struct PackedSectionRecovery {
    bool attempted = false;
    std::vector<PackedBlockRecovery> blocks;
    size_t recoveredBytes = 0;
    std::string diagnostic;
};

PackerInfoDiscovery discoverPackerInfo(const PeFile& pe);
PackedSectionRecovery decompressPackedSections(const PeFile& pe,
                                              const PackerInfoDiscovery& discovery,
                                              std::vector<uint8_t>& image);

const char* packerFormatName(PackerFormat format);

}  // namespace vmpstatic
