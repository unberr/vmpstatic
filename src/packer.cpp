#include "packer.hpp"

#include "checked.hpp"
#include "lzma.hpp"

#include <algorithm>
#include <functional>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace vmpstatic {
namespace {

constexpr uint32_t kCntUninitializedData = 0x00000080u;
constexpr size_t kMaxPackerEntries = 96;
constexpr size_t kMaxScanBytes = 256u << 20;
constexpr size_t kMaxCandidates = 64;
constexpr size_t kLzmaPropertiesSize = 5;

struct DestinationSection {
    uint32_t rva;
    size_t sectionIndex;
};

std::vector<DestinationSection> packedDestinations(const PeFile& pe) {
    std::vector<DestinationSection> out;
    for (size_t i = 0; i < pe.sections.size(); ++i) {
        const Section& s = pe.sections[i];
        if (s.rawSize == 0 && s.rawPtr == 0 &&
            (s.characteristics & kCntUninitializedData) == 0 && s.mappedSize() != 0) {
            out.push_back({s.va, i});
        }
    }
    return out;
}

bool rvaStartsLzmaStream(const PeFile& pe, uint32_t rva) {
    uint32_t offset = 0;
    return rvaToFileOffset(pe, rva, offset) && pe.bytes[offset] == 0;
}

bool entriesPassLzmaProbe(const PeFile& pe,
                          const std::array<uint8_t, kLzmaPropertiesSize>& properties,
                          const std::vector<PackerInfoEntry>& entries) {
    for (const PackerInfoEntry& entry : entries) {
        const Section* sourceSection = sectionForRva(pe, entry.sourceRva);
        uint32_t sourceOffset = 0;
        if (!sourceSection || !rvaToFileOffset(pe, entry.sourceRva, sourceOffset)) return false;
        const uint32_t delta = entry.sourceRva - sourceSection->va;
        if (delta >= sourceSection->rawSize || sourceOffset >= pe.bytes.size()) return false;
        const size_t available = std::min<size_t>(sourceSection->rawSize - delta,
                                                   pe.bytes.size() - sourceOffset);
        if (!probeRawLzma(properties, pe.bytes.data() + sourceOffset, available)) return false;
    }
    return true;
}

uint32_t rotateLeft32(uint32_t value, unsigned count) {
    count &= 31;
    return count == 0 ? value : (value << count) | (value >> (32 - count));
}

bool validProperties(const std::array<uint8_t, kLzmaPropertiesSize>& props) {
    // The first byte packs lc/lp/pb: values 0..224 are defined by LZMA.
    return props[0] < 9 * 5 * 5;
}

bool readEntries(const PeFile& pe, size_t tableOffset, size_t count,
                 std::vector<PackerInfoEntry>& entries) {
    if (count > kMaxPackerEntries || tableOffset > pe.bytes.size() ||
        count > (pe.bytes.size() - tableOffset) / 8) return false;
    const Reader reader(pe.bytes.data(), pe.bytes.size());
    entries.clear();
    entries.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const size_t at = tableOffset + i * 8;
        PackerInfoEntry entry;
        if (!reader.u32(at, entry.sourceRva) || !reader.u32(at + 4, entry.destinationRva) ||
            !rvaStartsLzmaStream(pe, entry.sourceRva)) return false;
        entries.push_back(entry);
    }
    return true;
}

bool isDestinationPermutation(const std::vector<PackerInfoEntry>& entries,
                              const std::vector<DestinationSection>& destinations) {
    if (entries.size() != destinations.size()) return false;
    std::unordered_set<uint32_t> expected;
    expected.reserve(destinations.size());
    for (const DestinationSection& destination : destinations) expected.insert(destination.rva);

    std::unordered_set<uint32_t> seen;
    seen.reserve(entries.size());
    for (const PackerInfoEntry& entry : entries) {
        if (expected.count(entry.destinationRva) == 0 ||
            !seen.insert(entry.destinationRva).second) return false;
    }
    return seen.size() == expected.size();
}

void scanRanges(const PeFile& pe, const std::function<void(size_t)>& visit) {
    size_t scanned = 0;
    auto scan = [&](size_t begin, size_t size) {
        if (begin >= pe.bytes.size() || scanned >= kMaxScanBytes) return;
        size = std::min(size, pe.bytes.size() - begin);
        size = std::min(size, kMaxScanBytes - scanned);
        const size_t aligned = (begin + 3) & ~size_t(3);
        const size_t end = begin + size;
        for (size_t offset = aligned; offset <= end && end - offset >= 16; offset += 4) {
            visit(offset);
        }
        scanned += size;
    };

    scan(0, std::min<size_t>(pe.sizeOfHeaders, pe.bytes.size()));
    for (const Section& section : pe.sections) {
        if (section.rawSize == 0) continue;
        scan(section.rawPtr, std::min<size_t>(section.rawSize, 64u << 20));
        if (scanned >= kMaxScanBytes) break;
    }
}

void addCandidate(std::vector<PackerInfoCandidate>& candidates,
                  PackerInfoCandidate candidate) {
    const auto duplicate = std::find_if(candidates.begin(), candidates.end(),
        [&](const PackerInfoCandidate& existing) {
            return existing.format == candidate.format &&
                   existing.tableFileOffset == candidate.tableFileOffset;
        });
    if (duplicate != candidates.end() || candidates.size() >= kMaxCandidates) return;
    candidates.push_back(std::move(candidate));
}

void findLegacyCandidates(const PeFile& pe,
                          const std::vector<DestinationSection>& destinations,
                          std::vector<PackerInfoCandidate>& candidates) {
    if (destinations.empty() || destinations.size() > kMaxPackerEntries) return;
    const size_t tableSize = destinations.size() * 8;
    scanRanges(pe, [&](size_t tableOffset) {
        if (tableOffset > pe.bytes.size() || tableSize > pe.bytes.size() - tableOffset ||
            tableOffset < 8) return;

        std::vector<PackerInfoEntry> entries;
        if (!readEntries(pe, tableOffset, destinations.size(), entries) ||
            !isDestinationPermutation(entries, destinations)) return;

        const uint32_t propertiesRva = le32(pe.bytes.data() + tableOffset - 8);
        uint32_t propertiesOffset = 0;
        if (!rvaToFileOffset(pe, propertiesRva, propertiesOffset) ||
            propertiesOffset > pe.bytes.size() ||
            kLzmaPropertiesSize > pe.bytes.size() - propertiesOffset) return;

        PackerInfoCandidate candidate;
        candidate.format = PackerFormat::LegacyPlaintext;
        candidate.tableFileOffset = static_cast<uint32_t>(tableOffset);
        candidate.lzmaPropertiesFileOffset = propertiesOffset;
        std::copy_n(pe.bytes.data() + propertiesOffset, kLzmaPropertiesSize,
                    candidate.lzmaProperties.begin());
        if (!validProperties(candidate.lzmaProperties) ||
            !entriesPassLzmaProbe(pe, candidate.lzmaProperties, entries)) return;
        candidate.entries = std::move(entries);
        addCandidate(candidates, std::move(candidate));
    });
}

void findRotatingKeyCandidates(const PeFile& pe,
                               const std::vector<DestinationSection>& destinations,
                               std::vector<PackerInfoCandidate>& candidates) {
    if (destinations.size() < 2 || destinations.size() > kMaxPackerEntries) return;
    const size_t tableSize = destinations.size() * 8;
    const Reader reader(pe.bytes.data(), pe.bytes.size());

    scanRanges(pe, [&](size_t tableOffset) {
        if (tableOffset > pe.bytes.size() || tableSize > pe.bytes.size() - tableOffset) return;

        std::vector<uint32_t> sources(destinations.size());
        for (size_t i = 0; i < destinations.size(); ++i) {
            uint32_t destinationRva = 0;
            if (!reader.u32(tableOffset + i * 8, sources[i]) ||
                !rvaStartsLzmaStream(pe, sources[i]) ||
                !reader.u32(tableOffset + i * 8 + 4, destinationRva)) return;
        }

        uint32_t storedFirstDestination = 0;
        if (!reader.u32(tableOffset + 4, storedFirstDestination)) return;
        for (const DestinationSection& seedSection : destinations) {
            const uint32_t key = storedFirstDestination ^ seedSection.rva;
            std::vector<PackerInfoEntry> entries;
            entries.reserve(destinations.size());
            for (size_t i = 0; i < destinations.size(); ++i) {
                uint32_t storedDestination = 0;
                if (!reader.u32(tableOffset + i * 8 + 4, storedDestination)) return;
                entries.push_back({sources[i],
                    storedDestination ^ rotateLeft32(key, static_cast<unsigned>(i * 7))});
            }
            if (!isDestinationPermutation(entries, destinations)) continue;

            PackerInfoCandidate candidate;
            candidate.format = PackerFormat::RotatingKey;
            candidate.tableFileOffset = static_cast<uint32_t>(tableOffset);
            candidate.destinationKey = key;
            candidate.lzmaProperties = {0x5D, 0x00, 0x00, 0x00, 0x04};
            if (!entriesPassLzmaProbe(pe, candidate.lzmaProperties, entries)) continue;
            candidate.entries = std::move(entries);
            addCandidate(candidates, std::move(candidate));
        }
    });
}

}  // namespace

PackerInfoDiscovery discoverPackerInfo(const PeFile& pe) {
    PackerInfoDiscovery result;
    if (!pe.valid) {
        result.diagnostic = "cannot inspect packed sections in an invalid PE";
        return result;
    }
    const auto destinations = packedDestinations(pe);
    if (destinations.empty()) {
        result.diagnostic = "no virtual-only initialized sections found";
        return result;
    }
    if (destinations.size() > kMaxPackerEntries) {
        result.diagnostic = "too many candidate packed sections";
        return result;
    }

    findLegacyCandidates(pe, destinations, result.candidates);
    // A clear destination table also satisfies the rotating-key equations with
    // key zero. Prefer the legacy form only when its linked property RVA validates.
    if (result.candidates.empty())
        findRotatingKeyCandidates(pe, destinations, result.candidates);
    if (result.candidates.empty()) {
        result.diagnostic = "no validated PACKER_INFO table found";
        return result;
    }
    if (result.candidates.size() != 1) {
        result.diagnostic = "multiple PACKER_INFO candidates; refusing to choose one";
        return result;
    }

    const PackerInfoCandidate& candidate = result.candidates.front();
    result.format = candidate.format;
    result.tableFileOffset = candidate.tableFileOffset;
    result.destinationKey = candidate.destinationKey;
    result.lzmaProperties = candidate.lzmaProperties;
    result.lzmaPropertiesFileOffset = candidate.lzmaPropertiesFileOffset;
    result.entries = candidate.entries;
    result.diagnostic = "unique PACKER_INFO table validated against packed destination sections";
    return result;
}

PackedSectionRecovery decompressPackedSections(const PeFile& pe,
                                              const PackerInfoDiscovery& discovery,
                                              std::vector<uint8_t>& image) {
    PackedSectionRecovery recovery;
    if (!pe.valid || !discovery.unique() || discovery.format == PackerFormat::Unknown ||
        image.size() < pe.sizeOfImage) {
        recovery.diagnostic = discovery.diagnostic;
        return recovery;
    }
    recovery.attempted = true;
    recovery.diagnostic = discovery.diagnostic;

    for (const PackerInfoEntry& entry : discovery.entries) {
        PackedBlockRecovery block;
        block.sourceRva = entry.sourceRva;
        block.destinationRva = entry.destinationRva;

        const Section* sourceSection = sectionForRva(pe, entry.sourceRva);
        const Section* destinationSection = sectionForRva(pe, entry.destinationRva);
        uint32_t sourceOffset = 0;
        if (!sourceSection || !destinationSection ||
            !rvaToFileOffset(pe, entry.sourceRva, sourceOffset)) {
            block.error = "source or destination RVA does not map to a valid section";
            recovery.blocks.push_back(std::move(block));
            continue;
        }

        const uint32_t sourceDelta = entry.sourceRva - sourceSection->va;
        if (sourceDelta >= sourceSection->rawSize || sourceOffset >= pe.bytes.size()) {
            block.error = "compressed source is outside file-backed section data";
            recovery.blocks.push_back(std::move(block));
            continue;
        }
        const size_t availableSource = std::min<size_t>(
            sourceSection->rawSize - sourceDelta, pe.bytes.size() - sourceOffset);
        block.sourceFileOffset = sourceOffset;
        block.sourceRangeSize = availableSource;
        const uint32_t destinationDelta = entry.destinationRva - destinationSection->va;
        if (destinationDelta >= destinationSection->mappedSize() ||
            entry.destinationRva >= image.size()) {
            block.error = "destination RVA is outside its mapped section";
            recovery.blocks.push_back(std::move(block));
            continue;
        }
        const size_t availableOutput = std::min<size_t>(
            destinationSection->mappedSize() - destinationDelta,
            image.size() - entry.destinationRva);
        const auto decoded = decompressRawLzma(discovery.lzmaProperties,
            pe.bytes.data() + sourceOffset, availableSource, availableOutput);
        if (!decoded.success) {
            block.error = decoded.error;
            recovery.blocks.push_back(std::move(block));
            continue;
        }

        std::copy(decoded.bytes.begin(), decoded.bytes.end(), image.begin() + entry.destinationRva);
        block.recovered = true;
        block.compressedSize = decoded.consumed;
        block.decompressedSize = decoded.bytes.size();
        recovery.recoveredBytes += decoded.bytes.size();
        recovery.blocks.push_back(std::move(block));
    }
    return recovery;
}

const char* packerFormatName(PackerFormat format) {
    switch (format) {
    case PackerFormat::LegacyPlaintext: return "legacy-plaintext";
    case PackerFormat::RotatingKey: return "rotating-key";
    case PackerFormat::Unknown: return "unknown";
    }
    return "unknown";
}

}  // namespace vmpstatic
