// PE32/PE32+ parsing, layout conversion and section analysis. Portable, no Win32.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vmpstatic {

constexpr uint32_t kScnExec = 0x20000000u;
constexpr uint32_t kScnRead = 0x40000000u;
constexpr uint32_t kScnWrite = 0x80000000u;
constexpr size_t kMaxImage = 1u << 30;  // 1 GiB ceiling for any allocation

struct DataDir {
    uint32_t rva = 0;
    uint32_t size = 0;
    bool present() const { return rva != 0 && size != 0; }
};

struct Section {
    std::string name;
    uint32_t va = 0;
    uint32_t vsize = 0;
    uint32_t rawPtr = 0;
    uint32_t rawSize = 0;
    uint32_t characteristics = 0;
    double entropy = 0.0;
    bool exec = false;
    bool write = false;
    bool read = false;
    bool vmpName = false;

    uint32_t mappedSize() const { return vsize ? vsize : rawSize; }
};

struct PeFile {
    std::vector<uint8_t> bytes;
    bool valid = false;
    std::string error;
    std::vector<std::string> diagnostics;

    bool is64 = false;
    uint16_t machine = 0;
    uint64_t imageBase = 0;
    uint32_t entryPoint = 0;
    uint32_t sizeOfImage = 0;
    uint32_t sizeOfHeaders = 0;
    uint32_t sectionAlign = 0;
    uint32_t fileAlign = 0;
    uint32_t numberOfRvaAndSizes = 0;
    DataDir dirs[16];

    std::vector<Section> sections;
    size_t optionalHeaderOffset = 0;
    size_t sectionTableOffset = 0;
    uint32_t overlayOffset = 0;  // end of the last section's raw data
    uint32_t securityDirectoryEntryOffset = 0;

    bool hasOverlay() const { return overlayOffset < bytes.size(); }
};

PeFile parsePe(std::vector<uint8_t> bytes);

const Section* sectionForRva(const PeFile& pe, uint32_t rva);
Section* sectionForRva(PeFile& pe, uint32_t rva);
bool vaToRva(const PeFile& pe, uint64_t va, uint32_t& rva);

// RVA to file offset, only when the byte range is backed by section raw data.
bool rvaToFileOffset(const PeFile& pe, uint32_t rva, uint32_t& offset);

bool isVmpSectionName(const std::string& name);
double entropyOf(const uint8_t* data, size_t size);

// Expands file layout into a SizeOfImage memory image (zero-filled gaps).
bool fileToImage(const PeFile& pe, std::vector<uint8_t>& image, std::string& error);

// Rewrites a memory image into a valid file layout with correct raw pointers.
bool imageToFile(const PeFile& pe, const std::vector<uint8_t>& image, std::vector<uint8_t>& out,
                 std::string& error);

}  // namespace vmpstatic
