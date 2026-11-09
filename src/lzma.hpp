// Bounded raw LZMA1 decompression used by static packed-section recovery.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace vmpstatic {

struct LzmaDecodeResult {
    bool success = false;
    size_t consumed = 0;
    std::vector<uint8_t> bytes;
    std::string error;
};

LzmaDecodeResult decompressRawLzma(const std::array<uint8_t, 5>& properties,
                                   const std::vector<uint8_t>& compressed,
                                   size_t outputLimit);
LzmaDecodeResult decompressRawLzma(const std::array<uint8_t, 5>& properties,
                                   const uint8_t* compressed, size_t compressedSize,
                                   size_t outputLimit);
bool probeRawLzma(const std::array<uint8_t, 5>& properties, const uint8_t* compressed,
                  size_t compressedSize, size_t probeSize = 512);

}  // namespace vmpstatic
