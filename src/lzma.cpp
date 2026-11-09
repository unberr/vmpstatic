#include "lzma.hpp"

#include "LzmaDec.h"
#include "pe.hpp"

#include <cstdlib>
#include <limits>

namespace vmpstatic {
namespace {

constexpr size_t kMaxDictionarySize = 256u << 20;

void* allocateLzmaMemory(ISzAllocPtr, size_t size) { return std::malloc(size); }
void freeLzmaMemory(ISzAllocPtr, void* address) { std::free(address); }

const ISzAlloc kAllocator = {allocateLzmaMemory, freeLzmaMemory};

}  // namespace

LzmaDecodeResult decompressRawLzma(const std::array<uint8_t, 5>& properties,
                                   const std::vector<uint8_t>& compressed,
                                   size_t outputLimit) {
    return decompressRawLzma(properties, compressed.data(), compressed.size(), outputLimit);
}

LzmaDecodeResult decompressRawLzma(const std::array<uint8_t, 5>& properties,
                                   const uint8_t* compressed, size_t compressedSize,
                                   size_t outputLimit) {
    LzmaDecodeResult result;
    if (properties[0] >= 9 * 5 * 5) {
        result.error = "invalid LZMA property byte";
        return result;
    }
    const uint32_t dictionarySize = static_cast<uint32_t>(properties[1]) |
        (static_cast<uint32_t>(properties[2]) << 8) |
        (static_cast<uint32_t>(properties[3]) << 16) |
        (static_cast<uint32_t>(properties[4]) << 24);
    if (dictionarySize > kMaxDictionarySize) {
        result.error = "LZMA dictionary exceeds the 256 MiB safety limit";
        return result;
    }
    if (!compressed || compressedSize == 0 || outputLimit == 0 || outputLimit > kMaxImage ||
        compressedSize > kMaxImage) {
        result.error = "invalid LZMA input or output limit";
        return result;
    }

    result.bytes.resize(outputLimit);
    SizeT outputSize = result.bytes.size();
    SizeT inputSize = compressedSize;
    ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
    const SRes code = LzmaDecode(result.bytes.data(), &outputSize, compressed, &inputSize,
                                 properties.data(), properties.size(), LZMA_FINISH_END,
                                 &status, &kAllocator);
    result.bytes.resize(outputSize);
    result.consumed = inputSize;
    if (code != SZ_OK) {
        result.error = "LZMA decoder returned error " + std::to_string(code);
        result.bytes.clear();
        return result;
    }
    if (status != LZMA_STATUS_FINISHED_WITH_MARK) {
        result.error = outputSize == outputLimit
            ? "decompressed output exceeds the destination section"
            : "LZMA stream ended without a validated end marker";
        result.bytes.clear();
        return result;
    }

    result.success = true;
    return result;
}

bool probeRawLzma(const std::array<uint8_t, 5>& properties, const uint8_t* compressed,
                  size_t compressedSize, size_t probeSize) {
    if (!compressed || compressedSize == 0 || probeSize == 0 || probeSize > (1u << 20) ||
        properties[0] >= 9 * 5 * 5) return false;
    const uint32_t dictionarySize = static_cast<uint32_t>(properties[1]) |
        (static_cast<uint32_t>(properties[2]) << 8) |
        (static_cast<uint32_t>(properties[3]) << 16) |
        (static_cast<uint32_t>(properties[4]) << 24);
    if (dictionarySize > kMaxDictionarySize) return false;

    std::vector<uint8_t> output(probeSize);
    SizeT outputSize = output.size();
    SizeT inputSize = compressedSize;
    ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
    const SRes code = LzmaDecode(output.data(), &outputSize, compressed, &inputSize,
                                 properties.data(), properties.size(), LZMA_FINISH_ANY,
                                 &status, &kAllocator);
    if (code != SZ_OK || outputSize == 0) return false;
    return status == LZMA_STATUS_FINISHED_WITH_MARK ||
           (status == LZMA_STATUS_NOT_FINISHED && outputSize == output.size());
}

}  // namespace vmpstatic
