// Instruction decoding for handler classification. Capstone when compiled in, byte
// idioms otherwise; every class is coarse and evidence-tagged.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace vmpstatic {

const char* disasmEngineName();

struct HandlerClass {
    std::string name = "unknown";
    std::string detail;
};

HandlerClass classifyHandler(const uint8_t* code, size_t size, uint64_t address, bool is64);

}  // namespace vmpstatic
