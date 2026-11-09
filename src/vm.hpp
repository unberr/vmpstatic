// Static VM entry and handler-table discovery inside packer-like sections.
#pragma once

#include "detect.hpp"
#include "pe.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vmpstatic {

struct VmEntry {
    uint32_t rva = 0;
    Confidence confidence = Confidence::None;
    std::string evidence;
};

// Looks for a saved-register frame: pushfq followed by register pushes within 32 bytes.
std::optional<VmEntry> findVmEntry(const PeFile& pe);

struct HandlerInfo {
    uint32_t rva = 0;
    std::string cls;
    std::string detail;
};

struct HandlerTable {
    uint32_t rva = 0;
    std::string section;
    size_t count = 0;
    Confidence confidence = Confidence::None;
    std::vector<HandlerInfo> handlers;
};

// Runs of RVAs that all land on executable section bytes, found inside packer-like
// sections; classified per entry by the first meaningful instruction.
std::vector<HandlerTable> findHandlerTables(const PeFile& pe, size_t maxTables);

struct VmDispatcher {
    uint32_t rva = 0;        // site of the indexed indirect jump
    std::string pattern;     // decoded operand hint
    uint32_t tableRva = 0;   // candidate table base, 0 when unresolved
    bool resolved = false;   // tableRva's first entries point at executable code
    Confidence confidence = Confidence::None;
};

// Indexed indirect jumps (`jmp [reg*8 + disp32]`, the VMProtect 3.x dispatch form) inside
// packer-like sections. The disp32 is read as an RVA or a VA, whichever yields a table of
// executable pointers.
std::vector<VmDispatcher> findVmDispatchers(const PeFile& pe, size_t maxDispatchers);

}  // namespace vmpstatic
