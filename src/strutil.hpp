// Small shared string helpers (single definition point).
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace vmpstatic {

inline std::string hex(uint64_t v) {
    char buffer[24];
    std::snprintf(buffer, sizeof buffer, "0x%llX", static_cast<unsigned long long>(v));
    return buffer;
}

inline std::string toLower(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

}  // namespace vmpstatic
