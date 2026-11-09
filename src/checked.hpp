// Bounds-checked little-endian access to untrusted bytes.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace vmpstatic {

inline uint16_t le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

inline uint32_t le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t le64(const uint8_t* p) {
    return static_cast<uint64_t>(le32(p)) | (static_cast<uint64_t>(le32(p + 4)) << 32);
}

class Reader {
public:
    Reader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    bool has(size_t off, size_t n) const { return off <= size_ && n <= size_ - off; }
    size_t size() const { return size_; }

    bool u16(size_t off, uint16_t& v) const {
        if (!has(off, 2)) return false;
        v = le16(data_ + off);
        return true;
    }
    bool u32(size_t off, uint32_t& v) const {
        if (!has(off, 4)) return false;
        v = le32(data_ + off);
        return true;
    }
    bool u64(size_t off, uint64_t& v) const {
        if (!has(off, 8)) return false;
        v = le64(data_ + off);
        return true;
    }
    bool bytes(size_t off, size_t n, std::vector<uint8_t>& out) const {
        if (!has(off, n)) return false;
        out.assign(data_ + off, data_ + off + n);
        return true;
    }
    // NUL-terminated ASCII, length cap keeps adversarial input from scanning the file.
    bool cstr(size_t off, std::string& out) const {
        out.clear();
        if (off >= size_) return false;
        for (size_t i = off; i < size_ && i - off < 512; ++i) {
            if (!data_[i]) return true;
            out.push_back(static_cast<char>(data_[i]));
        }
        return false;
    }

private:
    const uint8_t* data_;
    size_t size_;
};

inline bool isPrintableAscii(const std::string& s) {
    for (unsigned char c : s) {
        if (c < 0x20 || c > 0x7E) return false;
    }
    return !s.empty();
}

}  // namespace vmpstatic
