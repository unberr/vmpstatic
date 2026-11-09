#include "pe.hpp"

#include "checked.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace vmpstatic {
namespace {

uint64_t alignUp(uint64_t v, uint32_t a) {
    const uint64_t max = UINT64_MAX;
    if (!a) return v;
    if (v > max - (a - 1)) return max;
    const uint64_t rounded = ((v + a - 1) / a) * a;
    return rounded < v ? max : rounded;
}

constexpr uint16_t kPeMagic32 = 0x10B;
constexpr uint16_t kPeMagic64 = 0x20B;
constexpr size_t kMaxSections = 96;

}  // namespace

bool isVmpSectionName(const std::string& name) {
    // Same rule as unpaki's name_matches_vmp: optional leading '.' or '_', then "vmp".
    std::string lower;
    lower.reserve(name.size());
    for (char c : name) {
        lower.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
    }
    if (!lower.empty() && (lower[0] == '.' || lower[0] == '_')) lower.erase(0, 1);
    return lower.rfind("vmp", 0) == 0;
}

double entropyOf(const uint8_t* data, size_t size) {
    if (!data || size < 0x100) return 0.0;
    const size_t sample = std::min<size_t>(size, 0x8000);
    uint32_t freq[256] = {};
    for (size_t i = 0; i < sample; ++i) ++freq[data[i]];
    double h = 0.0;
    for (uint32_t f : freq) {
        if (!f) continue;
        const double p = static_cast<double>(f) / static_cast<double>(sample);
        h -= p * (std::log(p) / std::log(2.0));
    }
    return h;
}

PeFile parsePe(std::vector<uint8_t> bytes) {
    PeFile pe;
    pe.bytes = std::move(bytes);
    if (pe.bytes.size() > kMaxImage) {
        pe.error = "file exceeds the 1 GiB limit";
        return pe;
    }
    const Reader r(pe.bytes.data(), pe.bytes.size());

    auto fail = [&](const char* msg) {
        pe.valid = false;
        pe.error = msg;
        return pe;
    };

    if (!r.has(0, 0x40)) return fail("truncated DOS header");
    if (le16(pe.bytes.data()) != 0x5A4D) return fail("missing MZ signature");

    const int32_t lfanew = static_cast<int32_t>(le32(pe.bytes.data() + 0x3C));
    if (lfanew < 0 || !r.has(static_cast<size_t>(lfanew), 24)) return fail("invalid e_lfanew");
    const size_t nt = static_cast<size_t>(lfanew);
    if (le32(pe.bytes.data() + nt) != 0x00004550) return fail("missing PE signature");

    pe.machine = le16(pe.bytes.data() + nt + 4);
    const uint16_t numberOfSections = le16(pe.bytes.data() + nt + 6);
    const uint16_t optionalSize = le16(pe.bytes.data() + nt + 20);
    const size_t opt = nt + 24;

    uint16_t magic = 0;
    if (!r.has(opt, 2)) return fail("truncated optional header");
    magic = le16(pe.bytes.data() + opt);
    if (magic == kPeMagic64) {
        pe.is64 = true;
    } else if (magic == kPeMagic32) {
        pe.is64 = false;
    } else {
        return fail("unknown optional header magic");
    }

    const size_t commonEnd = pe.is64 ? 0x70 : 0x60;
    if (optionalSize < commonEnd || !r.has(opt, commonEnd)) return fail("truncated optional header");

    const uint8_t* o = pe.bytes.data() + opt;
    pe.entryPoint = le32(o + 0x10);
    pe.imageBase = pe.is64 ? le64(o + 0x18) : static_cast<uint64_t>(le32(o + 0x1C));
    pe.sectionAlign = le32(o + 0x20);
    pe.fileAlign = le32(o + 0x24);
    pe.sizeOfImage = le32(o + 0x38);
    pe.sizeOfHeaders = le32(o + 0x3C);
    pe.numberOfRvaAndSizes = le32(o + (pe.is64 ? 0x6C : 0x5C));
    if (pe.numberOfRvaAndSizes > 16) pe.numberOfRvaAndSizes = 16;

    const size_t dirOff = opt + (pe.is64 ? 0x70 : 0x60);
    if (optionalSize >= (pe.is64 ? 0x70u : 0x60u) + 5u * 8u &&
        r.has(dirOff + 4u * 8u, 8)) {
        pe.securityDirectoryEntryOffset = dirOff + 4u * 8u;
    }
    for (uint32_t i = 0; i < pe.numberOfRvaAndSizes; ++i) {
        if (!r.has(dirOff + static_cast<size_t>(i) * 8, 8)) break;
        pe.dirs[i].rva = le32(pe.bytes.data() + dirOff + i * 8);
        pe.dirs[i].size = le32(pe.bytes.data() + dirOff + i * 8 + 4);
    }

    if (pe.sizeOfImage == 0) return fail("SizeOfImage is zero");
    if (pe.sizeOfImage > kMaxImage) return fail("SizeOfImage exceeds the 1 GiB limit");

    pe.optionalHeaderOffset = opt;
    pe.sectionTableOffset = opt + optionalSize;
    if (numberOfSections == 0) return fail("no sections");
    if (numberOfSections > kMaxSections) return fail("too many sections");
    if (!r.has(pe.sectionTableOffset, static_cast<size_t>(numberOfSections) * 40)) {
        return fail("truncated section table");
    }

    uint32_t overlayEnd = 0;
    for (uint16_t i = 0; i < numberOfSections; ++i) {
        const size_t at = pe.sectionTableOffset + static_cast<size_t>(i) * 40;
        const uint8_t* s = pe.bytes.data() + at;

        Section sec;
        char raw[9] = {};
        std::memcpy(raw, s, 8);
        raw[8] = 0;
        sec.name = raw;
        sec.vsize = le32(s + 8);
        sec.va = le32(s + 12);
        sec.rawSize = le32(s + 16);
        sec.rawPtr = le32(s + 20);
        sec.characteristics = le32(s + 36);
        sec.exec = (sec.characteristics & kScnExec) != 0;
        sec.write = (sec.characteristics & kScnWrite) != 0;
        sec.read = (sec.characteristics & kScnRead) != 0;
        sec.vmpName = isVmpSectionName(sec.name);

        if (sec.rawPtr < pe.bytes.size() && sec.rawSize) {
            const size_t avail = pe.bytes.size() - sec.rawPtr;
            sec.entropy = entropyOf(pe.bytes.data() + sec.rawPtr, std::min<size_t>(sec.rawSize, avail));
        }
        const uint64_t rawEnd = static_cast<uint64_t>(sec.rawPtr) + sec.rawSize;
        if (sec.rawSize && rawEnd > pe.bytes.size()) {
            pe.diagnostics.push_back("section " + sec.name + " raw data is truncated");
        }
        if (sec.mappedSize() &&
            static_cast<uint64_t>(sec.va) + sec.mappedSize() > pe.sizeOfImage) {
            pe.diagnostics.push_back("section " + sec.name + " extends beyond SizeOfImage");
        }
        overlayEnd = std::max<uint32_t>(overlayEnd, static_cast<uint32_t>(
            std::min<uint64_t>(rawEnd, UINT32_MAX)));
        pe.sections.push_back(std::move(sec));
    }

    for (size_t i = 0; i < pe.sections.size(); ++i) {
        const Section& a = pe.sections[i];
        for (size_t j = i + 1; j < pe.sections.size(); ++j) {
            const Section& b = pe.sections[j];
            const uint64_t aVaEnd = static_cast<uint64_t>(a.va) + a.mappedSize();
            const uint64_t bVaEnd = static_cast<uint64_t>(b.va) + b.mappedSize();
            if (a.mappedSize() && b.mappedSize() && a.va < bVaEnd && b.va < aVaEnd)
                pe.diagnostics.push_back("virtual sections " + a.name + " and " + b.name + " overlap");
            const uint64_t aRawEnd = static_cast<uint64_t>(a.rawPtr) + a.rawSize;
            const uint64_t bRawEnd = static_cast<uint64_t>(b.rawPtr) + b.rawSize;
            if (a.rawSize && b.rawSize && a.rawPtr < bRawEnd && b.rawPtr < aRawEnd)
                pe.diagnostics.push_back("raw sections " + a.name + " and " + b.name + " overlap");
        }
    }

    pe.overlayOffset = std::min<uint32_t>(overlayEnd, static_cast<uint32_t>(pe.bytes.size()));
    if (pe.fileAlign && (pe.fileAlign & (pe.fileAlign - 1))) return fail("FileAlignment is not a power of two");
    if (pe.sectionAlign && (pe.sectionAlign & (pe.sectionAlign - 1))) {
        return fail("SectionAlignment is not a power of two");
    }

    if (pe.entryPoint >= pe.sizeOfImage || !sectionForRva(pe, pe.entryPoint))
        pe.diagnostics.push_back("AddressOfEntryPoint is outside all mapped sections");

    pe.valid = true;
    return pe;
}

const Section* sectionForRva(const PeFile& pe, uint32_t rva) {
    for (const Section& s : pe.sections) {
        if (rva >= s.va && rva - s.va < s.mappedSize()) return &s;
    }
    return nullptr;
}

Section* sectionForRva(PeFile& pe, uint32_t rva) {
    return const_cast<Section*>(sectionForRva(static_cast<const PeFile&>(pe), rva));
}

bool rvaToFileOffset(const PeFile& pe, uint32_t rva, uint32_t& offset) {
    const Section* s = sectionForRva(pe, rva);
    if (!s) return false;
    const uint32_t delta = rva - s->va;
    if (delta >= s->rawSize) return false;
    const uint64_t absolute = static_cast<uint64_t>(s->rawPtr) + delta;
    if (absolute >= pe.bytes.size() || absolute >= pe.overlayOffset) return false;
    offset = static_cast<uint32_t>(absolute);
    return true;
}

bool vaToRva(const PeFile& pe, uint64_t va, uint32_t& rva) {
    if (va < pe.imageBase) return false;
    const uint64_t delta = va - pe.imageBase;
    if (delta >= pe.sizeOfImage) return false;
    rva = static_cast<uint32_t>(delta);
    return true;
}

bool fileToImage(const PeFile& pe, std::vector<uint8_t>& image, std::string& error) {
    error.clear();
    if (!pe.valid) {
        error = pe.error.empty() ? "invalid PE" : pe.error;
        return false;
    }
    image.assign(pe.sizeOfImage, 0);

    const size_t headerCopy = std::min<size_t>(pe.sizeOfHeaders, pe.bytes.size());
    if (headerCopy) std::memcpy(image.data(), pe.bytes.data(), headerCopy);

    for (const Section& s : pe.sections) {
        const uint32_t mappedSize = s.mappedSize();
        if (!mappedSize || s.va >= image.size()) continue;
        size_t copy = std::min(s.rawSize, mappedSize);
        copy = std::min<size_t>(copy, image.size() - s.va);
        if (s.rawPtr >= pe.bytes.size()) continue;
        copy = std::min<size_t>(copy, pe.bytes.size() - s.rawPtr);
        if (copy) std::memcpy(image.data() + s.va, pe.bytes.data() + s.rawPtr, copy);
    }
    return true;
}

bool imageToFile(const PeFile& pe, const std::vector<uint8_t>& image, std::vector<uint8_t>& out,
                 std::string& error) {
    error.clear();
    if (!pe.valid) {
        error = pe.error.empty() ? "invalid PE" : pe.error;
        return false;
    }
    if (image.size() < pe.sizeOfImage) {
        error = "image buffer is smaller than SizeOfImage";
        return false;
    }

    const uint32_t fileAlign = pe.fileAlign ? pe.fileAlign : 0x200;
    for (size_t i = 0; i < pe.sections.size(); ++i) {
        const Section& a = pe.sections[i];
        if (a.mappedSize() && static_cast<uint64_t>(a.va) + a.mappedSize() > pe.sizeOfImage) {
            error = "section " + a.name + " extends beyond SizeOfImage";
            return false;
        }
        for (size_t j = i + 1; j < pe.sections.size(); ++j) {
            const Section& b = pe.sections[j];
            const uint64_t aEnd = static_cast<uint64_t>(a.va) + a.mappedSize();
            const uint64_t bEnd = static_cast<uint64_t>(b.va) + b.mappedSize();
            if (a.mappedSize() && b.mappedSize() && a.va < bEnd && b.va < aEnd) {
                error = "cannot reconstruct overlapping virtual sections";
                return false;
            }
        }
    }
    const uint64_t alignedHeaders = alignUp(pe.sizeOfHeaders ? pe.sizeOfHeaders : 0x400, fileAlign);
    if (alignedHeaders == UINT64_MAX || alignedHeaders > kMaxImage) {
        error = "reconstructed headers exceed the 1 GiB limit";
        return false;
    }
    uint64_t headers = alignedHeaders;
    const size_t tableEnd =
        pe.sectionTableOffset + pe.sections.size() * static_cast<size_t>(40);
    if (tableEnd < pe.sectionTableOffset) {
        error = "section table size overflows";
        return false;
    }
    if (headers < tableEnd) headers = alignUp(tableEnd, fileAlign);
    if (headers == UINT64_MAX || headers > image.size() || headers > kMaxImage) {
        error = "image is smaller than its own headers or header alignment overflows";
        return false;
    }

    std::vector<uint32_t> rawSize(pe.sections.size()), rawPtr(pe.sections.size());
    uint64_t cursor = headers;
    for (size_t i = 0; i < pe.sections.size(); ++i) {
        const uint32_t size = pe.sections[i].mappedSize();
        const uint64_t alignedSize = alignUp(size ? size : 1, fileAlign);
        if (alignedSize == UINT64_MAX || alignedSize > UINT32_MAX || cursor > UINT32_MAX ||
            alignedSize > kMaxImage - cursor || alignedSize > UINT32_MAX - cursor) {
            error = "reconstructed image exceeds the 1 GiB or PE field limit";
            return false;
        }
        rawSize[i] = static_cast<uint32_t>(alignedSize);
        rawPtr[i] = static_cast<uint32_t>(cursor);
        cursor += alignedSize;
    }
    const uint64_t overlaySize = pe.hasOverlay() ? pe.bytes.size() - pe.overlayOffset : 0;
    if (overlaySize > kMaxImage - cursor || cursor + overlaySize > UINT32_MAX) {
        error = "reconstructed image with overlay exceeds the 1 GiB or PE field limit";
        return false;
    }

    out.assign(static_cast<size_t>(cursor + overlaySize), 0);
    std::memcpy(out.data(), image.data(), static_cast<size_t>(headers));
    if (pe.securityDirectoryEntryOffset && pe.securityDirectoryEntryOffset <= headers &&
        8 <= headers - pe.securityDirectoryEntryOffset) {
        std::fill_n(out.data() + pe.securityDirectoryEntryOffset, 8, 0);
    }

    for (size_t i = 0; i < pe.sections.size(); ++i) {
        uint8_t* entry = out.data() + pe.sectionTableOffset + i * 40;
        std::memcpy(entry + 16, &rawSize[i], 4);
        std::memcpy(entry + 20, &rawPtr[i], 4);
        if (pe.sections[i].va >= image.size()) continue;
        const uint32_t vsize = pe.sections[i].mappedSize();
        const size_t copy = std::min<size_t>(vsize, image.size() - pe.sections[i].va);
        if (copy) std::memcpy(out.data() + rawPtr[i], image.data() + pe.sections[i].va, copy);
    }
    if (overlaySize) {
        std::memcpy(out.data() + cursor, pe.bytes.data() + pe.overlayOffset,
                    static_cast<size_t>(overlaySize));
    }
    return true;
}

}  // namespace vmpstatic
