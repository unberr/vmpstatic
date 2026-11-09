#include "vm.hpp"

#include "checked.hpp"
#include "disasm.hpp"
#include "oep.hpp"
#include "strutil.hpp"

#include <algorithm>
#include <cstdio>
#include <set>
#include <string>

namespace vmpstatic {
namespace {

constexpr size_t kEntryScanBytes = 0x400;
constexpr size_t kMaxTableScan = 4u << 20;
constexpr size_t kMinEntries = 8;
constexpr size_t kMaxEntries = 4096;

bool executableRva(const PeFile& pe, uint32_t rva) {
    if (rva == 0 || rva >= pe.sizeOfImage) return false;
    const Section* s = sectionForRva(pe, rva);
    return s && s->exec;
}

bool isPackerLike(const Section& s) { return s.exec && isPackerSection(s); }

}  // namespace

std::optional<VmEntry> findVmEntry(const PeFile& pe) {
    std::optional<VmEntry> best;
    for (const Section& sec : pe.sections) {
        if (!isPackerLike(sec) || sec.rawPtr >= pe.bytes.size()) continue;
        const size_t available = std::min<size_t>(sec.rawSize, pe.bytes.size() - sec.rawPtr);
        const size_t limit = std::min(available, kEntryScanBytes);
        const uint8_t* data = pe.bytes.data() + sec.rawPtr;

        for (size_t i = 0; i + 2 < limit; ++i) {
            if (data[i] != 0x9C) continue;  // pushfq
            size_t pushes = 0;
            for (size_t j = i + 1; j < limit && j < i + 32; ++j) {
                if (data[j] >= 0x50 && data[j] <= 0x57) {
                    ++pushes;
                } else if (data[j] == 0x41 && j + 1 < limit && data[j + 1] >= 0x50 &&
                           data[j + 1] <= 0x57) {
                    ++pushes;
                    ++j;
                }
            }
            if (pushes < 2) continue;
            VmEntry entry;
            entry.rva = sec.va + static_cast<uint32_t>(i);
            entry.confidence = pushes >= 6 ? Confidence::High : Confidence::Low;
            entry.evidence = "pushfq + " + std::to_string(pushes) + " register pushes at rva " +
                             hex(entry.rva);
            if (!best || entry.confidence > best->confidence) best = entry;
            if (entry.confidence == Confidence::High) return best;
        }
    }
    return best;
}

namespace {

// True when the 8 dwords at rva are executable-code RVAs (a handler table).
bool tableLooksExecutable(const PeFile& pe, uint32_t rva) {
    const size_t available = pe.sizeOfImage > rva ? pe.sizeOfImage - rva : 0;
    if (available < 8 * 4) return false;
    uint32_t offset = 0;
    if (!rvaToFileOffset(pe, rva, offset)) return false;
    if (pe.bytes.size() - offset < 8 * 4) return false;
    const Reader reader(pe.bytes.data(), pe.bytes.size());
    for (int i = 0; i < 8; ++i) {
        uint32_t entry = 0;
        if (!reader.u32(offset + static_cast<size_t>(i) * 4, entry)) return false;
        if (!executableRva(pe, entry)) return false;
    }
    return true;
}

uint32_t resolveTableRva(const PeFile& pe, uint32_t raw) {
    if (tableLooksExecutable(pe, raw)) return raw;
    if (raw > pe.imageBase) {
        const uint64_t rva = raw - pe.imageBase;
        if (rva < pe.sizeOfImage && tableLooksExecutable(pe, static_cast<uint32_t>(rva))) {
            return static_cast<uint32_t>(rva);
        }
    }
    return 0;
}

}  // namespace

std::vector<VmDispatcher> findVmDispatchers(const PeFile& pe, size_t maxDispatchers) {
    std::vector<VmDispatcher> found;
    const Reader reader(pe.bytes.data(), pe.bytes.size());

    for (const Section& sec : pe.sections) {
        if (!isPackerLike(sec) || sec.rawPtr >= pe.bytes.size()) continue;
        const size_t available = std::min<size_t>(std::min(sec.rawSize, sec.mappedSize()),
                                                  kMaxTableScan);
        const size_t limit = std::min(available, pe.bytes.size() - sec.rawPtr);

        for (size_t i = 0; i + 7 <= limit && found.size() < maxDispatchers; ++i) {
            const uint8_t* at = pe.bytes.data() + sec.rawPtr + i;
            if (at[0] != 0xFF || at[1] != 0x24) continue;  // jmp r/m64, ModRM 0x24 = [SIB]
            const uint8_t sib = at[2];
            if ((sib & 0x07) != 0x05) continue;  // no base: disp32 follows
            const uint8_t index = static_cast<uint8_t>((sib >> 3) & 0x07);
            if (index == 4) continue;  // rsp cannot be an index
            uint32_t raw = 0;
            if (!reader.u32(sec.rawPtr + i + 3, raw)) continue;

            VmDispatcher d;
            d.rva = sec.va + static_cast<uint32_t>(i);
            const unsigned scale = 1u << (sib >> 6);
            d.pattern = "jmp qword ptr [r" + std::string(1, static_cast<char>('a' + index)) +
                        "*" + std::to_string(scale) + " + disp32]";
            const uint32_t tableRva = resolveTableRva(pe, raw);
            if (tableRva) {
                d.tableRva = tableRva;
                d.resolved = true;
                d.confidence = Confidence::High;
            } else {
                d.confidence = Confidence::Low;
            }
            found.push_back(std::move(d));
            i += 6;
        }
    }

    std::sort(found.begin(), found.end(), [](const VmDispatcher& a, const VmDispatcher& b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.rva < b.rva;
    });
    if (found.size() > maxDispatchers) found.resize(maxDispatchers);
    return found;
}

std::vector<HandlerTable> findHandlerTables(const PeFile& pe, size_t maxTables) {
    std::vector<HandlerTable> tables;
    const Reader reader(pe.bytes.data(), pe.bytes.size());

    for (const Section& sec : pe.sections) {
        if (!isPackerLike(sec) || sec.rawPtr >= pe.bytes.size()) continue;
        const size_t available = std::min<size_t>(std::min(sec.rawSize, sec.mappedSize()),
                                                  kMaxTableScan);
        const size_t limit = std::min(available, pe.bytes.size() - sec.rawPtr);

        for (size_t i = 0; i + kMinEntries * 4 <= limit && tables.size() < maxTables;) {
            size_t count = 0;
            std::set<uint32_t> distinct;
            while (count < kMaxEntries && i + (count + 1) * 4 <= limit) {
                uint32_t rva = 0;
                if (!reader.u32(sec.rawPtr + i + count * 4, rva)) break;
                if (!executableRva(pe, rva)) break;
                distinct.insert(rva);
                ++count;
            }
            if (count < kMinEntries || distinct.size() < kMinEntries - 2) {
                i += 4;
                continue;
            }

            HandlerTable table;
            table.rva = sec.va + static_cast<uint32_t>(i);
            table.section = sec.name;
            table.count = count;
            table.confidence = count >= 16 ? Confidence::High : Confidence::Medium;
            table.handlers.reserve(count);
            for (size_t n = 0; n < count; ++n) {
                uint32_t rva = 0;
                reader.u32(sec.rawPtr + i + n * 4, rva);
                HandlerInfo info;
                info.rva = rva;
                uint32_t offset = 0;
                if (rvaToFileOffset(pe, rva, offset)) {
                    const size_t left = std::min<size_t>(64, pe.bytes.size() - offset);
                    const HandlerClass cls = classifyHandler(pe.bytes.data() + offset, left,
                                                             pe.imageBase + rva, pe.is64);
                    info.cls = cls.name;
                    info.detail = cls.detail;
                } else {
                    info.detail = "no file data";
                }
                table.handlers.push_back(std::move(info));
            }
            tables.push_back(std::move(table));
            i += count * 4;
        }
    }

    std::sort(tables.begin(), tables.end(), [](const HandlerTable& a, const HandlerTable& b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.rva < b.rva;
    });
    if (tables.size() > maxTables) tables.resize(maxTables);
    return tables;
}

}  // namespace vmpstatic
