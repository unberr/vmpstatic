#include "imports.hpp"

#include "checked.hpp"
#include "oep.hpp"
#include "strutil.hpp"

#include <algorithm>
#include <cstring>
#include <optional>
#include <set>

namespace vmpstatic {
namespace {

constexpr size_t kMaxDescriptors = 4096;
constexpr size_t kMaxThunks = 65536;

std::optional<std::string> decodeName(const std::vector<uint8_t>& image, uint32_t rva,
                                      uint32_t key, size_t limit = 128) {
    if (rva == 0 || rva >= image.size()) return std::nullopt;
    const size_t available = std::min<size_t>(limit, image.size() - rva);
    std::string out;
    out.reserve(std::min<size_t>(available, 32));
    for (size_t i = 0; i < available; ++i) {
        const uint8_t c = static_cast<uint8_t>(image[rva + i] ^ encodedByte(key, i));
        if (c == 0) {
            if (out.size() < 2) return std::nullopt;
            return out;
        }
        if (c < 0x20 || c > 0x7E) return std::nullopt;
        out.push_back(static_cast<char>(c));
    }
    return std::nullopt;  // unterminated within the lookahead window
}

bool plausibleModuleName(const std::string& name) {
    if (name.size() <= 4 || name.size() > 64) return false;
    const size_t suffix = name.size() - 4;
    return name[suffix] == '.' &&
           (name[suffix + 1] == 'd' || name[suffix + 1] == 'D') &&
           (name[suffix + 2] == 'l' || name[suffix + 2] == 'L') &&
           (name[suffix + 3] == 'l' || name[suffix + 3] == 'L');
}

}  // namespace

uint8_t encodedByte(uint32_t key, size_t index) {
    const unsigned shift = static_cast<unsigned>(index & 31);
    const uint32_t rotated = shift ? ((key << shift) | (key >> (32 - shift))) : key;
    return static_cast<uint8_t>((rotated + static_cast<uint32_t>(index)) & 0xFF);
}

void transformBytes(const uint8_t* in, size_t size, uint32_t key, std::vector<uint8_t>& out) {
    out.resize(size);
    for (size_t i = 0; i < size; ++i) out[i] = static_cast<uint8_t>(in[i] ^ encodedByte(key, i));
}

ImportTable parseImports(const PeFile& pe) {
    ImportTable table;
    const DataDir& dir = pe.dirs[1];
    if (!dir.present()) {
        table.error = "no import directory";
        return table;
    }

    uint32_t descriptorOffset = 0;
    if (!rvaToFileOffset(pe, dir.rva, descriptorOffset)) {
        table.error = "import directory has no file data";
        return table;
    }
    const Section* descriptorSection = sectionForRva(pe, dir.rva);
    if (!descriptorSection || dir.rva - descriptorSection->va >= descriptorSection->rawSize) {
        table.error = "import directory has no bounded raw data";
        return table;
    }
    const size_t descriptorBytes = std::min<size_t>(
        dir.size, std::min<size_t>(pe.bytes.size() - descriptorOffset,
                                   descriptorSection->rawSize - (dir.rva - descriptorSection->va)));
    if (descriptorBytes < 20) {
        table.error = "import directory is smaller than one descriptor";
        return table;
    }

    const Reader reader(pe.bytes.data(), pe.bytes.size());
    const size_t ptrSize = pe.is64 ? 8 : 4;
    const uint64_t ordinalFlag = pe.is64 ? 0x8000000000000000ull : 0x80000000ull;
    std::set<std::string> modules;

    for (size_t index = 0; index < kMaxDescriptors && index * 20 + 20 <= descriptorBytes; ++index) {
        const size_t at = descriptorOffset + index * 20;
        uint32_t ilt = 0, nameRva = 0, iat = 0;
        if (!reader.u32(at, ilt) || !reader.u32(at + 12, nameRva) ||
            !reader.u32(at + 16, iat)) {
            break;
        }
        if (ilt == 0 && nameRva == 0 && iat == 0) break;

        std::string module;
        uint32_t nameOffset = 0;
        if (rvaToFileOffset(pe,nameRva, nameOffset) && reader.cstr(nameOffset, module) &&
            isPrintableAscii(module)) {
            modules.insert(module);
        } else {
            module = "<unreadable>";
        }

        const uint32_t thunkRva = ilt ? ilt : iat;
        const Section* thunkSection = sectionForRva(pe, thunkRva);
        uint32_t thunkOffset = 0;
        if (thunkRva == 0 || !thunkSection ||
            thunkRva - thunkSection->va >= thunkSection->rawSize ||
            !rvaToFileOffset(pe, thunkRva, thunkOffset)) {
            continue;
        }
        const size_t thunkBytes = std::min<size_t>(
            thunkSection->rawSize - (thunkRva - thunkSection->va), pe.bytes.size() - thunkOffset);
        const size_t thunkCount = std::min(kMaxThunks, thunkBytes / ptrSize);

        for (size_t t = 0; t < thunkCount; ++t) {
            const size_t slot = thunkOffset + t * ptrSize;
            uint64_t value = 0;
            const bool ok = pe.is64 ? reader.u64(slot, value)
                                    : [&] {
                                          uint32_t v = 0;
                                          if (!reader.u32(slot, v)) return false;
                                          value = v;
                                          return true;
                                      }();
            if (!ok) break;
            if (value == 0) break;

            ImportEntry entry;
            entry.module = module;
            const uint64_t iatRva = static_cast<uint64_t>(iat) + t * ptrSize;
            if (iatRva > UINT32_MAX) break;
            entry.iatRva = static_cast<uint32_t>(iatRva);
            if (value & ordinalFlag) {
                entry.byOrdinal = true;
                entry.ordinal = static_cast<uint16_t>(value & 0xFFFF);
                entry.name = "#" + std::to_string(entry.ordinal);
            } else {
                uint32_t hintOffset = 0;
                const uint32_t hintRva = static_cast<uint32_t>(value & 0x7FFFFFFF);
                if (!rvaToFileOffset(pe,hintRva, hintOffset) ||
                    !reader.cstr(hintOffset + 2, entry.name) || !isPrintableAscii(entry.name)) {
                    entry.name = "<unreadable>";
                }
            }
            table.entries.push_back(std::move(entry));
        }
    }

    table.moduleCount = modules.size();
    if (table.entries.empty() && table.error.empty()) table.error = "import table has no entries";
    return table;
}

std::vector<StringKey> recoverStringKeys(const PeFile& pe) {
    static const char* kPlaintexts[] = {"ZwQueryInformationProcess", "NtQueryInformationProcess"};
    std::vector<StringKey> keys;
    const size_t limit = std::min<size_t>(pe.bytes.size(), 64u << 20);
    keys.reserve(2);
    for (const char* text : kPlaintexts) {
        const size_t length = std::strlen(text) + 1;  // includes the trailing NUL
        if (limit < length) continue;
        const auto* plain = reinterpret_cast<const uint8_t*>(text);
        const uint8_t* const bytes = pe.bytes.data();
        const size_t lastOffset = limit - length;
        for (size_t offset = 0; offset <= lastOffset; ++offset) {
            const uint8_t* data = bytes + offset;
            const uint8_t first = static_cast<uint8_t>(data[0] ^ plain[0]);
            const uint8_t second = static_cast<uint8_t>(((data[1] ^ plain[1]) - 1) & 0xFF);
            if ((second & 254) != ((first << 1) & 254)) continue;
            const uint8_t third = static_cast<uint8_t>(((data[2] ^ plain[2]) - 2) & 0xFF);
            if ((third & 254) != ((second << 1) & 254)) continue;

            uint8_t stream[32] = {};
            stream[0] = first;
            stream[1] = second;
            stream[2] = third;
            size_t lastConsistent = 3;
            for (; lastConsistent < length; ++lastConsistent) {
                const uint8_t value = static_cast<uint8_t>(
                    ((data[lastConsistent] ^ plain[lastConsistent]) -
                     static_cast<int>(lastConsistent)) & 0xFF);
                if ((value & 254) != ((stream[lastConsistent - 1] << 1) & 254)) break;
                stream[lastConsistent] = value;
            }
            if (lastConsistent != length) continue;

            uint32_t key = first;
            for (size_t i = 1; i < 25; ++i) key |= static_cast<uint32_t>(stream[i] & 1) << (32 - i);
            bool matches = true;
            for (size_t i = 0; i < length; ++i) {
                if (static_cast<uint8_t>(data[i] ^ encodedByte(key, i)) != plain[i]) {
                    matches = false;
                    break;
                }
            }
            if (!matches) continue;

            const auto existing = std::find_if(keys.begin(), keys.end(),
                                               [key](const StringKey& k) { return k.key == key; });
            if (existing == keys.end()) {
                keys.push_back({key, 1});
            } else {
                ++existing->matches;
            }
        }
    }
    return keys;
}

std::vector<EncodedImportTable> findEncodedImportTables(const std::vector<uint8_t>& image,
                                                        const std::vector<uint32_t>& keys) {
    std::vector<EncodedImportTable> tables;
    if (image.size() < 16 || keys.empty()) return tables;

    const Reader reader(image.data(), image.size());
    for (uint32_t key : keys) {
        for (size_t cursor = 4; cursor + 12 <= image.size();) {
            uint32_t nameRva = 0, slotRva = 0;
            if (!reader.u32(cursor, nameRva) || !reader.u32(cursor + 4, slotRva)) break;
            if (nameRva == 0 || slotRva >= image.size()) {
                ++cursor;
                continue;
            }
            const auto firstName = decodeName(image, nameRva, key);
            if (!firstName || firstName->size() > 64) {
                ++cursor;
                continue;
            }

            std::vector<EncodedImportRecord> records;
            size_t at = cursor;
            bool terminated = false;
            for (size_t n = 0; n < 4096 && at + 12 <= image.size(); ++n) {
                uint32_t recordName = 0, recordSlot = 0, recordKey = 0;
                reader.u32(at, recordName);
                if (recordName == 0) {
                    terminated = true;
                    break;
                }
                reader.u32(at + 4, recordSlot);
                reader.u32(at + 8, recordKey);
                const auto name = decodeName(image, recordName, key);
                if (!name || recordSlot >= image.size()) break;
                records.push_back({*name, recordSlot, static_cast<uint32_t>(at),
                                   static_cast<int32_t>(recordKey)});
                at += 12;
            }
            if (!terminated || records.size() < 2) {
                ++cursor;
                continue;
            }

            EncodedImportTable table;
            table.tableRva = static_cast<uint32_t>(cursor) - 4;  // module-name pointer sits there
            reader.u32(cursor - 4, table.moduleNameRva);
            const auto module = decodeName(image, table.moduleNameRva, key);
            table.module = module && plausibleModuleName(*module) ? *module : "unknown";
            table.records = std::move(records);

            auto existing = std::find_if(tables.begin(), tables.end(),
                                         [&table](const EncodedImportTable& t) {
                                             return t.tableRva == table.tableRva;
                                         });
            if (existing == tables.end()) tables.push_back(std::move(table));
            cursor = at + 4;  // skip past the terminator
        }
    }

    std::sort(tables.begin(), tables.end(), [](const EncodedImportTable& a,
                                               const EncodedImportTable& b) {
        return a.tableRva < b.tableRva;
    });
    return tables;
}

namespace {

bool parseExports(const PeFile& pe, std::map<std::string, uint16_t>& out) {
    const DataDir& dir = pe.dirs[0];
    if (!dir.present()) return false;
    uint32_t directoryOffset = 0;
    if (!rvaToFileOffset(pe, dir.rva, directoryOffset)) return false;

    const Section* directorySection = sectionForRva(pe, dir.rva);
    if (!directorySection || dir.rva - directorySection->va >= directorySection->rawSize)
        return false;
    const size_t directoryBytes = std::min<size_t>(
        dir.size, std::min<size_t>(pe.bytes.size() - directoryOffset,
            directorySection->rawSize - (dir.rva - directorySection->va)));
    if (directoryBytes < 0x28) return false;
    const size_t directoryEnd = static_cast<size_t>(directoryOffset) + directoryBytes;
    if (directoryOffset > directoryEnd || 0x28 > directoryEnd - directoryOffset)
        return false;
    const Reader reader(pe.bytes.data(), pe.bytes.size());
    uint32_t ordinalBase = 0, functionCount = 0, nameCount = 0;
    uint32_t functionsRva = 0, namesRva = 0, ordinalsRva = 0;
    if (!reader.u32(directoryOffset + 0x10, ordinalBase) ||
        !reader.u32(directoryOffset + 0x14, functionCount) ||
        !reader.u32(directoryOffset + 0x18, nameCount) ||
        !reader.u32(directoryOffset + 0x1C, functionsRva) ||
        !reader.u32(directoryOffset + 0x20, namesRva) ||
        !reader.u32(directoryOffset + 0x24, ordinalsRva)) {
        return false;
    }
    if (nameCount > 65536) nameCount = 65536;

    uint32_t namesOffset = 0, ordinalsOffset = 0, functionsOffset = 0;
    if (!rvaToFileOffset(pe, namesRva, namesOffset) ||
        !rvaToFileOffset(pe, ordinalsRva, ordinalsOffset) ||
        !rvaToFileOffset(pe, functionsRva, functionsOffset)) return false;
    const Section* namesSection = sectionForRva(pe, namesRva);
    const Section* ordinalsSection = sectionForRva(pe, ordinalsRva);
    const Section* functionsSection = sectionForRva(pe, functionsRva);
    if (!namesSection || !ordinalsSection || !functionsSection ||
        namesRva - namesSection->va >= namesSection->rawSize ||
        ordinalsRva - ordinalsSection->va >= ordinalsSection->rawSize ||
        functionsRva - functionsSection->va >= functionsSection->rawSize) return false;
    const size_t namesRemaining = namesSection->rawSize - (namesRva - namesSection->va);
    const size_t ordinalsRemaining = ordinalsSection->rawSize - (ordinalsRva - ordinalsSection->va);
    const size_t functionRemaining = functionsSection->rawSize - (functionsRva - functionsSection->va);
    const size_t namesCountLimit = std::min<size_t>(nameCount,
        std::min(namesRemaining / 4, ordinalsRemaining / 2));
    if (namesCountLimit < nameCount) return false;
    const size_t functionCountLimit = functionRemaining / 4;
    if (functionCount > functionCountLimit) return false;

    for (size_t i = 0; i < namesCountLimit; ++i) {
        uint32_t nameRva = 0;
        uint16_t ordinalIndex = 0;
        if (!reader.u32(static_cast<size_t>(namesOffset) + i * 4, nameRva)) break;
        if (!reader.u16(static_cast<size_t>(ordinalsOffset) + i * 2, ordinalIndex)) break;
        if (ordinalIndex >= functionCount || ordinalIndex >= functionCountLimit) continue;
        const uint64_t ordinal = static_cast<uint64_t>(ordinalBase) + ordinalIndex;
        if (ordinal > 0xFFFF) continue;
        std::string name;
        uint32_t nameOffset = 0;
        if (!rvaToFileOffset(pe, nameRva, nameOffset) || !reader.cstr(nameOffset, name) ||
            !isPrintableAscii(name)) {
            continue;
        }
        out.emplace(std::move(name), static_cast<uint16_t>(ordinal));
    }
    return !out.empty();
}

}  // namespace

const std::map<std::string, uint16_t>* ExportCatalog::exports(const std::string& module) const {
    const auto it = modules.find(toLower(module));
    return it == modules.end() ? nullptr : &it->second;
}

ExportCatalog buildExportCatalog(const std::vector<CatalogModule>& inputs) {
    ExportCatalog catalog;
    for (const CatalogModule& input : inputs) {
        if (!input.pe || !input.pe->valid) continue;
        std::map<std::string, uint16_t> exports;
        if (!parseExports(*input.pe, exports)) continue;
        catalog.modules[toLower(input.name)] = std::move(exports);
    }
    return catalog;
}

CatalogValidation validateEncodedTables(std::vector<EncodedImportTable>& tables,
                                        const ExportCatalog& catalog) {
    CatalogValidation stats;
    std::vector<EncodedImportTable> kept;
    kept.reserve(tables.size());
    for (EncodedImportTable& table : tables) {
        const auto* exports = catalog.exports(table.module);
        if (!exports) {
            ++stats.unknownModules;
            stats.records += table.records.size();
            kept.push_back(std::move(table));
            continue;
        }
        ++stats.tables;
        EncodedImportTable filtered;
        filtered.tableRva = table.tableRva;
        filtered.moduleNameRva = table.moduleNameRva;
        filtered.module = table.module;
        for (EncodedImportRecord& record : table.records) {
            ++stats.records;
            const auto it = exports->find(record.name);
            if (it == exports->end()) {
                ++stats.dropped;
                continue;
            }
            record.ordinal = it->second;
            record.hasOrdinal = true;
            record.validated = true;
            ++stats.validated;
            filtered.records.push_back(std::move(record));
        }
        if (!filtered.records.empty()) kept.push_back(std::move(filtered));
    }
    tables = std::move(kept);
    return stats;
}

std::vector<ApiReference> findApiReferences(const PeFile& pe, const ImportTable& imports,
                                            size_t maxRefs) {
    std::vector<ApiReference> refs;
    if (imports.entries.empty() || maxRefs == 0) return refs;

    std::map<uint32_t, const ImportEntry*> bySlot;
    for (const ImportEntry& entry : imports.entries) bySlot[entry.iatRva] = &entry;

    constexpr size_t kScanCap = 4u << 20;
    for (const Section& sec : pe.sections) {
        if (!sec.exec || sec.rawPtr >= pe.bytes.size()) continue;
        const size_t available = std::min<size_t>(sec.rawSize, pe.bytes.size() - sec.rawPtr);
        const size_t limit = std::min(available, kScanCap);
        const bool packer = isPackerSection(sec);

        for (size_t i = 0; i + 6 <= limit && refs.size() < maxRefs; ++i) {
            const uint8_t* at = pe.bytes.data() + sec.rawPtr + i;
            // Optional REX.W prefix on x64 (`48 FF 25 ...`); site is the true start.
            size_t off = 0;
            if (pe.is64 && i + 7 <= limit && (at[0] & 0xF8) == 0x48 && at[1] == 0xFF &&
                (at[2] == 0x15 || at[2] == 0x25)) {
                off = 1;
            } else if (at[0] != 0xFF || (at[1] != 0x15 && at[1] != 0x25)) {
                continue;  // call/jmp [rip+disp32] / [abs32]
            }
            uint32_t target = 0;
            if (pe.is64) {
                const int32_t disp = static_cast<int32_t>(le32(at + off + 2));
                const int64_t resolved = static_cast<int64_t>(sec.va + i + 6 + off) + disp;
                if (resolved < 0 || resolved > 0xFFFFFFFFll) continue;
                target = static_cast<uint32_t>(resolved);
            } else if (!vaToRva(pe, le32(at + off + 2), target)) {
                continue;
            }

            const auto it = bySlot.find(target);
            if (it == bySlot.end()) continue;
            ApiReference ref;
            ref.siteRva = sec.va + static_cast<uint32_t>(i);
            ref.iatRva = target;
            ref.module = it->second->module;
            ref.name = it->second->name;
            ref.ordinal = it->second->ordinal;
            ref.byOrdinal = it->second->byOrdinal;
            ref.packerSection = packer;
            refs.push_back(std::move(ref));
            i += 5 + off;
        }
    }
    // mov reg, [rip+disp32] loads (vmpfix mov stubs read the IAT the same way;
    // x86 absolute form included; eax-only A1 form intentionally not covered).
    for (const Section& sec : pe.sections) {
        if (!sec.exec || sec.rawPtr >= pe.bytes.size()) continue;
        const size_t available = std::min<size_t>(sec.rawSize, pe.bytes.size() - sec.rawPtr);
        const size_t limit = std::min(available, kScanCap);
        const bool packer = isPackerSection(sec);
        for (size_t i = 0; i + 6 <= limit && refs.size() < maxRefs; ++i) {
            const uint8_t* at = pe.bytes.data() + sec.rawPtr + i;
            size_t ilen = 0;
            uint32_t target = 0;
            if (pe.is64 && i + 7 <= limit && (at[0] & 0xF8) == 0x48 && at[1] == 0x8B &&
                (at[2] & 0xC7) == 0x05) {
                const int32_t disp = static_cast<int32_t>(le32(at + 3));
                const int64_t resolved = static_cast<int64_t>(sec.va + i + 7) + disp;
                if (resolved < 0 || resolved > 0xFFFFFFFFll) continue;
                target = static_cast<uint32_t>(resolved);
                ilen = 7;
            } else if (at[0] == 0x8B && (at[1] & 0xC7) == 0x05) {
                if (pe.is64) {
                    const int32_t disp = static_cast<int32_t>(le32(at + 2));
                    const int64_t resolved = static_cast<int64_t>(sec.va + i + 6) + disp;
                    if (resolved < 0 || resolved > 0xFFFFFFFFll) continue;
                    target = static_cast<uint32_t>(resolved);
                } else if (!vaToRva(pe, le32(at + 2), target)) {
                    continue;
                }
                ilen = 6;
            } else {
                continue;
            }
            const auto it = bySlot.find(target);
            if (it == bySlot.end()) continue;
            ApiReference ref;
            ref.siteRva = sec.va + static_cast<uint32_t>(i);
            ref.iatRva = target;
            ref.module = it->second->module;
            ref.name = it->second->name;
            ref.ordinal = it->second->ordinal;
            ref.byOrdinal = it->second->byOrdinal;
            ref.packerSection = packer;
            refs.push_back(std::move(ref));
            i += ilen - 1;
        }
    }
    std::stable_sort(refs.begin(), refs.end(), [](const ApiReference& a, const ApiReference& b) {
        if (a.packerSection != b.packerSection) return a.packerSection;
        return a.siteRva < b.siteRva;
    });
    return refs;
}

// Matches one contiguous vmpfix resolving core at `at` (3 x 7 bytes on x64,
// 3 x 6 bytes on x86). Returns the full register id (0-15 x64, 0-7 x86), or -1.
// r/m field 4 always means a SIB byte follows, so those shapes are rejected.
int matchResolverCore(const uint8_t* at, size_t remaining, bool is64) {
    const size_t ilen = is64 ? 7 : 6;  // REX + opcode + ModRM + disp32, or no REX
    if (remaining < ilen * 3) return -1;
    uint8_t rex[3] = {0, 0, 0};
    if (is64) {
        for (size_t k = 0; k < 3; ++k) {
            const uint8_t b = at[k * ilen];
            if ((b & 0xF8) != 0x48) return -1;  // REX.W required
            rex[k] = b;
        }
    }
    const size_t ro = is64 ? 1 : 0;  // REX offset within each instruction
    const auto opc = [&](size_t insn) { return at[insn * ilen + ro]; };
    const auto mod = [&](size_t insn) { return at[insn * ilen + ro + 1]; };
    const auto fullReg = [&](size_t insn, uint8_t field) {
        return is64 ? static_cast<uint8_t>((((rex[insn] >> 2) & 1) << 3) | field)
                    : field;
    };
    // 1) lea reg, [rip+disp32] (x64) / lea reg, [disp32] (x86): mod=00, r/m=101
    if (opc(0) != 0x8D) return -1;
    const uint8_t m1 = mod(0);
    if ((m1 & 0xC7) != 0x05) return -1;
    const uint8_t f1 = (m1 >> 3) & 7;
    if (f1 == 4) return -1;
    const uint8_t want = fullReg(0, f1);
    // 2) mov reg, [reg+disp32] and 3) lea reg, [reg+disp32]: mod=10, reg == base
    for (size_t insn = 1; insn <= 2; ++insn) {
        const uint8_t m = mod(insn);
        if ((m & 0xC0) != 0x80) return -1;
        const uint8_t fr = (m >> 3) & 7, fb = m & 7;
        if (fr != fb || fr == 4) return -1;
        if (is64 && (((rex[insn] >> 2) & 1) != (rex[insn] & 1))) return -1;  // R==B
        if (fullReg(insn, fr) != want) return -1;
    }
    if (opc(1) != 0x8B || opc(2) != 0x8D) return -1;
    return want;
}

std::vector<ResolverStubCore> findResolverStubCores(const PeFile& pe, size_t maxRefs) {
    std::vector<ResolverStubCore> out;
    if (maxRefs == 0) return out;
    constexpr size_t kScanCap = 4u << 20;
    for (const Section& sec : pe.sections) {
        if (!sec.exec || sec.rawPtr >= pe.bytes.size()) continue;
        const size_t available = std::min<size_t>(sec.rawSize, pe.bytes.size() - sec.rawPtr);
        const size_t limit = std::min(available, kScanCap);
        const size_t step = pe.is64 ? 21 : 18;
        for (size_t i = 0; i + step <= limit && out.size() < maxRefs; ++i) {
            const int reg =
                matchResolverCore(pe.bytes.data() + sec.rawPtr + i, limit - i, pe.is64);
            if (reg < 0) continue;
            ResolverStubCore core;
            core.rva = sec.va + static_cast<uint32_t>(i);
            core.reg = static_cast<uint8_t>(reg);
            core.packerSection = isPackerSection(sec);
            out.push_back(core);
            i += step - 1;
        }
    }
    return out;
}

}  // namespace vmpstatic
