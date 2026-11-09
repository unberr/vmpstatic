// Static import recovery: PE import directory plus VMProtect encoded import tables.
#pragma once

#include "pe.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace vmpstatic {

struct ImportEntry {
    std::string module;
    std::string name;  // empty when by ordinal
    uint32_t iatRva = 0;
    uint16_t ordinal = 0;
    bool byOrdinal = false;
};

struct ImportTable {
    std::vector<ImportEntry> entries;
    size_t moduleCount = 0;
    std::string error;
};

ImportTable parseImports(const PeFile& pe);

struct ApiReference {
    uint32_t siteRva = 0;       // referencing instruction (call/jmp/mov)
    uint32_t iatRva = 0;        // import slot it reads through
    std::string module;
    std::string name;           // empty when by ordinal
    uint16_t ordinal = 0;
    bool byOrdinal = false;
    bool packerSection = false; // reference sits in a packer-like section
};

// Indirect `call`/`jmp [rip+disp32]` / `[abs32]` sites (REX-prefixed forms included)
// and `mov reg,[mem]` loads that resolve to a parsed import slot.
// This is the static import-usage map inside VM code, without emulation.
std::vector<ApiReference> findApiReferences(const PeFile& pe, const ImportTable& imports,
                                            size_t maxRefs);

// vmpfix (archercreat/vmpfix) resolving core, detected statically and report-only:
//   lea reg, [rip+disp32] / mov reg, [reg+disp32] / lea reg, [reg+disp32]
// with the same register, back-to-back. Dynamic import fixers execute these stubs;
// here they are only counted as evidence of mutated import resolution (no emulation).
// Junk-separated variants are NOT detected: only contiguous triples match.
struct ResolverStubCore {
    uint32_t rva = 0;
    uint8_t reg = 0;          // full register id: 0-15 x64 (rax..rdi, r8..r15), 0-7 x86
    bool packerSection = false;
};

std::vector<ResolverStubCore> findResolverStubCores(const PeFile& pe, size_t maxRefs);

// Port of vmpunpack's rotating-XOR string cipher (unpack/discover.py).
uint8_t encodedByte(uint32_t key, size_t index);
void transformBytes(const uint8_t* in, size_t size, uint32_t key, std::vector<uint8_t>& out);

struct StringKey {
    uint32_t key = 0;
    size_t matches = 0;  // known-plaintext matches that validated the key
};
std::vector<StringKey> recoverStringKeys(const PeFile& pe);

struct EncodedImportRecord {
    std::string name;
    uint32_t slotRva = 0;
    uint32_t recordRva = 0;
    int32_t key = 0;
    uint16_t ordinal = 0;
    bool hasOrdinal = false;
    bool validated = false;
};

struct EncodedImportTable {
    uint32_t tableRva = 0;
    uint32_t moduleNameRva = 0;
    std::string module;
    std::vector<EncodedImportRecord> records;
};

// Structural recovery: records must decode to printable names with a recovered key.
// Names are checked against an export catalog in validateEncodedTables, when one is given.
std::vector<EncodedImportTable> findEncodedImportTables(const std::vector<uint8_t>& image,
                                                        const std::vector<uint32_t>& keys);

struct CatalogModule {
    std::string name;  // normalized module name, e.g. "ntdll.dll"
    const PeFile* pe = nullptr;
};

// Export name -> ordinal per module, parsed from DLLs supplied on the command line.
struct ExportCatalog {
    std::map<std::string, std::map<std::string, uint16_t>> modules;  // lower-case name
    const std::map<std::string, uint16_t>* exports(const std::string& module) const;
};

ExportCatalog buildExportCatalog(const std::vector<CatalogModule>& inputs);

struct CatalogValidation {
    size_t tables = 0;
    size_t records = 0;
    size_t validated = 0;
    size_t dropped = 0;
    size_t unknownModules = 0;
};

// Drops records whose name is absent from a known module's export list.
CatalogValidation validateEncodedTables(std::vector<EncodedImportTable>& tables,
                                        const ExportCatalog& catalog);

}  // namespace vmpstatic
