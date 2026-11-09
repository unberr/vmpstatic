// Synthetic-PE tests: parser, layout conversion, detection, OEP, imports, encoded tables.
#include "analysis.hpp"
#include "checked.hpp"
#include "detect.hpp"
#include "imports.hpp"
#include "oep.hpp"
#include "pe.hpp"
#include "packer.hpp"
#include "lzma.hpp"
#include "report.hpp"
#include "vm.hpp"

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <string>
#include <vector>

namespace {

int failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                   \
        }                                                                 \
    } while (0)

constexpr uint64_t kBase = 0x140000000ull;
constexpr size_t kFileSize = 0x1600;
constexpr size_t kSectionTable = 0x188;
constexpr size_t kOpt = 0x98;
constexpr uint32_t kKey = 0x00010001;

void put16(std::vector<uint8_t>& d, size_t off, uint16_t v) {
    d[off] = static_cast<uint8_t>(v & 0xFF);
    d[off + 1] = static_cast<uint8_t>(v >> 8);
}

void put32(std::vector<uint8_t>& d, size_t off, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) d[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

void put64(std::vector<uint8_t>& d, size_t off, uint64_t v) {
    for (size_t i = 0; i < 8; ++i) d[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

void putEncoded(std::vector<uint8_t>& d, size_t fileOffset, const char* text) {
    const size_t length = std::strlen(text) + 1;
    std::vector<uint8_t> encoded;
    vmpstatic::transformBytes(reinterpret_cast<const uint8_t*>(text), length, kKey, encoded);
    std::memcpy(d.data() + fileOffset, encoded.data(), length);
}

void addSection(std::vector<uint8_t>& d, size_t index, const char* name, uint32_t va,
                uint32_t vsize, uint32_t rawPtr, uint32_t rawSize, uint32_t characteristics) {
    const size_t at = kSectionTable + index * 40;
    std::memcpy(d.data() + at, name, std::strlen(name));
    put32(d, at + 8, vsize);
    put32(d, at + 12, va);
    put32(d, at + 16, rawSize);
    put32(d, at + 20, rawPtr);
    put32(d, at + 36, characteristics);
}

// Two sections: .text with a small import directory, .vmp0 with entropy-like filler,
// an encoded module name plus a two-record encoded import table, and a planted branch.
std::vector<uint8_t> makePe32Plus(bool ordinalImport) {
    std::vector<uint8_t> d(kFileSize, 0);
    put16(d, 0, 0x5A4D);
    put32(d, 0x3C, 0x80);
    put32(d, 0x80, 0x00004550);
    put16(d, 0x84, 0x8664);
    put16(d, 0x86, 2);
    put16(d, 0x94, 0xF0);
    put16(d, kOpt, 0x20B);
    put32(d, kOpt + 0x10, 0x1000);  // AddressOfEntryPoint
    put64(d, kOpt + 0x18, kBase);
    put32(d, kOpt + 0x20, 0x1000);
    put32(d, kOpt + 0x24, 0x200);
    put32(d, kOpt + 0x38, 0x3000);
    put32(d, kOpt + 0x3C, 0x400);
    put16(d, kOpt + 0x44, 3);
    put32(d, kOpt + 0x6C, 16);
    put32(d, kOpt + 0x70 + 8, 0x1100);  // import directory RVA
    put32(d, kOpt + 0x70 + 12, 20);     // import directory size

    addSection(d, 0, ".text", 0x1000, 0x200, 0x400, 0x200, 0x60000020);
    addSection(d, 1, ".vmp0", 0x2000, 0x1000, 0x600, 0x1000, 0xE0000020);

    // .text: import descriptor, ILT/IAT, module and function names.
    put32(d, 0x500 + 0, 0x1140);   // OriginalFirstThunk
    put32(d, 0x500 + 12, 0x1180);  // Name
    put32(d, 0x500 + 16, 0x11A0);  // FirstThunk
    std::memcpy(d.data() + 0x580, "KERNEL32.dll", 13);
    put64(d, 0x540, ordinalImport ? 0x8000000000000005ull : 0x11C0ull);
    put64(d, 0x548, 0);
    put64(d, 0x5A0, ordinalImport ? 0x8000000000000005ull : 0x11C0ull);
    put64(d, 0x5A8, 0);
    put16(d, 0x5C0, 0);
    std::memcpy(d.data() + 0x5C2, "ExitProcess", 12);
    // Prologue target for the branch scan, away from the entry point.
    const uint8_t prologue[] = {0x55, 0x8B, 0xEC};
    std::memcpy(d.data() + 0x450, prologue, sizeof prologue);
    // x86 SEH CRT startup at RVA 0x1060 (file 0x460) for CRT-pattern OEP test.
    const uint8_t seh[] = {0x6A, 0xFF, 0x68, 0x11, 0x22, 0x33, 0x44,
                           0x64, 0xA1, 0x00, 0x00, 0x00, 0x00};
    std::memcpy(d.data() + 0x460, seh, sizeof seh);
    // Security-cookie anchor at RVA 0x1070/0x1080: prologue + default x64 cookie.
    const uint8_t cookiePrologue[] = {0x55, 0x8B, 0xEC};
    std::memcpy(d.data() + 0x470, cookiePrologue, sizeof cookiePrologue);
    static const uint8_t kCookie[] = {0x32, 0xA2, 0xDF, 0x2D, 0x99, 0x2B, 0x00, 0x00};
    std::memcpy(d.data() + 0x480, kCookie, sizeof kCookie);
    // mainCRTStartup at RVA 0x1090: prologue, E8 call to 0x1070, add rsp,28h + jmp.
    std::memcpy(d.data() + 0x490, cookiePrologue, sizeof cookiePrologue);
    d[0x4A0] = 0xE8;
    put32(d, 0x4A1, static_cast<uint32_t>(0x1070 - (0x10A0 + 5)));
    static const uint8_t kEpilogue[] = {0x48, 0x83, 0xC4, 0x28, 0xE9,
                                        0x00, 0x00, 0x00, 0x00};
    std::memcpy(d.data() + 0x4A5, kEpilogue, sizeof kEpilogue);

    // .vmp0: high-entropy filler, then a deterministic encoded blob.
    uint32_t x = 0x12345678;
    for (size_t i = 0; i < 0x1000; ++i) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        d[0x600 + i] = static_cast<uint8_t>(x);
    }
    std::memset(d.data() + 0xA00, 0, 0x300);  // RVAs 0x2400..0x2700

    putEncoded(d, 0xA00, "ntdll.dll");  // module name at RVA 0x2400
    putEncoded(d, 0xA80, "NtClose");    // RVA 0x2480
    putEncoded(d, 0xAA0, "NtCreateFile");  // RVA 0x24A0
    putEncoded(d, 0xC00, "ZwQueryInformationProcess");  // RVA 0x2600

    put32(d, 0xA20, 0x2400);  // module-name RVA
    put32(d, 0xA24, 0x2480);  // record 1: name RVA
    put32(d, 0xA28, 0x2500);  // slot RVA
    put32(d, 0xA2C, 0x11223344);
    put32(d, 0xA30, 0x24A0);  // record 2
    put32(d, 0xA34, 0x2508);
    put32(d, 0xA38, 0x11223344);
    put32(d, 0xA3C, 0);  // terminator

    // Branch from .vmp0 at RVA 0x2300 (file offset 0x900) into the prologue at RVA 0x1050.
    d[0x900] = 0xE8;
    put32(d, 0x901, static_cast<uint32_t>(0x1050 - (0x2300 + 5)));

    // VM entry frame at RVA 0x2200: pushfq plus eight register pushes.
    d[0x800] = 0x9C;
    for (size_t i = 0; i < 8; ++i) d[0x801 + i] = static_cast<uint8_t>(0x50 + i);

    // Eight handler entries at RVA 0x2800 (file 0xE00), each pointing into .vmp0.
    std::memset(d.data() + 0xE00, 0, 0x40);
    for (size_t i = 0; i < 8; ++i) put32(d, 0xE00 + i * 4, 0x2700 + static_cast<uint32_t>(i * 16));
    static const uint8_t kApiCall[] = {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00};
    std::memcpy(d.data() + 0xD00, kApiCall, sizeof kApiCall);

    // call [rip+disp] at RVA 0x2720 resolving through the IAT slot at RVA 0x11A0.
    const int32_t rel = static_cast<int32_t>(0x11A0 - (0x2720 + 6));
    d[0xD20] = 0xFF;
    d[0xD21] = 0x15;
    put32(d, 0xD22, static_cast<uint32_t>(rel));

    // jmp [rip+disp] at RVA 0x2730 resolving through the same IAT slot (unpaki FF25).
    const int32_t relJmp = static_cast<int32_t>(0x11A0 - (0x2730 + 6));
    d[0xD30] = 0xFF;
    d[0xD31] = 0x25;
    put32(d, 0xD32, static_cast<uint32_t>(relJmp));

    // vmpfix resolving core at RVA 0x2760 (file 0xD60): lea rsi,[rip+..] /
    // mov rsi,[rsi+..] / lea rsi,[rsi+..] (reg id 6, back-to-back).
    static const uint8_t kCore[] = {0x48, 0x8D, 0x35, 0x11, 0x11, 0x11, 0x11,
                                    0x48, 0x8B, 0xB6, 0x22, 0x22, 0x22, 0x22,
                                    0x48, 0x8D, 0xB6, 0x33, 0x33, 0x33, 0x33};
    std::memcpy(d.data() + 0xD60, kCore, sizeof kCore);
    // r8 core at RVA 0x2780 (REX 0x4D = W+R+B): reg id 8.
    static const uint8_t kCore8[] = {0x4D, 0x8D, 0x05, 0x11, 0x11, 0x11, 0x11,
                                     0x4D, 0x8B, 0x80, 0x22, 0x22, 0x22, 0x22,
                                     0x4D, 0x8D, 0x80, 0x33, 0x33, 0x33, 0x33};
    std::memcpy(d.data() + 0xD80, kCore8, sizeof kCore8);
    // rsp-shaped triple at RVA 0x27A0: r/m field 4 means SIB follows, must not match.
    static const uint8_t kCoreSp[] = {0x48, 0x8D, 0x25, 0x11, 0x11, 0x11, 0x11,
                                      0x48, 0x8B, 0xA4, 0x22, 0x22, 0x22, 0x22,
                                      0x48, 0x8D, 0xA4, 0x33, 0x33, 0x33, 0x33};
    std::memcpy(d.data() + 0xDA0, kCoreSp, sizeof kCoreSp);

    // REX.W jmp [rip+disp] at RVA 0x27C0 through the same IAT slot.
    const int32_t relRex = static_cast<int32_t>(0x11A0 - (0x27C0 + 7));
    d[0xDC0] = 0x48;
    d[0xDC1] = 0xFF;
    d[0xDC2] = 0x25;
    put32(d, 0xDC3, static_cast<uint32_t>(relRex));

    // mov rsi,[rip+disp] at RVA 0x27D0 through the same IAT slot.
    const int32_t relMov = static_cast<int32_t>(0x11A0 - (0x27D0 + 7));
    d[0xDD0] = 0x48;
    d[0xDD1] = 0x8B;
    d[0xDD2] = 0x0D;
    put32(d, 0xDD3, static_cast<uint32_t>(relMov));

    // jmp qword ptr [rax*8 + disp32] at RVA 0x2740, disp32 = table RVA 0x2800.
    static const uint8_t kDispatch[] = {0xFF, 0x24, 0xC5, 0x00, 0x28, 0x00, 0x00};
    std::memcpy(d.data() + 0xD40, kDispatch, sizeof kDispatch);
    return d;
}

// Minimal PE32+ DLL with an export directory listing NtClose and NtCreateFile.
std::vector<uint8_t> makeCatalogDll() {
    std::vector<uint8_t> d(0x800, 0);
    put16(d, 0, 0x5A4D);
    put32(d, 0x3C, 0x80);
    put32(d, 0x80, 0x00004550);
    put16(d, 0x84, 0x8664);
    put16(d, 0x86, 1);
    put16(d, 0x94, 0xF0);
    put16(d, kOpt, 0x20B);
    put64(d, kOpt + 0x18, 0x180000000ull);
    put32(d, kOpt + 0x20, 0x1000);
    put32(d, kOpt + 0x24, 0x200);
    put32(d, kOpt + 0x38, 0x2000);
    put32(d, kOpt + 0x3C, 0x400);
    put32(d, kOpt + 0x6C, 16);
    put32(d, kOpt + 0x70, 0x1000);  // export directory RVA
    put32(d, kOpt + 0x74, 40);
    addSection(d, 0, ".text", 0x1000, 0x400, 0x400, 0x400, 0x40000040);

    put32(d, 0x40C, 0x11C0);  // Name
    put32(d, 0x410, 1);       // OrdinalBase
    put32(d, 0x414, 2);       // NumberOfFunctions
    put32(d, 0x418, 2);       // NumberOfNames
    put32(d, 0x41C, 0x1100);  // AddressOfFunctions
    put32(d, 0x420, 0x1120);  // AddressOfNames
    put32(d, 0x424, 0x1140);  // AddressOfNameOrdinals
    put32(d, 0x500, 0x1000);
    put32(d, 0x504, 0x1010);
    put32(d, 0x520, 0x1180);
    put32(d, 0x524, 0x11A0);
    put16(d, 0x540, 0);
    put16(d, 0x542, 1);
    std::memcpy(d.data() + 0x580, "NtClose", 8);
    std::memcpy(d.data() + 0x5A0, "NtCreateFile", 13);
    std::memcpy(d.data() + 0x5C0, "ntdll.dll", 10);
    return d;
}

std::vector<uint8_t> makePe32() {
    constexpr size_t kOpt32 = 0x98;
    std::vector<uint8_t> d(0x600, 0);
    put16(d, 0, 0x5A4D);
    put32(d, 0x3C, 0x80);
    put32(d, 0x80, 0x00004550);
    put16(d, 0x84, 0x14C);
    put16(d, 0x86, 1);
    put16(d, 0x94, 0xE0);
    put16(d, kOpt32, 0x10B);
    put32(d, kOpt32 + 0x10, 0x1000);
    put32(d, kOpt32 + 0x1C, 0x400000);
    put32(d, kOpt32 + 0x20, 0x1000);
    put32(d, kOpt32 + 0x24, 0x200);
    put32(d, kOpt32 + 0x38, 0x2000);
    put32(d, kOpt32 + 0x3C, 0x200);
    put32(d, kOpt32 + 0x5C, 16);
    const size_t table = kOpt32 + 0xE0;
    std::memcpy(d.data() + table, ".text", 5);
    put32(d, table + 8, 0x200);
    put32(d, table + 12, 0x1000);
    put32(d, table + 16, 0x200);
    put32(d, table + 20, 0x200);
    put32(d, table + 36, 0x60000020);
    return d;
}

void testParse() {
    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    CHECK(pe.valid);
    CHECK(pe.is64);
    CHECK(pe.machine == 0x8664);
    CHECK(pe.imageBase == kBase);
    CHECK(pe.entryPoint == 0x1000);
    CHECK(pe.sizeOfImage == 0x3000);
    CHECK(pe.sections.size() == 2);
    CHECK(pe.sections[0].name == ".text");
    CHECK(pe.sections[1].name == ".vmp0");
    CHECK(pe.sections[1].vmpName);
    CHECK(!pe.sections[0].vmpName);
    CHECK(pe.sections[1].entropy > 6.8);
    CHECK(!pe.hasOverlay());

    auto bad = vmpstatic::parsePe(std::vector<uint8_t>(16, 0));
    CHECK(!bad.valid);
    CHECK(!bad.error.empty());

    auto pe32 = vmpstatic::parsePe(makePe32());
    CHECK(pe32.valid);
    CHECK(!pe32.is64);
    CHECK(pe32.imageBase == 0x400000);
    CHECK(pe32.entryPoint == 0x1000);
    CHECK(pe32.sections.size() == 1);
    CHECK(pe32.dirs[0].size == 0);
}

void testNames() {
    CHECK(vmpstatic::isVmpSectionName(".vmp0"));
    CHECK(vmpstatic::isVmpSectionName("VMP1"));
    CHECK(vmpstatic::isVmpSectionName("_vmp"));
    CHECK(vmpstatic::isVmpSectionName("vmp"));
    CHECK(!vmpstatic::isVmpSectionName(".text"));
    CHECK(!vmpstatic::isVmpSectionName("xvmp"));

    vmpstatic::Section s;
    s.name = ".vmp0";
    CHECK(vmpstatic::isPackerSection(s));
    s.name = ".custom";
    s.exec = true;
    s.vsize = 0x800;
    CHECK(!vmpstatic::isPackerSection(s));
    s.vsize = 0x1000;
    CHECK(vmpstatic::isPackerSection(s));
    s.name = ".rdata";
    CHECK(!vmpstatic::isPackerSection(s));
    s.name = ".text2";
    CHECK(!vmpstatic::isPackerSection(s));
    s.name = ".CRT$XCU";
    CHECK(!vmpstatic::isPackerSection(s));
}

void testPeDiagnostics() {
    auto bytes = makePe32Plus(false);
    put32(bytes, kSectionTable + 40 + 12, 0x1000); // overlap .text virtual range
    auto pe = vmpstatic::parsePe(bytes);
    CHECK(pe.valid);
    bool foundOverlap = false;
    for (const auto& d : pe.diagnostics)
        if (d.find("virtual sections") != std::string::npos) foundOverlap = true;
    CHECK(foundOverlap);

    bytes = makePe32Plus(false);
    put32(bytes, kOpt + 0x10, 0x5000);
    pe = vmpstatic::parsePe(bytes);
    bool foundEntryPoint = false;
    for (const auto& d : pe.diagnostics)
        if (d.find("AddressOfEntryPoint") != std::string::npos) foundEntryPoint = true;
    CHECK(foundEntryPoint);
}

uint32_t rotateLeft32(uint32_t value, unsigned count) {
    count &= 31;
    return count ? (value << count) | (value >> (32 - count)) : value;
}

const std::vector<uint8_t>& packedLzmaFixture() {
    static const std::vector<uint8_t> bytes = {
        0x00,0x2B,0x13,0x46,0x49,0x1E,0x17,0x72,0x67,0xA9,0x6C,0xAE,
        0x3D,0xBB,0xF8,0x54,0xF7,0x3F,0xAB,0x22,0x18,0xE7,0xBE,0x29,
        0x4D,0x15,0xE9,0xAF,0x01,0x13,0x98,0xE3,0xD5,0xA9,0x7E,0xA1,
        0xE7,0xF7,0xCD,0x71,0xB2,0x10,0xDA,0xBF,0xFC,0xFB,0xE7,0x40};
    return bytes;
}

std::vector<uint8_t> makePackedPe(vmpstatic::PackerFormat format, bool duplicate = false) {
    auto d = makePe32Plus(false);
    put16(d, 0x86, 4);
    put32(d, kOpt + 0x38, 0x6000);
    addSection(d, 2, ".data", 0x3000, 0x800, 0, 0, 0xC0000040);
    addSection(d, 3, ".text2", 0x4000, 0x900, 0, 0, 0x60000020);

    // Each candidate block is an independently compressed raw LZMA1 stream.
    const auto& compressed = packedLzmaFixture();
    std::memcpy(d.data() + 0x900, compressed.data(), compressed.size());
    std::memcpy(d.data() + 0x940, compressed.data(), compressed.size());
    if (format == vmpstatic::PackerFormat::LegacyPlaintext) {
        put32(d, 0x11F8, 0x2400); // RVA of the five LZMA property bytes
        d[0xA00] = 0x5D;
        d[0xA01] = 0x00;
        d[0xA02] = 0x00;
        d[0xA03] = 0x10;
        d[0xA04] = 0x00;
        put32(d, 0x1200, 0x2300);
        put32(d, 0x1204, 0x3000);
        put32(d, 0x1208, 0x2340);
        put32(d, 0x120C, 0x4000);
        if (duplicate) {
            put32(d, 0x12F8, 0x2400);
            put32(d, 0x1300, 0x2300);
            put32(d, 0x1304, 0x3000);
            put32(d, 0x1308, 0x2340);
            put32(d, 0x130C, 0x4000);
        }
    } else {
        constexpr uint32_t key = 0xA1B2C3D4;
        put32(d, 0x1200, 0x2300);
        put32(d, 0x1204, 0x3000 ^ key);
        put32(d, 0x1208, 0x2340);
        put32(d, 0x120C, 0x4000 ^ rotateLeft32(key, 7));
    }
    return d;
}

void testPackerMetadataDiscovery() {
    auto legacyPe = vmpstatic::parsePe(makePackedPe(vmpstatic::PackerFormat::LegacyPlaintext));
    CHECK(legacyPe.valid);
    const auto legacy = vmpstatic::discoverPackerInfo(legacyPe);
    CHECK(legacy.format == vmpstatic::PackerFormat::LegacyPlaintext);
    CHECK(legacy.candidates.size() == 1);
    CHECK(legacy.entries.size() == 2);
    if (legacy.entries.size() == 2) {
        CHECK(legacy.entries[0].sourceRva == 0x2300);
        CHECK(legacy.entries[0].destinationRva == 0x3000);
        CHECK(legacy.entries[1].destinationRva == 0x4000);
    }
    CHECK(legacy.lzmaProperties[0] == 0x5D);
    std::vector<uint8_t> legacyImage;
    std::string error;
    CHECK(vmpstatic::fileToImage(legacyPe, legacyImage, error));
    const auto legacyRecovery = vmpstatic::decompressPackedSections(legacyPe, legacy, legacyImage);
    CHECK(legacyRecovery.attempted);
    CHECK(legacyRecovery.blocks.size() == 2);
    CHECK(legacyRecovery.blocks[0].recovered);
    CHECK(std::memcmp(legacyImage.data() + 0x3000,
                      "VMProtect section recovered statically.\0", 40) == 0);

    auto encodedPe = vmpstatic::parsePe(makePackedPe(vmpstatic::PackerFormat::RotatingKey));
    const auto encoded = vmpstatic::discoverPackerInfo(encodedPe);
    CHECK(encoded.format == vmpstatic::PackerFormat::RotatingKey);
    CHECK(encoded.candidates.size() == 1);
    CHECK(encoded.entries.size() == 2);
    CHECK(encoded.destinationKey == 0xA1B2C3D4);
    std::vector<uint8_t> encodedImage;
    CHECK(vmpstatic::fileToImage(encodedPe, encodedImage, error));
    const auto encodedRecovery =
        vmpstatic::decompressPackedSections(encodedPe, encoded, encodedImage);
    CHECK(encodedRecovery.blocks.size() == 2);
    CHECK(encodedRecovery.blocks[1].recovered);

    auto ambiguousPe = vmpstatic::parsePe(
        makePackedPe(vmpstatic::PackerFormat::LegacyPlaintext, true));
    const auto ambiguous = vmpstatic::discoverPackerInfo(ambiguousPe);
    CHECK(ambiguous.format == vmpstatic::PackerFormat::Unknown);
    CHECK(ambiguous.candidates.size() > 1);
}

void testRawLzmaDecode() {
    const std::array<uint8_t, 5> properties = {0x5D, 0x00, 0x00, 0x10, 0x00};
    const std::vector<uint8_t> compressed = {
        0x00,0x2B,0x13,0x46,0x49,0x1E,0x17,0x72,0x67,0xA9,0x6C,0xAE,
        0x3D,0xBB,0xF8,0x54,0xF7,0x3F,0xAB,0x22,0x18,0xE7,0xBE,0x29,
        0x4D,0x15,0xE9,0xAF,0x01,0x13,0x98,0xE3,0xD5,0xA9,0x7E,0xA1,
        0xE7,0xF7,0xCD,0x71,0xB2,0x10,0xDA,0xBF,0xFC,0xFB,0xE7,0x40};
    const auto result = vmpstatic::decompressRawLzma(properties, compressed, 128);
    CHECK(result.success);
    CHECK(std::string(result.bytes.begin(), result.bytes.end()) ==
          std::string("VMProtect section recovered statically.\0", 40));

    const auto overLimit = vmpstatic::decompressRawLzma(properties, compressed, 10);
    CHECK(!overLimit.success);
}

void testImports() {
    auto boundedImports = makePe32Plus(false);
    put32(boundedImports, kOpt + 0x70 + 12, 16);
    auto boundedPe = vmpstatic::parsePe(boundedImports);
    const auto boundedTable = vmpstatic::parseImports(boundedPe);
    CHECK(boundedTable.entries.empty());

    auto truncatedThunks = makePe32Plus(false);
    put32(truncatedThunks, 0x500, 0x11F8);
    auto truncatedThunkPe = vmpstatic::parsePe(truncatedThunks);
    const auto truncatedThunkTable = vmpstatic::parseImports(truncatedThunkPe);
    CHECK(truncatedThunkTable.entries.empty());

    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    auto table = vmpstatic::parseImports(pe);
    CHECK(table.entries.size() == 1);
    CHECK(table.moduleCount == 1);
    CHECK(table.entries[0].module == "KERNEL32.dll");
    CHECK(table.entries[0].name == "ExitProcess");
    CHECK(!table.entries[0].byOrdinal);
    CHECK(table.entries[0].iatRva == 0x11A0);

    auto ordinalPe = vmpstatic::parsePe(makePe32Plus(true));
    auto ordinalTable = vmpstatic::parseImports(ordinalPe);
    CHECK(ordinalTable.entries.size() == 1);
    CHECK(ordinalTable.entries[0].byOrdinal);
    CHECK(ordinalTable.entries[0].ordinal == 5);
    CHECK(ordinalTable.entries[0].name == "#5");
}

void testDetection() {
    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    auto d = vmpstatic::detect(pe);
    CHECK(d.vmpSections.size() == 1);
    CHECK(d.confidence == vmpstatic::Confidence::Medium);
    CHECK(d.score >= 4);
    bool hasResolverSignal = false;
    for (const auto& s : d.signals) {
        if (s.name == "import resolver stub cores" && s.weight == 2) hasResolverSignal = true;
    }
    CHECK(hasResolverSignal);
    CHECK(d.version == "Unknown");

    auto pe32 = vmpstatic::parsePe(makePe32());
    auto plain = vmpstatic::detect(pe32);
    CHECK(plain.vmpSections.empty());
    CHECK(plain.confidence != vmpstatic::Confidence::High);
}

void testCookieOep() {
    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    const auto candidates = vmpstatic::findOepCandidates(pe, 32);
    bool hasCookie = false;
    for (const auto& c : candidates) {
        if (c.method == vmpstatic::OepMethod::PrologueScan && c.rva == 0x1090 &&
            c.confidence == vmpstatic::Confidence::Medium &&
            c.evidence.find("mainCRTStartup") != std::string::npos) {
            hasCookie = true;
        }
    }
    CHECK(hasCookie);
    // Without the cookie immediate the anchor must stay silent.
    auto noCookie = makePe32Plus(false);
    std::memset(noCookie.data() + 0x480, 0, 8);
    auto noCookiePe = vmpstatic::parsePe(noCookie);
    for (const auto& c : vmpstatic::findOepCandidates(noCookiePe, 32)) {
        CHECK(c.evidence.find("mainCRTStartup") == std::string::npos);
    }
}

void testOep() {
    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    auto candidates = vmpstatic::findOepCandidates(pe, 32);
    bool hasEntry = false;
    bool hasBranch = false;
    bool hasCrt = false;
    for (const auto& c : candidates) {
        if (c.method == vmpstatic::OepMethod::EntryPoint && c.rva == 0x1000) {
            hasEntry = c.confidence == vmpstatic::Confidence::High;
        }
        if (c.method == vmpstatic::OepMethod::BranchScan && c.rva == 0x1050) {
            hasBranch = c.confidence == vmpstatic::Confidence::Medium;
        }
        if (c.method == vmpstatic::OepMethod::PrologueScan && c.rva == 0x1060) {
            hasCrt = c.confidence == vmpstatic::Confidence::Medium;
        }
    }
    CHECK(hasEntry);
    CHECK(hasBranch);
    CHECK(hasCrt);
}

void testEncodedTables() {
    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    const auto keys = vmpstatic::recoverStringKeys(pe);
    CHECK(keys.size() == 1);
    CHECK(!keys.empty() && keys[0].matches >= 1);

    std::vector<uint8_t> image;
    std::string error;
    CHECK(vmpstatic::fileToImage(pe, image, error));
    CHECK(image.size() == pe.sizeOfImage);
    CHECK(image[0x2400] == (static_cast<uint8_t>('n') ^ vmpstatic::encodedByte(kKey, 0)));

    std::vector<uint32_t> keyValues = {kKey};
    const auto tables = vmpstatic::findEncodedImportTables(image, keyValues);
    CHECK(tables.size() == 1);
    if (tables.size() == 1) {
        CHECK(tables[0].module == "ntdll.dll");
        CHECK(tables[0].tableRva == 0x2420);
        CHECK(tables[0].records.size() == 2);
        if (tables[0].records.size() == 2) {
            CHECK(tables[0].records[0].name == "NtClose");
            CHECK(tables[0].records[0].slotRva == 0x2500);
            CHECK(tables[0].records[1].name == "NtCreateFile");
            CHECK(tables[0].records[1].slotRva == 0x2508);
        }
    }
}

void testVm() {
    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    const auto entry = vmpstatic::findVmEntry(pe);
    CHECK(entry.has_value());
    if (entry) {
        CHECK(entry->rva == 0x2200);
        CHECK(entry->confidence == vmpstatic::Confidence::High);
    }

    const auto tables = vmpstatic::findHandlerTables(pe, 8);
    CHECK(!tables.empty());
    bool found = false;
    for (const auto& t : tables) {
        if (t.rva != 0x2800) continue;
        found = true;
        CHECK(t.count == 8);
        CHECK(t.section == ".vmp0");
        CHECK(t.confidence == vmpstatic::Confidence::Medium);
        if (!t.handlers.empty()) {
            CHECK(t.handlers[0].rva == 0x2700);
            CHECK(t.handlers[0].cls == "api-call");
        }
    }
    CHECK(found);
}

void testDispatchers() {
    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    const auto dispatchers = vmpstatic::findVmDispatchers(pe, 8);
    CHECK(!dispatchers.empty());
    bool found = false;
    for (const auto& d : dispatchers) {
        if (d.rva != 0x2740) continue;
        found = true;
        CHECK(d.resolved);
        CHECK(d.tableRva == 0x2800);
        CHECK(d.confidence == vmpstatic::Confidence::High);
    }
    CHECK(found);
}

void testApiReferences() {
    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    const auto imports = vmpstatic::parseImports(pe);
    CHECK(imports.entries.size() == 1);
    const auto refs = vmpstatic::findApiReferences(pe, imports, 64);
    bool found = false;
    bool foundJmp = false;
    bool foundRex = false;
    bool foundMov = false;
    for (const auto& r : refs) {
        if (r.siteRva != 0x2720 && r.siteRva != 0x2730 && r.siteRva != 0x27C0 &&
            r.siteRva != 0x27D0) {
            continue;
        }
        if (r.iatRva != 0x11A0) continue;
        if (r.name != "ExitProcess") continue;
        if (!r.packerSection) continue;
        if (r.siteRva == 0x2720) found = true;
        if (r.siteRva == 0x2730) foundJmp = true;
        if (r.siteRva == 0x27C0) foundRex = true;
        if (r.siteRva == 0x27D0) foundMov = true;
    }
    CHECK(found);
    CHECK(foundJmp);
    CHECK(foundRex);
    CHECK(foundMov);
}

void testCatalog() {
    auto dll = vmpstatic::parsePe(makeCatalogDll());
    CHECK(dll.valid);
    auto outOfDirBytes = makeCatalogDll();
    put32(outOfDirBytes, kOpt + 0x74, 0x20);
    auto outOfDirPe = vmpstatic::parsePe(outOfDirBytes);
    CHECK(outOfDirPe.valid);
    const auto outOfDirCatalog = vmpstatic::buildExportCatalog({{"ntdll.dll", &outOfDirPe}});
    CHECK(outOfDirCatalog.modules.empty());

    auto oversizedNameTableBytes = makeCatalogDll();
    put32(oversizedNameTableBytes, 0x420, 0x13F8);
    auto oversizedNameTablePe = vmpstatic::parsePe(oversizedNameTableBytes);
    const auto oversizedNameTableCatalog =
        vmpstatic::buildExportCatalog({{"ntdll.dll", &oversizedNameTablePe}});
    CHECK(oversizedNameTableCatalog.modules.empty());

    std::vector<vmpstatic::CatalogModule> modules = {{"ntdll.dll", &dll}};
    const auto catalog = vmpstatic::buildExportCatalog(modules);
    CHECK(catalog.modules.size() == 1);
    const auto* exports = catalog.exports("NTDLL.DLL");
    CHECK(exports != nullptr);
    if (exports) {
        CHECK(exports->count("NtClose") == 1);
        CHECK(exports->at("NtClose") == 1);
        CHECK(exports->at("NtCreateFile") == 2);
    }

    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    const auto keys = vmpstatic::recoverStringKeys(pe);
    std::vector<uint8_t> image;
    std::string error;
    CHECK(vmpstatic::fileToImage(pe, image, error));
    std::vector<uint32_t> keyValues;
    for (const auto& k : keys) keyValues.push_back(k.key);
    auto tables = vmpstatic::findEncodedImportTables(image, keyValues);
    CHECK(tables.size() == 1);
    const auto stats = vmpstatic::validateEncodedTables(tables, catalog);
    CHECK(stats.validated == 2);
    CHECK(stats.dropped == 0);
    CHECK(stats.records == 2);
    if (!tables.empty() && tables[0].records.size() == 2) {
        CHECK(tables[0].records[0].validated);
        CHECK(tables[0].records[0].hasOrdinal);
        CHECK(tables[0].records[0].ordinal == 1);
        CHECK(tables[0].records[1].ordinal == 2);
    }

    auto bogus = vmpstatic::findEncodedImportTables(image, keyValues);
    bogus[0].records[0].name = "NtBogus";
    const auto bogusStats = vmpstatic::validateEncodedTables(bogus, catalog);
    CHECK(bogusStats.dropped == 1);
    CHECK(bogusStats.validated == 1);

    auto unknownModule = vmpstatic::findEncodedImportTables(image, keyValues);
    unknownModule[0].module = "kernel32.dll";
    const auto unknownStats = vmpstatic::validateEncodedTables(unknownModule, catalog);
    CHECK(unknownStats.unknownModules == 1);
    CHECK(unknownStats.validated == 0);
}

void testRoundTrip() {
    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    std::vector<uint8_t> image;
    std::string error;
    CHECK(vmpstatic::fileToImage(pe, image, error));
    CHECK(vmpstatic::patchEntryPoint(image, pe, 0x1050));

    auto overlappingLayout = pe;
    overlappingLayout.sections[1].va = overlappingLayout.sections[0].va;
    std::vector<uint8_t> overlappedImage;
    CHECK(vmpstatic::fileToImage(overlappingLayout, overlappedImage, error));
    std::vector<uint8_t> overlappingOut;
    CHECK(!vmpstatic::imageToFile(overlappingLayout, overlappedImage, overlappingOut, error));
    CHECK(!error.empty());

    std::vector<uint8_t> out;
    auto zeroVirtualSize = makePe32Plus(false);
    put32(zeroVirtualSize, kSectionTable + 8, 0);
    auto zeroVirtualPe = vmpstatic::parsePe(zeroVirtualSize);
    CHECK(zeroVirtualPe.valid);
    CHECK(zeroVirtualPe.sections[0].mappedSize() == 0x200);
    std::vector<uint8_t> zeroVirtualImage;
    CHECK(vmpstatic::fileToImage(zeroVirtualPe, zeroVirtualImage, error));
    CHECK(zeroVirtualImage[0x1000] == zeroVirtualSize[0x400]);

    CHECK(vmpstatic::imageToFile(pe, image, out, error));

    auto rebuilt = vmpstatic::parsePe(out);
    CHECK(rebuilt.valid);
    CHECK(rebuilt.entryPoint == 0x1050);
    CHECK(rebuilt.sections.size() == 2);
    CHECK(rebuilt.sections[0].rawPtr == 0x400);
    CHECK(rebuilt.sections[1].rawPtr == 0x600);
    CHECK(rebuilt.sections[1].rawSize == 0x1000);

    std::vector<uint8_t> imageAgain;
    CHECK(vmpstatic::fileToImage(rebuilt, imageAgain, error));
    CHECK(imageAgain[0x1050] == image[0x1050]);
    CHECK(imageAgain[0x2200] == image[0x2200]);
    CHECK(imageAgain[0x2800] == image[0x2800]);

    auto overlayBytes = makePe32Plus(false);
    overlayBytes.insert(overlayBytes.end(), {0x43, 0x45, 0x52, 0x54});
    put32(overlayBytes, kOpt + 0x70 + 4 * 8, 0x1620);
    put32(overlayBytes, kOpt + 0x70 + 4 * 8 + 4, 4);
    auto overlayPe = vmpstatic::parsePe(overlayBytes);
    CHECK(overlayPe.valid);
    CHECK(overlayPe.hasOverlay());
    CHECK(overlayPe.overlayOffset == kFileSize);
    CHECK(vmpstatic::fileToImage(overlayPe, image, error));
    CHECK(vmpstatic::imageToFile(overlayPe, image, out, error));
    auto rebuiltOverlay = vmpstatic::parsePe(out);
    uint32_t offset = 0;
    CHECK(rebuiltOverlay.valid);
    CHECK(rebuiltOverlay.dirs[4].rva == 0);
    CHECK(rebuiltOverlay.dirs[4].size == 0);
    CHECK(!vmpstatic::rvaToFileOffset(rebuiltOverlay, 0x1620, offset));
    CHECK(rebuiltOverlay.hasOverlay());
    CHECK(std::equal(out.end() - 4, out.end(), overlayBytes.end() - 4));

    auto signedBytes = makePe32Plus(false);
    put32(signedBytes, kOpt + 0x70 + 4 * 8, 0x1800);
    put32(signedBytes, kOpt + 0x70 + 4 * 8 + 4, 0x80);
    auto signedPe = vmpstatic::parsePe(signedBytes);
    CHECK(signedPe.valid);
    CHECK(vmpstatic::fileToImage(signedPe, image, error));
    CHECK(vmpstatic::imageToFile(signedPe, image, out, error));
    auto rebuiltSigned = vmpstatic::parsePe(out);
    CHECK(rebuiltSigned.valid);
    CHECK(rebuiltSigned.dirs[4].rva == 0);
    CHECK(rebuiltSigned.dirs[4].size == 0);

    vmpstatic::AnalyzeOptions options;
    options.manualOep = 0;
    options.hasManualOep = false;
    const auto defaultOep = vmpstatic::analyze(rebuilt, options);
    CHECK(defaultOep.selectedOep == rebuilt.entryPoint);
    options.manualOep = 0x1050;
    options.hasManualOep = true;
    auto analysis = vmpstatic::analyze(rebuilt, options);
    CHECK(analysis.selectedOep == 0x1050);
    CHECK(analysis.selectedMethod == vmpstatic::OepMethod::Manual);
    options.manualOep = 0;
    options.hasManualOep = true;
    const auto zeroOepAnalysis = vmpstatic::analyze(rebuilt, options);
    CHECK(zeroOepAnalysis.selectedOep == 0);
    CHECK(zeroOepAnalysis.selectedMethod == vmpstatic::OepMethod::Manual);
    options.manualOep = kBase + 0x1050;
    options.hasManualOep = true;
    const auto vaAnalysis = vmpstatic::analyze(rebuilt, options);
    CHECK(vaAnalysis.selectedOep == 0x1050);
    CHECK(vaAnalysis.selectedMethod == vmpstatic::OepMethod::Manual);
    CHECK(analysis.vmEntry.has_value());
    CHECK(!analysis.handlerTables.empty());
    const std::string json = vmpstatic::renderJson(analysis, "sample.exe");
    CHECK(json.find("\"rva\": \"0x1050\"") != std::string::npos);
    CHECK(json.find("\"module\": \"ntdll.dll\"") != std::string::npos);
    CHECK(json.find("\"handlerTables\"") != std::string::npos);
    CHECK(json.find("\"class\": \"api-call\"") != std::string::npos);
    CHECK(json.find("\"dispatchers\"") != std::string::npos);
    CHECK(json.find("\"dataDirectories\"") != std::string::npos);
    CHECK(json.find("\"name\": \"import\"") != std::string::npos);
    CHECK(json.find("\"packedSections\"") != std::string::npos);
    CHECK(json.find("\"tableRva\": \"0x2800\"") != std::string::npos);
    CHECK(json.find("\"apiReferences\"") != std::string::npos);
    CHECK(json.find("\"siteRva\": \"0x2720\"") != std::string::npos);
    CHECK(json.find("\"resolverStubCores\"") != std::string::npos);
    CHECK(json.find("\"rva\": \"0x2760\"") != std::string::npos);
    CHECK(json.find("mainCRTStartup") != std::string::npos);
    const std::string text = vmpstatic::renderText(analysis, "sample.exe");
    CHECK(text.find("detection:") != std::string::npos);
    CHECK(text.find("handler tables: 1") != std::string::npos);
}

}  // namespace

void testResolverStubCores() {
    auto pe = vmpstatic::parsePe(makePe32Plus(false));
    const auto cores = vmpstatic::findResolverStubCores(pe, 64);
    bool found = false;
    bool foundR8 = false;
    bool foundSp = false;
    for (const auto& c : cores) {
        if (c.rva == 0x2760) {
            found = true;
            CHECK(c.reg == 6);
            CHECK(c.packerSection);
        }
        if (c.rva == 0x2780) {
            foundR8 = true;
            CHECK(c.reg == 8);
            CHECK(c.packerSection);
        }
        if (c.rva == 0x27A0) foundSp = true;
    }
    CHECK(found);
    CHECK(foundR8);
    CHECK(!foundSp);
    // A triple with mismatched registers must not match.
    auto bad = makePe32Plus(false);
    bad[0xD68] = 0xBE;  // mov reg field rsi(6) -> rdi(7): breaks the shared-reg rule
    auto badPe = vmpstatic::parsePe(bad);
    bool badFound = false;
    for (const auto& c : vmpstatic::findResolverStubCores(badPe, 64)) {
        if (c.rva == 0x2760) badFound = true;
    }
    CHECK(!badFound);
}

int main() {
    testParse();
    testNames();
    testPeDiagnostics();
    testPackerMetadataDiscovery();
    testRawLzmaDecode();
    testImports();
    testDetection();
    testOep();
    testCookieOep();
    testEncodedTables();
    testVm();
    testDispatchers();
    testApiReferences();
    testResolverStubCores();
    testCatalog();
    testRoundTrip();
    if (failures == 0) std::printf("all tests passed\n");
    return failures == 0 ? 0 : 1;
}
