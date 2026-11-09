#include "oep.hpp"

#include "checked.hpp"
#include "strutil.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace vmpstatic {
namespace {

constexpr size_t kMaxScanPerSection = 4u << 20;  // 4 MiB per section
constexpr size_t kMaxCandidates = 4096;

bool isKnownSafeName(const std::string& name) {
    static const char* kSafe[] = {".rdata", ".data",  ".pdata", ".rsrc", ".reloc",
                                  ".idata", ".edata", ".tls",   ".gfids", ".crt",
                                  ".xdata", ".bss",   ".text"};
    const std::string n = toLower(name);
    for (const char* safe : kSafe) {
        const std::string prefix(safe);
        if (n.compare(0, prefix.size(), prefix) == 0) return true;
    }
    return false;
}

bool isNonPackerExec(const PeFile& pe, uint32_t rva, const Section** out) {
    const Section* s = sectionForRva(pe, rva);
    if (!s || !s->exec || isPackerSection(*s)) return false;
    *out = s;
    return true;
}

void addCandidate(std::vector<OepCandidate>& out, uint32_t rva, OepMethod method,
                  Confidence confidence, std::string evidence) {
    for (const OepCandidate& c : out) {
        if (c.rva == rva) return;
    }
    out.push_back({rva, method, confidence, std::move(evidence)});
}

// Default MSVC security-cookie immediates: the anchor for cookie-based OEP
// recovery (Opus 5.5 review). Static-only: byte patterns, never executed.
bool findCookieImmediate(const uint8_t* data, size_t limit, bool is64, size_t& at) {
    static const uint8_t k32[] = {0x4E, 0xE6, 0x40, 0xBB};
    static const uint8_t k64[] = {0x32, 0xA2, 0xDF, 0x2D, 0x99, 0x2B, 0x00, 0x00};
    const uint8_t* pattern = is64 ? k64 : k32;
    const size_t length = is64 ? sizeof k64 : sizeof k32;
    for (size_t i = 0; i + length <= limit; ++i) {
        if (std::memcmp(data + i, pattern, length) == 0) {
            at = i;
            return true;
        }
    }
    return false;
}

// Nearest generic function prologue at or before `from` (bounded back-scan).
bool functionStartBefore(const uint8_t* data, size_t from, size_t available, size_t& start) {
    if (from >= available) return false;
    const size_t earliest = from > 0x200 ? from - 0x200 : 0;
    for (size_t i = from + 1; i-- > earliest;) {
        if (i + 3 <= available && looksLikePrologue(data + i, available - i)) {
            start = i;
            return true;
        }
    }
    return false;
}

// Cookie-anchored OEP: __security_init_cookie reference -> E8 caller whose next
// instruction is the CRT epilogue/tail-jmp -> caller function start.
// Only fires when .text is visible (packed/encrypted CRT stays silent by design).
std::vector<OepCandidate> findCookieAnchoredOep(const PeFile& pe) {
    std::vector<OepCandidate> out;
    struct CookieRef {
        const Section* section;
        size_t offset;
    };
    std::vector<CookieRef> cookies;
    for (const Section& sec : pe.sections) {
        if (!sec.exec || isPackerSection(sec) || sec.rawPtr >= pe.bytes.size()) continue;
        const size_t available = std::min<size_t>(sec.rawSize, pe.bytes.size() - sec.rawPtr);
        size_t at = 0;
        if (findCookieImmediate(pe.bytes.data() + sec.rawPtr, available, pe.is64, at)) {
            cookies.push_back({&sec, at});
        }
    }
    for (const CookieRef& c : cookies) {
        size_t funcOff = 0;
        if (!functionStartBefore(pe.bytes.data() + c.section->rawPtr, c.offset,
                                 std::min<size_t>(c.section->rawSize,
                                          pe.bytes.size() - c.section->rawPtr),
                                 funcOff)) {
            continue;
        }
        const uint32_t cookieFunc = c.section->va + static_cast<uint32_t>(funcOff);
        for (const Section& sec : pe.sections) {
            if (!sec.exec || sec.rawPtr >= pe.bytes.size()) continue;
            const size_t available = std::min<size_t>(sec.rawSize, pe.bytes.size() - sec.rawPtr);
            const uint8_t* data = pe.bytes.data() + sec.rawPtr;
            for (size_t i = 0; i + 5 <= available; ++i) {
                if (data[i] != 0xE8) continue;
                const int32_t rel = static_cast<int32_t>(le32(data + i + 1));
                const int64_t target = static_cast<int64_t>(sec.va + i + 5) + rel;
                if (target != cookieFunc) continue;
                bool epilogue = false;
                if (!pe.is64 && i + 5 + 1 <= available && data[i + 5] == 0xE9) {
                    epilogue = true;
                } else if (pe.is64 && i + 5 + 9 <= available && data[i + 5] == 0x48 &&
                           data[i + 6] == 0x83 && data[i + 7] == 0xC4 &&
                           data[i + 8] == 0x28 && data[i + 9] == 0xE9) {
                    epilogue = true;
                }
                if (!epilogue) continue;
                size_t callerOff = 0;
                if (!functionStartBefore(data, i, available, callerOff)) continue;
                addCandidate(out, sec.va + static_cast<uint32_t>(callerOff),
                             OepMethod::PrologueScan, Confidence::Medium,
                             "security-cookie-anchored mainCRTStartup (call at rva " +
                                 hex(sec.va + static_cast<uint32_t>(i)) + ")");
            }
        }
    }
    return out;
}

}  // namespace

const char* oepMethodName(OepMethod m) {
    switch (m) {
    case OepMethod::Manual: return "manual";
    case OepMethod::EntryPoint: return "entry-point";
    case OepMethod::BranchScan: return "branch-scan";
    case OepMethod::PrologueScan: return "prologue-scan";
    }
    return "unknown";
}

bool isPackerSection(const Section& section) {
    if (section.vmpName || isVmpSectionName(section.name)) return true;
    const std::string n = toLower(section.name);
    if (n.compare(0, 5, ".text") == 0 || isKnownSafeName(section.name)) return false;
    return section.exec && section.mappedSize() >= 0x1000;
}

Confidence crtPrologueConfidence(const uint8_t* data, size_t size) {
    // MSVC CRT startup signatures (VMProtectDumper pass 1-2, unpaki OEP research).
    // Static-only: pattern match, never executed. Specificity differs per pattern.
    if (!data || size < 10) return Confidence::None;
    // x86 SEH setup: 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 (13 bytes, VC6-VS2005 era)
    if (size >= 13 && data[0] == 0x6A && data[1] == 0xFF && data[2] == 0x68 &&
        data[7] == 0x64 && data[8] == 0xA1 && data[9] == 0x00 && data[10] == 0x00 &&
        data[11] == 0x00 && data[12] == 0x00) {
        return Confidence::Medium;
    }
    // x86 security-cookie init: E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? (call+jmp back-to-back).
    // Only 2 bytes are fixed, so tail-call thunks collide: keep Low.
    if (data[0] == 0xE8 && data[5] == 0xE9) return Confidence::Low;
    return Confidence::None;
}

bool looksLikePrologue(const uint8_t* data, size_t size) {
    if (!data || size < 2) return false;
    static const uint8_t kPrologues[][8] = {
        {0x55, 0x8B, 0xEC},              // push ebp; mov ebp, esp
        {0x48, 0x89, 0x5C, 0x24},        // mov [rsp+..], rbx
        {0x48, 0x83, 0xEC},              // sub rsp, imm8
        {0x48, 0x81, 0xEC},              // sub rsp, imm32
        {0x40, 0x53},                    // push rbx (REX)
        {0x40, 0x55},                    // push rbp (REX)
        {0x48, 0x8B, 0xC4},              // mov rax, rsp
        {0x48, 0x89, 0x4C, 0x24},        // mov [rsp+..], rcx
    };
    for (const auto& pattern : kPrologues) {
        if (std::memcmp(data, pattern, 3) == 0) return true;
    }
    return false;
}

std::vector<OepCandidate> findOepCandidates(const PeFile& pe, size_t maxResults) {
    std::vector<OepCandidate> out;

    const Section* ep = sectionForRva(pe, pe.entryPoint);
    if (ep && !isPackerSection(*ep)) {
        addCandidate(out, pe.entryPoint, OepMethod::EntryPoint, Confidence::High,
                     "AddressOfEntryPoint already in non-packer section " + ep->name);
    } else if (ep) {
        addCandidate(out, pe.entryPoint, OepMethod::EntryPoint, Confidence::Low,
                     "AddressOfEntryPoint inside packer-like section " + ep->name);
    } else {
        addCandidate(out, pe.entryPoint, OepMethod::EntryPoint, Confidence::Low,
                     "AddressOfEntryPoint outside every section");
    }

    for (const Section& sec : pe.sections) {
        if (!sec.exec) continue;
        const size_t available = std::min<size_t>(std::min(sec.rawSize, sec.mappedSize()),
                                                  kMaxScanPerSection);
        if (sec.rawPtr >= pe.bytes.size() || available < 5) continue;
        const size_t limit = std::min(available, pe.bytes.size() - sec.rawPtr);
        const uint8_t* data = pe.bytes.data() + sec.rawPtr;

        if (isPackerSection(sec)) {
            // Only rel32 branches whose target starts like a real function count; random
            // bytes in an encrypted section almost never satisfy that.
            for (size_t i = 0; i + 5 <= limit && out.size() < kMaxCandidates; ++i) {
                const uint8_t op = data[i];
                size_t length = 0;
                if (op == 0xE8 || op == 0xE9) {
                    length = 5;
                } else if (op == 0x0F && i + 6 <= limit && (data[i + 1] & 0xF0) == 0x80) {
                    length = 6;
                } else {
                    continue;
                }
                const int32_t rel = static_cast<int32_t>(le32(data + i + length - 4));
                const int64_t target = static_cast<int64_t>(sec.va) + static_cast<int64_t>(i) +
                                       static_cast<int64_t>(length) + rel;
                if (target < 0 || static_cast<uint64_t>(target) >= pe.sizeOfImage) continue;
                const uint32_t targetRva = static_cast<uint32_t>(target);
                const Section* targetSection = nullptr;
                if (!isNonPackerExec(pe, targetRva, &targetSection)) continue;
                const uint32_t delta = targetRva - targetSection->va;
                if (delta >= targetSection->rawSize) continue;
                const uint8_t* targetData = pe.bytes.data() + targetSection->rawPtr + delta;
                const bool atStart = delta < 0x20;
                if (!atStart && !looksLikePrologue(targetData, targetSection->rawSize - delta)) {
                    continue;
                }
                addCandidate(out, targetRva, OepMethod::BranchScan,
                             atStart ? Confidence::High : Confidence::Medium,
                             std::string(op == 0xE8 ? "call" : "branch") + " at rva " +
                                 hex(sec.va + i) + " into " + targetSection->name);
            }
            continue;
        }

        // Non-packer executable section: its start is a plausible original entry point.
        if (limit >= 2 && looksLikePrologue(data, limit)) {
            addCandidate(out, sec.va, OepMethod::PrologueScan, Confidence::Low,
                         "prologue at start of " + sec.name);
        }
        for (size_t i = 1; i < std::min<size_t>(0x40, limit); ++i) {
            if (!looksLikePrologue(data + i, limit - i)) continue;
            addCandidate(out, sec.va + static_cast<uint32_t>(i), OepMethod::PrologueScan,
                         Confidence::Low, "prologue near start of " + sec.name);
            break;
        }
        // CRT startup deeper in .text (VMProtectDumper CRT scan, r0da packing post):
        // high-specificity patterns only, bounded 0x400 window. SEH is Medium,
        // the bare call+jmp shape is Low (tail-call thunks collide).
        for (size_t i = 0; i + 10 <= limit && i < 0x400; ++i) {
            const Confidence crt = crtPrologueConfidence(data + i, limit - i);
            if (crt == Confidence::None) continue;
            addCandidate(out, sec.va + static_cast<uint32_t>(i), OepMethod::PrologueScan,
                         crt, "CRT startup pattern in " + sec.name);
            break;
        }
    }

    for (OepCandidate c : findCookieAnchoredOep(pe)) out.push_back(std::move(c));

    std::sort(out.begin(), out.end(), [](const OepCandidate& a, const OepCandidate& b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        if (a.method != b.method) return a.method < b.method;
        return a.rva < b.rva;
    });
    if (out.size() > maxResults) out.resize(maxResults);
    return out;
}

}  // namespace vmpstatic
