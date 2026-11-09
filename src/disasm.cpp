#include "disasm.hpp"

#include <cstdio>
#include <initializer_list>

#ifdef VMPSTATIC_CAPSTONE
#include <capstone/capstone.h>
#endif

namespace vmpstatic {
namespace {

#ifdef VMPSTATIC_CAPSTONE
bool in(const char* value, std::initializer_list<const char*> names) {
    for (const char* name : names) {
        if (std::string(value) == name) return true;
    }
    return false;
}

// Stack shuffling dominates VMProtect handler prologues, so the first non-stack
// instruction is what identifies the handler kind.
const char* classOfMnemonic(const char* mnemonic, const std::string& operands) {
    if (in(mnemonic, {"push", "pop", "pushfq", "popfq", "pusha", "popa", "enter", "leave"})) {
        return "stack";
    }
    if (in(mnemonic, {"mov", "movabs", "movzx", "movsx", "movsxd", "xchg"})) {
        if (operands.find('[') != std::string::npos) return "load-store";
        return "move";
    }
    if (in(mnemonic, {"lea"})) return "address";
    if (in(mnemonic, {"add", "sub", "and", "or", "xor", "adc", "sbb", "neg", "not", "inc",
                      "dec", "bswap"})) {
        return "arithmetic";
    }
    if (in(mnemonic, {"shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr", "shld", "shrd"})) {
        return "shift";
    }
    if (in(mnemonic, {"cmp", "test", "bt", "bts", "btr", "btc"})) return "compare";
    if (in(mnemonic, {"call"})) {
        return operands.find('[') != std::string::npos || operands.find("rip") != std::string::npos
                   ? "api-call"
                   : "call";
    }
    if (mnemonic[0] == 'j' && !in(mnemonic, {"jmp"})) return "branch";
    if (in(mnemonic, {"jmp"})) return "branch";
    if (in(mnemonic, {"ret", "retf", "iret", "iretd", "iretq"})) return "ret";
    if (in(mnemonic, {"syscall", "sysenter", "int", "int3", "ud2"})) return "trap";
    if (in(mnemonic, {"mul", "imul", "div", "idiv"})) return "muldiv";
    if (in(mnemonic, {"movs", "stos", "lods", "scas", "cmps", "rep", "repne"})) return "string";
    if (mnemonic[0] == 'c' && in(mnemonic, {"cmove", "cmovne", "cmovz", "cmovnz", "cmovb",
                                            "cmovae", "cmovbe", "cmova", "cmovl", "cmovge",
                                            "cmovle", "cmovg", "cmovs", "cmovns"})) {
        return "cmov";
    }
    if (in(mnemonic, {"bsf", "bsr", "popcnt", "tzcnt", "lzcnt", "crc32"})) return "bit";
    if (in(mnemonic, {"nop", "pause", "endbr64"})) return "nop";
    return nullptr;
}

HandlerClass classifyWithCapstone(const uint8_t* code, size_t size, uint64_t address, bool is64) {
    HandlerClass result;
    csh handle = 0;
    if (cs_open(CS_ARCH_X86, is64 ? CS_MODE_64 : CS_MODE_32, &handle) != CS_ERR_OK) {
        result.detail = "capstone open failed";
        return result;
    }
    cs_insn* insn = cs_malloc(handle);
    const uint8_t* cursor = code;
    size_t remaining = size;
    uint64_t current = address;
    std::string seen;
    const char* chosen = nullptr;
    for (int i = 0; i < 4 && cs_disasm_iter(handle, &cursor, &remaining, &current, insn); ++i) {
        if (!seen.empty()) seen += ", ";
        seen += insn->mnemonic;
        if (!chosen) {
            const char* cls = classOfMnemonic(insn->mnemonic, insn->op_str);
            if (cls && std::string(cls) != "stack") chosen = cls;
        }
    }
    cs_free(insn, 1);
    cs_close(&handle);
    result.name = chosen ? chosen : (seen.empty() ? "unknown" : "stack");
    result.detail = seen;
    return result;
}

#else

const char* classOfOpcode(const uint8_t* code, size_t size) {
    const uint8_t b = code[0];
    if ((b >= 0x50 && b <= 0x5F) || b == 0x9C || b == 0x9D) return "stack";
    if (b == 0x41 && size > 1 && code[1] >= 0x50 && code[1] <= 0x5F) return "stack";
    if (b == 0x8B || b == 0x89 || b == 0x8A || b == 0x88 || b == 0xC6 || b == 0xC7) {
        return "load-store";
    }
    if (b == 0x48 || b == 0x4C || b == 0x0F) {
        if (size > 1 && code[1] >= 0xB6 && code[1] <= 0xBF) return "move";
        if (size > 1 && code[1] >= 0x80 && code[1] <= 0x8F) return "branch";
        if (size > 1 && code[1] == 0x05) return "trap";
        if (size > 1 && (code[1] == 0xAF || code[1] == 0xA3 || code[1] == 0xAB)) return "bit";
    }
    if (b == 0x01 || b == 0x03 || b == 0x29 || b == 0x2B || b == 0x21 || b == 0x23 ||
        b == 0x31 || b == 0x33 || b == 0x83 || b == 0x81) {
        return "arithmetic";
    }
    if (b >= 0xD0 && b <= 0xD3) return "shift";
    if (b == 0xC0 || b == 0xC1) return "shift";
    if (b == 0x38 || b == 0x39 || b == 0x84 || b == 0x85) return "compare";
    if (b == 0xE8) return "call";
    if (b == 0xE9 || b == 0xEB) return "branch";
    if (b == 0xFF && size > 1) {
        if (code[1] >= 0x10 && code[1] <= 0x17) return "api-call";
        if (code[1] >= 0x20 && code[1] <= 0x27) return "branch";
        return "branch";
    }
    if (b == 0xC3 || b == 0xC2) return "ret";
    if (b == 0xF6 || b == 0xF7) return "muldiv";
    return nullptr;
}

HandlerClass classifyWithPattern(const uint8_t* code, size_t size) {
    HandlerClass result;
    for (size_t skip = 0; skip < size && skip < 8; ++skip) {
        const uint8_t* at = code + skip;
        const size_t left = size - skip;
        if (left < 2) break;
        const char* cls = classOfOpcode(at, left);
        if (!cls) continue;
        if (std::string(cls) == "stack" && skip + 1 < size) continue;  // prefer the real op
        result.name = cls;
        break;
    }
    char buffer[64];
    std::snprintf(buffer, sizeof buffer, "opcode 0x%02X (pattern mode)", code[0]);
    result.detail = buffer;
    return result;
}

#endif

}  // namespace

const char* disasmEngineName() {
#ifdef VMPSTATIC_CAPSTONE
    return "capstone";
#else
    return "pattern";
#endif
}

HandlerClass classifyHandler(const uint8_t* code, size_t size, uint64_t address, bool is64) {
    HandlerClass result;
    if (!code || size < 2) {
        result.detail = "too short";
        return result;
    }
#ifdef VMPSTATIC_CAPSTONE
    return classifyWithCapstone(code, size, address, is64);
#else
    (void)address;
    (void)is64;
    return classifyWithPattern(code, size);
#endif
}

}  // namespace vmpstatic
