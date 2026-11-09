#include "analysis.hpp"
#include "pe.hpp"
#include "report.hpp"
#include "strutil.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>

namespace {

void usage(const char* program) {
    std::printf(
        "vmpstatic %s - static VMProtect analysis and layout reconstruction\n"
        "\n"
        "usage:\n"
        "  %s inspect <file.exe> [--json] [--oep <rva|va>]\n"
        "  %s analyze <file.exe> [--report <path>] [--oep <rva|va>]\n"
        "  %s unpack  <file.exe> <out.exe> [--report <path>] [--oep <rva|va>]\n"
        "           [--raw-dump] [--artifacts <dir>]\n"
        "\n"
        "commands:\n"
        "  inspect   parse and report; --json prints the report to stdout\n"
        "  analyze   print the report and write JSON (default <file>.vmpstatic.json)\n"
        "  unpack    expand to a memory image, normalize section layout, patch the entry\n"
        "            point, and write a file. This does not rebuild imports.\n"
        "\n"
        "options:\n"
        "  --oep <rva|va>  entry point override (RVA, or VA when >= image base)\n"
        "  --catalog <dll> module export catalog for validating encoded imports;\n"
        "                  repeat for each DLL (e.g. ntdll.dll kernel32.dll)\n"
        "  --report <p>    JSON report path\n"
        "  --artifacts <d> save candidate PE/image and compressed/decompressed blocks\n"
        "  --json          inspect only: JSON instead of text\n"
        "  -h, --help      this text\n"
        "  --version       tool version\n"
        "\n"
        "the input must be a Windows .exe; it is never executed, loaded, or emulated.\n",
        vmpstatic::toolVersion(), program, program, program);
}

bool readFile(const std::string& path, std::vector<uint8_t>& out, std::string& error) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        error = "cannot open " + path;
        return false;
    }
    const std::streamoff size = in.tellg();
    if (size <= 0) {
        error = "cannot read size of " + path;
        return false;
    }
    if (static_cast<uint64_t>(size) > vmpstatic::kMaxImage) {
        error = "file exceeds the 1 GiB limit";
        return false;
    }
    out.resize(static_cast<size_t>(size));
    in.seekg(0);
    if (!in.read(reinterpret_cast<char*>(out.data()), size)) {
        error = "short read on " + path;
        return false;
    }
    return true;
}

bool writeRange(const std::string& path, const uint8_t* bytes, size_t size,
                std::string& error) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot create " + path;
        return false;
    }
    if (size) out.write(reinterpret_cast<const char*>(bytes), static_cast<std::streamsize>(size));
    if (!out) {
        error = "write failed for " + path;
        return false;
    }
    return true;
}

bool writeFile(const std::string& path, const std::vector<uint8_t>& bytes, std::string& error) {
    return writeRange(path, bytes.data(), bytes.size(), error);
}

bool writeFile(const std::string& path, const std::string& text, std::string& error) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot create " + path;
        return false;
    }
    out << text;
    if (!out) {
        error = "write failed for " + path;
        return false;
    }
    return true;
}

std::string baseName(const std::string& path) {
    const size_t slash = path.find_last_of("/\\");
    return vmpstatic::toLower(slash == std::string::npos ? path : path.substr(slash + 1));
}

bool hasExeExtension(const std::string& path) {
    const std::string name = baseName(path);
    return name.size() > 4 && name.compare(name.size() - 4, 4, ".exe") == 0;
}

bool pathsAlias(const std::string& first, const std::string& second) {
    std::error_code ec;
    if (std::filesystem::exists(second, ec) && !ec &&
        std::filesystem::equivalent(first, second, ec) && !ec) return true;
    ec.clear();
    const auto a = std::filesystem::weakly_canonical(first, ec);
    if (ec) return false;
    ec.clear();
    const auto b = std::filesystem::weakly_canonical(second, ec);
    return !ec && a == b;
}

bool writeArtifacts(const std::string& directory, const std::vector<uint8_t>& candidate,
                    const std::vector<uint8_t>& memoryImage, bool rawDump,
                    const vmpstatic::PeFile& pe, const vmpstatic::Analysis& analysis,
                    const std::string& jsonReport, std::string& error) {
    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    if (ec) {
        error = "cannot create artifact directory " + directory + ": " + ec.message();
        return false;
    }
    const std::filesystem::path root(directory);
    const auto candidatePath = root / (rawDump ? "candidate_memory.bin" : "candidate_pe.exe");
    if (!writeFile(candidatePath.string(), candidate, error) ||
        !writeFile((root / "report.json").string(), jsonReport, error)) return false;

    for (size_t i = 0; i < analysis.packedRecovery.blocks.size(); ++i) {
        const auto& block = analysis.packedRecovery.blocks[i];
        if (block.sourceFileOffset > pe.bytes.size() ||
            block.sourceRangeSize > pe.bytes.size() - block.sourceFileOffset) {
            error = "packed source artifact range is out of bounds";
            return false;
        }
        char name[96];
        std::snprintf(name, sizeof name, "block_%03zu_src_%08X_dst_%08X",
                      i, block.sourceRva, block.destinationRva);
        const size_t compressedSize = block.recovered ? block.compressedSize
                                                       : block.sourceRangeSize;
        if (!writeRange((root / (std::string(name) + ".compressed.bin")).string(),
                        pe.bytes.data() + block.sourceFileOffset, compressedSize, error))
            return false;
        if (!block.recovered) continue;
        if (block.destinationRva > memoryImage.size() ||
            block.decompressedSize > memoryImage.size() - block.destinationRva) {
            error = "decompressed artifact range is out of bounds";
            return false;
        }
        if (!writeRange((root / (std::string(name) + ".decompressed.bin")).string(),
                        memoryImage.data() + block.destinationRva,
                        block.decompressedSize, error)) return false;
    }
    return true;
}

bool parseNumber(const std::string& text, uint64_t& value) {
    if (text.empty()) return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(text.c_str(), &end, 0);
    if (errno != 0 || !end || *end != '\0') return false;
    value = static_cast<uint64_t>(parsed);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    const std::string command = argv[1];
    if (command == "-h" || command == "--help") {
        usage(argv[0]);
        return 0;
    }
    if (command == "--version") {
        std::printf("vmpstatic %s\n", vmpstatic::toolVersion());
        return 0;
    }

    std::vector<std::string> positional;
    std::vector<std::string> catalogPaths;
    std::string reportPath;
    std::string artifactsPath;
    std::string oepText;
    bool json = false;
    bool rawDump = false;
    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            return 0;
        }
        if (arg == "--json") {
            json = true;
        } else if (arg == "--raw-dump") {
            rawDump = true;
        } else if (arg == "--report" && i + 1 < argc) {
            reportPath = argv[++i];
        } else if (arg == "--artifacts" && i + 1 < argc) {
            artifactsPath = argv[++i];
        } else if (arg == "--oep" && i + 1 < argc) {
            oepText = argv[++i];
        } else if (arg == "--catalog" && i + 1 < argc) {
            catalogPaths.push_back(argv[++i]);
        } else if (arg.rfind("--", 0) == 0) {
            std::fprintf(stderr, "unknown option: %s\n", arg.c_str());
            return 2;
        } else {
            positional.push_back(arg);
        }
    }

    const bool isInspect = command == "inspect";
    const bool isAnalyze = command == "analyze";
    const bool isUnpack = command == "unpack";
    if (!isInspect && !isAnalyze && !isUnpack) {
        std::fprintf(stderr, "unknown command: %s\n", command.c_str());
        usage(argv[0]);
        return 2;
    }
    if (rawDump && !isUnpack) {
        std::fprintf(stderr, "--raw-dump is valid only with unpack\n");
        return 2;
    }
    if (!artifactsPath.empty() && !isUnpack) {
        std::fprintf(stderr, "--artifacts is valid only with unpack\n");
        return 2;
    }
    if (rawDump && !oepText.empty()) {
        std::fprintf(stderr, "--raw-dump cannot be combined with --oep\n");
        return 2;
    }
    const size_t required = isUnpack ? 2 : 1;
    if (positional.size() != required) {
        std::fprintf(stderr, "%s expects %zu argument(s)\n", command.c_str(), required);
        return 2;
    }

    const bool hasManualOep = !oepText.empty();
    uint64_t manualOep = 0;
    if (hasManualOep && !parseNumber(oepText, manualOep)) {
        std::fprintf(stderr, "invalid --oep value: %s\n", oepText.c_str());
        return 2;
    }

    const std::string& inputPath = positional[0];
    if (!hasExeExtension(inputPath)) {
        std::fprintf(stderr, "%s: expected a Windows .exe file\n", inputPath.c_str());
        return 2;
    }
    if (isUnpack) {
        const std::string& outputPath = positional[1];
        if (!rawDump && !hasExeExtension(outputPath)) {
            std::fprintf(stderr, "%s: output must be a Windows .exe file\n",
                         outputPath.c_str());
            return 2;
        }
        if (pathsAlias(inputPath, outputPath)) {
            std::fprintf(stderr, "input and output paths resolve to the same file\n");
            return 2;
        }
    }
    std::vector<uint8_t> file;
    std::string error;
    if (!readFile(inputPath, file, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 1;
    }

    auto pe = vmpstatic::parsePe(std::move(file));
    if (!pe.valid) {
        std::fprintf(stderr, "%s: not a supported PE: %s\n", inputPath.c_str(), pe.error.c_str());
        return 1;
    }

    if (hasManualOep) {
        uint32_t manualRva = 0;
        const bool validAddress = manualOep >= pe.imageBase
                                      ? vmpstatic::vaToRva(pe, manualOep, manualRva)
                                      : (manualOep <= 0xFFFFFFFFull &&
                                         manualOep < pe.sizeOfImage &&
                                         (manualRva = static_cast<uint32_t>(manualOep), true));
        if (!validAddress) {
            std::fprintf(stderr, "--oep address is outside the PE image\n");
            return 2;
        }
    }

    std::vector<vmpstatic::PeFile> catalogs;
    catalogs.reserve(catalogPaths.size());
    for (const std::string& catalogPath : catalogPaths) {
        std::vector<uint8_t> bytes;
        if (!readFile(catalogPath, bytes, error)) {
            std::fprintf(stderr, "warning: %s\n", error.c_str());
            continue;
        }
        auto dll = vmpstatic::parsePe(std::move(bytes));
        if (!dll.valid) {
            std::fprintf(stderr, "warning: %s: not a PE (%s)\n", catalogPath.c_str(),
                         dll.error.c_str());
            continue;
        }
        catalogs.push_back(std::move(dll));
    }

    std::vector<vmpstatic::CatalogModule> catalogModules;
    catalogModules.reserve(catalogs.size());
    for (size_t i = 0; i < catalogs.size(); ++i) {
        catalogModules.push_back({baseName(catalogPaths[i]), &catalogs[i]});
    }
    const vmpstatic::ExportCatalog catalog =
        vmpstatic::buildExportCatalog(catalogModules);
    if (!catalogPaths.empty() && catalog.modules.empty()) {
        std::fprintf(stderr, "warning: no exports parsed from the supplied catalogs\n");
    }

    vmpstatic::AnalyzeOptions options;
    options.manualOep = manualOep;
    options.hasManualOep = hasManualOep;
    options.catalog = catalog.modules.empty() ? nullptr : &catalog;
    vmpstatic::Analysis analysis = vmpstatic::analyze(pe, options);

    if (isUnpack) {
        const std::string& outputPath = positional[1];
        const std::string report = reportPath.empty() ? outputPath + ".analysis.json" : reportPath;
        if (pathsAlias(inputPath, report) || pathsAlias(outputPath, report)) {
            std::fprintf(stderr, "report path must not resolve to the input or output file\n");
            return 2;
        }
        if (!artifactsPath.empty() &&
            (pathsAlias(inputPath, artifactsPath) || pathsAlias(outputPath, artifactsPath) ||
             pathsAlias(report, artifactsPath))) {
            std::fprintf(stderr, "artifact directory must not resolve to an input/output file\n");
            return 2;
        }
        std::vector<uint8_t> image;
        if (!vmpstatic::fileToImage(pe, image, error)) {
            std::fprintf(stderr, "%s\n", error.c_str());
            return 1;
        }
        analysis.packedRecovery =
            vmpstatic::decompressPackedSections(pe, analysis.packerInfo, image);
        if (!rawDump && !vmpstatic::patchEntryPoint(image, pe, analysis.selectedOep)) {
            std::fprintf(stderr, "entry point RVA 0x%X is outside the image\n",
                         analysis.selectedOep);
            return 1;
        }
        std::vector<uint8_t> output;
        if (rawDump) {
            if (!writeFile(outputPath, image, error)) {
                std::fprintf(stderr, "%s\n", error.c_str());
                return 1;
            }
        } else {
            if (!vmpstatic::imageToFile(pe, image, output, error)) {
                std::fprintf(stderr, "%s\n", error.c_str());
                return 1;
            }
        }
        for (const auto& block : analysis.packedRecovery.blocks) {
            if (!block.recovered)
                std::fprintf(stderr, "warning: packed block at RVA 0x%X was not restored: %s\n",
                             block.sourceRva, block.error.c_str());
        }
        if (!rawDump && !writeFile(outputPath, output, error)) {
            std::fprintf(stderr, "%s\n", error.c_str());
            return 1;
        }
        const std::string jsonReport = vmpstatic::renderJson(analysis, inputPath);
        if (!writeFile(report, jsonReport, error)) {
            std::fprintf(stderr, "%s\n", error.c_str());
            return 1;
        }
        if (!artifactsPath.empty() &&
            !writeArtifacts(artifactsPath, rawDump ? image : output, image, rawDump,
                            pe, analysis, jsonReport, error)) {
            std::fprintf(stderr, "%s\n", error.c_str());
            return 1;
        }
        std::printf("%s\n", vmpstatic::renderText(analysis, inputPath).c_str());
        if (rawDump) {
            std::printf("wrote raw memory image %s (%zu bytes); no PE repairs applied\n",
                        outputPath.c_str(), image.size());
        } else {
            std::printf("wrote %s (%zu bytes), entry point 0x%X\n", outputPath.c_str(),
                        output.size(), analysis.selectedOep);
        }
        std::printf("report: %s\n", report.c_str());
        if (!artifactsPath.empty()) std::printf("artifacts: %s\n", artifactsPath.c_str());
        return 0;
    }

    if (isInspect) {
        std::printf("%s", json ? vmpstatic::renderJson(analysis, inputPath).c_str()
                               : vmpstatic::renderText(analysis, inputPath).c_str());
        if (!reportPath.empty() && pathsAlias(inputPath, reportPath)) {
            std::fprintf(stderr, "report path must not resolve to the input file\n");
            return 2;
        }
        if (!reportPath.empty() &&
            !writeFile(reportPath, vmpstatic::renderJson(analysis, inputPath), error)) {
            std::fprintf(stderr, "%s\n", error.c_str());
            return 1;
        }
        return 0;
    }

    const std::string report = reportPath.empty() ? inputPath + ".vmpstatic.json" : reportPath;
    if (pathsAlias(inputPath, report)) {
        std::fprintf(stderr, "report path must not resolve to the input file\n");
        return 2;
    }
    if (!writeFile(report, vmpstatic::renderJson(analysis, inputPath), error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 1;
    }
    std::printf("%s", vmpstatic::renderText(analysis, inputPath).c_str());
    std::printf("report: %s\n", report.c_str());
    return 0;
}
