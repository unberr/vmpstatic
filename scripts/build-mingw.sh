#!/bin/sh
# Cross-build a static Windows console binary. Requires x86_64-w64-mingw32-g++.
set -eu
cd "$(dirname "$0")/.."
out=${1:-build-win}
mkdir -p "$out"
x86_64-w64-mingw32-gcc -std=c11 -O2 -Wall -Wextra -Ithird_party/7zip_lzma \
    -c third_party/7zip_lzma/LzmaDec.c -o "$out/lzmadec.o"
x86_64-w64-mingw32-g++ -std=c++17 -O2 -Wall -Wextra -s -static -Isrc \
    -Ithird_party/7zip_lzma src/pe.cpp src/detect.cpp src/oep.cpp src/imports.cpp \
    src/disasm.cpp src/vm.cpp src/packer.cpp src/lzma.cpp src/analysis.cpp src/report.cpp \
    src/main.cpp "$out/lzmadec.o" -o "$out/vmpstatic.exe"
echo "wrote $out/vmpstatic.exe"
