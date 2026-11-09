# 7-Zip LZMA decoder

The files in this directory are from the C decoder in [ip7z/7zip](https://github.com/ip7z/7zip/tree/main/C):

- `LzmaDec.c`
- `LzmaDec.h`
- `7zTypes.h`
- `Precomp.h`
- `Compiler.h`

The 7-Zip LZMA SDK code is in the public domain, as stated by its source headers and the
[official SDK page](https://www.7-zip.org/sdk.html). The decoder is isolated behind the
project's bounded C++ wrapper in `src/lzma.cpp`.
