# clam_upx

Standalone UPX unpacker and ClamAV integration for PE32, PE32+, ELF32, and ELF64.

**Author:** David Zimmer / Cisco Security Research  
**License:** GPL v2 (decompression engines derived from ClamAV/libclamav)

---

## What it does

Decompresses UPX-packed executables for malware analysis and ClamAV signature development. Supports all four UPX compression algorithms across all four target formats, validated against UPX 1.20 through 5.1.1.

| Format | Architecture | NRV2B | NRV2D | NRV2E | LZMA |
|--------|-------------|-------|-------|-------|------|
| PE32 | Windows x86 | ✓ | ✓ | ✓ | ✓ |
| PE32+ | Windows x64 | ✓ | ✓ | ✓ | ✓ |
| ELF32 | Linux i386 | ✓ | ✓ | ✓ | ✓ |
| ELF64 | Linux x86-64 | ✓ | ✓ | ✓ | ✓ |

Format is detected automatically from the file header (`MZ` → PE path, `\x7fELF` → ELF path).

---

## Build

**Windows (MSVC):**
```
cl /W3 /O2 /TC clam_upx.c upx_pe.c upx_elf.c lzma_iface.c LzmaDec.c /Fe:clam_upx.exe
```

**Linux / macOS:**
```
gcc -Wall -O2 -o clam_upx clam_upx.c upx_pe.c upx_elf.c lzma_iface.c LzmaDec.c
```

A Visual Studio solution (`clam_upx_test.sln`) is included for Windows development.

---

## Usage

```
clam_upx <input> [output]
```

Output defaults to `<input>.unp`. Diagnostic output goes to stderr; the final write confirmation goes to stdout.

**Exit codes:** `0` success, `1` error, `2` all decompressors failed.

---

## Test harness

Test samples live under `tests/` organized by UPX version:

```
tests/
  1/    UPX 1.20  (PE32, ELF32)
  2/    UPX 2.02  (PE32, ELF32, ELF64)
  3/    UPX 3.09  (PE32, ELF32, ELF64 — first version with LZMA)
  4/    UPX 4.20  (PE32, PE32+, ELF32, ELF64)
  5/    UPX 5.01  (PE32, PE32+, ELF32, ELF64)
  51/   UPX 5.11  (PE32, PE32+, ELF32, ELF64)

Run all tests (Windows):

cscript tests\unpack_all.js
cscript tests\unpack_all.js -64        # use clam_upx64.exe
cscript tests\unpack_all.js 4          # single folder
```

The script deletes stale `.unp` files before each run so failures cannot hide behind previous successful output. Current result: **73/73 PASSED**.

---

## Architecture

All detection and decompression logic is split into two framework-free modules. The standalone tool and the ClamAV integration call the same code — the test harness validates exactly what ships in libclamav.

```
upx_pe.c / upx_pe.h     PE32 and PE32+ detection and decompression
upx_elf.c / upx_elf.h   ELF32 and ELF64 detection and decompression
clam_upx.c              Standalone tool (file I/O, format dispatch)
clamav_shim.h           ClamAV API stubs for standalone build
lzma_iface.c            LZMA state machine (from ClamAV, stripped of framework deps)
LzmaDec.c / LzmaDec.h   Igor Pavlov's LZMA decoder (7z SDK, public domain)
```

### Key design decision

`upx_unpack_pe32()` tries all three NRV variants plus LZMA unconditionally — it does not dispatch based on stub signature identification. UPX stub layouts shift across versions; fixed-offset probes that work for UPX 3.x miss UPX 4.x+. The try-all approach is robust against unknown stub variants and adversarially crafted inputs. Stub identification in `is_upx_pe32()` is advisory only, used for diagnostic logging.

For PE32+ (x64), stub identification does drive dispatch because x64 stub signatures are stable across all tested versions, and the `magic[]` import-table scan values differ by algorithm.

---

## Security

All fields read from packed binaries are tagged `[FROM FILE]` in the source and validated before use. See `SECURITY NOTES` in the legacy `README.txt` for the full list of checks. Do not run against untrusted input as root without a sandbox.
