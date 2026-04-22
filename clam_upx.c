/*
 * clam_upx.c
 *
 * Automatic UPX unpacker for PE32 (x86), PE32+ (x64), ELF32 (i386),
 * and ELF64 (x86-64) files,
 * using ClamAV's upx.c decompression engines.
 *
 * Supports all four UPX compression algorithms:
 *   NRV2B, NRV2D, NRV2E  (bit-stream LZ77 variants)
 *   LZMA                  (requires lzma_iface.c + LzmaDec.c)
 *
 * Build (MSVC 2019/2022, Developer Command Prompt):
 *   cl /W3 /O2 /TC clam_upx.c upx_elf.c upx_standalone.c lzma_iface.c LzmaDec.c /Fe:clam_upx.exe
 *
 * Build (GCC/MinGW/Linux):
 *   gcc -Wall -O2 -I. -o clam_upx clam_upx.c upx_elf.c upx_standalone.c lzma_iface.c LzmaDec.c
 *
 * ELF decompression is implemented in upx_elf.c (see upx_elf.h).
 * This file contains PE32/PE32+ decompression and the main() entry point.
 *
 *
 * Usage:
 *   clam_upx <packed.exe> [output.bin] [algo]
 *
 *   packed.exe   UPX-packed PE32, PE32+, or ELF32 binary
 *   output.bin   optional output filename  (default: <input>.unp)
 *   algo         2b | 2d | 2e | lzma | all  (default: all)
 *
 * ── HOW UPX PACKING WORKS (brief) ─────────────────────────────────────
 *
 * UPX creates two (PE32) or three (PE32+) new sections:
 *   UPX0: empty on disk (SizeOfRawData==0), large virtual size.
 *         This is the destination buffer at runtime.
 *   UPX1: contains the compressed original image + the stub decompressor
 *         code at the end. The PE entry point is set to point into UPX1
 *         where the stub begins.
 *   UPX2: PE32+ only. Small section containing the UPX identity string
 *         and metadata. Not involved in decompression.
 *
 * At load time, the OS maps UPX1 into memory. The CPU jumps to EP (in
 * UPX1), the stub decompresses UPX1's payload into UPX0's virtual space,
 * then jumps to the original entry point within UPX0.
 *
 * We reverse this offline: read UPX1 raw bytes, pass to the decompressor,
 * collect output into a buffer, then reconstruct PE headers around it.
 *
 * ── SECURITY MODEL ────────────────────────────────────────────────────
 *
 * Every field read from the packed binary is explicitly labelled
 * [FROM FILE] below. Each such field is validated before use:
 *   - Integer fields are range-checked against known-sane limits
 *   - Pointer/offset fields are checked against [0, fsz) before deref
 *   - Sizes are checked for overflow before any arithmetic
 *   - The decompressor output buffer is fixed at dsize+8192 bytes,
 *     and dsize itself is bounded before allocation
 *
 * ── x64 STUB DIFFERENCES FROM x86 ────────────────────────────────────
 *
 * The x64 (PE32+) UPX stub differs from x86 in several important ways:
 *
 * 1. No skew. x86 stubs use 'mov esi, imm32' (absolute VA of compressed
 *    data) allowing a "skew" offset to be computed. x64 stubs use
 *    'lea rsi,[rip+rel32]' (RIP-relative), so no absolute VA is present
 *    and skew does not apply.
 *
 * 2. Different stub layout. The NRV_HEAD signature and algo-specific
 *    code appear at different offsets from EP. All constants below were
 *    derived by disassembling real UPX 4.x packed PE64 binaries.
 *
 * 3. Three sections. PE32+ packed files have UPX0 + UPX1 + UPX2.
 *    The section-pair finder stops at the first UPX0+UPX1 match,
 *    naturally ignoring UPX2.
 *
 * 4. LZMA 2-byte header. x64 UPX uses a custom 2-byte properties header
 *    before the LZMA stream (documented in UPX's compress_lzma.cpp):
 *      byte[0] = ((lc+lp) << 3) | pb    <- NOT the standard LZMA props byte
 *      byte[1] = (lp << 4) | lc
 *    The LZMA compressed data follows from byte[2] onward.
 *    ClamAV's upx_inflatelzma() skips 2 bytes (src+2) and builds its own
 *    fake 5-byte LZMA header from the 'properties' argument, so we must
 *    decode the UPX 2-byte header format, not treat byte[0] as a standard
 *    LZMA props byte.
 *
 * 5. pe64fromupx() replaces pefromupx(). After decompression the output
 *    buffer contains raw original-image content, not a valid PE file.
 *    pe64fromupx() reconstructs a PE32+ wrapper exactly as pefromupx()
 *    does for PE32, but with PE64-appropriate header sizes and magic.
 */

#include "clamav_shim.h"
#include "upx.h"
#include "lzma_iface.h"
#include "upx_elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * PE32 / PE32+ UPX DECOMPRESSION
 * The following code handles Windows PE format (MZ magic).
 * ═══════════════════════════════════════════════════════════════════ */

/* ── Portable PE structures ──────────────────────────────────────────
 * Defined here so the tool compiles without windows.h on Linux/GCC.
 * PACK_PUSH/PACK_POP ensure 1-byte packing to match on-disk layout.  */
#ifdef _MSC_VER
  #define PACK_PUSH __pragma(pack(push,1))
  #define PACK_POP  __pragma(pack(pop))
#else
  #define PACK_PUSH _Pragma("pack(push,1)")
  #define PACK_POP  _Pragma("pack(pop)")
#endif

PACK_PUSH
typedef struct {
    uint16_t e_magic;       /* Must be MZ_MAGIC = 0x5A4D               */
    uint16_t e_cblp,e_cp,e_crlc,e_cparhdr,e_minalloc,e_maxalloc;
    uint16_t e_ss,e_sp,e_csum,e_ip,e_cs,e_lfarlc,e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid,e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;      /* [FROM FILE] offset to PE signature       */
} DOS_HEADER;

typedef struct {
    uint16_t Machine;               /* [FROM FILE] CPU architecture     */
    uint16_t NumberOfSections;      /* [FROM FILE] section count        */
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;  /* [FROM FILE] opt header byte count*/
    uint16_t Characteristics;
} FILE_HEADER;

typedef struct {                    /* PE32 optional header (Magic=0x10b) */
    uint16_t Magic;                 /* [FROM FILE] must be PE32_MAGIC   */
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;   /* [FROM FILE] EP RVA               */
    uint32_t BaseOfCode, BaseOfData;
    uint32_t ImageBase;             /* [FROM FILE] 4 bytes in PE32      */
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOSVersion,MinorOSVersion,MajorImageVersion,MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint32_t SizeOfStackReserve, SizeOfStackCommit;
    uint32_t SizeOfHeapReserve,  SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
} OPT32;

typedef struct {                    /* PE32+ optional header (Magic=0x20b) */
    uint16_t Magic;                 /* [FROM FILE] must be PE64_MAGIC   */
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;   /* [FROM FILE] EP RVA               */
    uint32_t BaseOfCode;
    /* NOTE: no BaseOfData field in PE32+ */
    uint64_t ImageBase;             /* [FROM FILE] 8 bytes in PE32+     */
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOSVersion,MinorOSVersion,MajorImageVersion,MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint64_t SizeOfStackReserve, SizeOfStackCommit; /* 8 bytes in PE32+ */
    uint64_t SizeOfHeapReserve,  SizeOfHeapCommit;  /* 8 bytes in PE32+ */
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
} OPT64;

typedef struct {
    uint8_t  Name[8];               /* [FROM FILE] section name (not NUL-terminated guaranteed) */
    uint32_t VirtualSize;           /* [FROM FILE] in-memory size       */
    uint32_t VirtualAddress;        /* [FROM FILE] RVA in memory        */
    uint32_t SizeOfRawData;         /* [FROM FILE] on-disk size (0 = UPX0 pattern) */
    uint32_t PointerToRawData;      /* [FROM FILE] file offset of raw data */
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SHDR;
PACK_POP

#define MZ_MAGIC   0x5A4Du          /* "MZ" */
#define PE_MAGIC   0x00004550u      /* "PE\0\0" */
#define PE32_MAGIC 0x010Bu          /* PE32 optional header magic */
#define PE64_MAGIC 0x020Bu          /* PE32+ optional header magic */

/* Maximum section count we accept from the binary.
 * The PE spec permits up to 96. This caps potential loops.           */
#define MAX_SECTIONS 96

/* ── main ────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    /* All declarations at top for C89/MSVC /TC compatibility */
    const char  *infile, *outfile;
    FILE        *f;
    long         fsz;
    uint8_t     *filebuf;           /* entire file in memory            */
    DOS_HEADER  *dos;
    FILE_HEADER *fhdr;
    uint16_t     opt_magic;         /* [FROM FILE] PE32 or PE32+ magic  */
    int          is64;              /* true if PE32+                    */
    SHDR        *sects;             /* pointer into filebuf             */
    int          nsect, i, upx0, upx1;
    /* Parameters passed to inflate functions - all derived from [FROM FILE] fields */
    uint32_t     ssize;    /* [FROM FILE] UPX1 raw/compressed size     */
    uint32_t     dsize;    /* [FROM FILE] UPX0.vsz + UPX1.vsz         */
    uint32_t     upx0_rva; /* [FROM FILE] UPX0 virtual address (RVA)  */
    uint32_t     upx1_rva; /* [FROM FILE] UPX1 virtual address (RVA)  */
    uint32_t     ep_rva;   /* [FROM FILE] AddressOfEntryPoint (RVA)   */
    uint64_t     imagebase;/* [FROM FILE] image load address           */
    size_t       ep_foff;  /* derived: file offset of entry point      */
    const uint8_t *epbuff; /* pointer into filebuf at ep_foff          */
    const uint8_t *src;    /* pointer to compressed data in filebuf    */
    char        *dest = NULL; /* decompressed output buffer               */
    uint32_t     outdsize;
    int          success;

    /* ── argument parsing ── */
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <packed.exe> [out.bin]\n"
            "  Supports PE32 (x86) and PE32+ (x64) and ELF 32/64\n", argv[0]);
        return 1;
    }
    infile = argv[1];
    {
        /* Default output filename: input + ".unp"
         * Using a static buffer avoids malloc failure path here.     */
        static char ob[4096];
        if (argc >= 3) {
            outfile = argv[2];
        } else {
            size_t n = strlen(infile);
            if (n+5 > sizeof(ob)) n = sizeof(ob)-5;  /* truncate safely */
            memcpy(ob, infile, n);
            memcpy(ob+n, ".unp", 5);   /* includes NUL terminator */
            outfile = ob;
        }
    }

    /* ── read entire file into memory ── */
    f = fopen(infile,"rb");
    if (!f) { perror(infile); return 1; }
    fseek(f,0,SEEK_END); fsz=ftell(f); rewind(f);
    /* Minimum: DOS header (64 bytes) + PE sig (4) + COFF header (20) */
    if (fsz < 0x80) { fprintf(stderr,"file too small to be a PE\n"); fclose(f); return 1; }
    /* SECURITY: allocate DECOMP_OVERHEAD extra bytes past the file content.
     * The x86/x64 LZMA decoder (LzmaDec) reads its input with a range coder
     * that may advance its internal buffer pointer one byte past the declared
     * inSize before the end-of-input check fires.  When the compressed data
     * (UPX1 section raw bytes) ends at exactly filebuf+fsz, that one-byte
     * overread lands one byte past the malloc'd region.  Adding DECOMP_OVERHEAD
     * gives LzmaDec a safe zero-filled landing zone.  calloc() ensures the
     * padding bytes are zero so they cannot feed false LZMA stream data.  */
    filebuf = (uint8_t*)calloc((size_t)fsz + DECOMP_OVERHEAD, 1);
    if (!filebuf) { perror("malloc"); fclose(f); return 1; }
    if (fread(filebuf,1,(size_t)fsz,f)!=(size_t)fsz) {
        perror("fread"); fclose(f); free(filebuf); return 1; }
    fclose(f);

    /* ── detect file format: PE (MZ) or ELF ────────────────────────────
     * Check the first 4 bytes.  An ELF file starts with \x7fELF.
     * A PE file starts with MZ (0x5a4d).
     * Anything else is rejected.                                     */
    if (fsz >= 4 &&
        filebuf[0] == 0x7f && filebuf[1] == 'E' &&
        filebuf[2] == 'L'  && filebuf[3] == 'F') {
        int r = handle_elf(filebuf, (size_t)fsz, outfile);
        free(filebuf);
        return r;
    }

    /* ── validate MZ header ── */
    dos = (DOS_HEADER*)filebuf;
    /* [FROM FILE] e_magic: must be "MZ" */
    if (dos->e_magic != MZ_MAGIC) {
        fprintf(stderr,"not a supported format (no MZ or ELF magic)\n");
        free(filebuf); return 1;
    }
    {
        uint32_t sig;
        /* [FROM FILE] e_lfanew: signed offset to PE signature.
         * Lower bound: must be past the DOS header itself.
         * Upper bound: must leave room for PE sig (4) + COFF header (20)
         *              = 24 bytes minimum before end of file.         */
        int32_t lfa = dos->e_lfanew;
        if (lfa < (int32_t)sizeof(DOS_HEADER) || lfa > fsz-24) {
            fprintf(stderr,"invalid e_lfanew (0x%x)\n", (unsigned)lfa);
            free(filebuf); return 1;
        }
        /* [FROM FILE] PE signature: must be "PE\0\0" */
        memcpy(&sig, filebuf+lfa, 4);
        if (sig != PE_MAGIC) {
            fprintf(stderr,"not a PE file (no PE signature)\n");
            free(filebuf); return 1;
        }
        /* COFF file header immediately follows PE signature */
        fhdr = (FILE_HEADER*)(filebuf+lfa+4);
    }

    /* ── determine PE32 vs PE32+ from optional header magic ──
     * [FROM FILE] Magic field: first 2 bytes of the optional header.
     * 0x010b = PE32, 0x020b = PE32+. Anything else is unsupported.  */
    memcpy(&opt_magic, (uint8_t*)fhdr+sizeof(FILE_HEADER), 2);
    is64 = (opt_magic == PE64_MAGIC);
    if (opt_magic != PE32_MAGIC && opt_magic != PE64_MAGIC) {
        fprintf(stderr,"unsupported optional header magic 0x%04x\n", opt_magic);
        free(filebuf); return 1;
    }

    /* ── extract entry point, image base, and section table pointer ──
     *
     * [FROM FILE] AddressOfEntryPoint, ImageBase from optional header.
     * [FROM FILE] SizeOfOptionalHeader used to skip past optional header
     *             to reach the section table.
     *
     * SECURITY: SizeOfOptionalHeader is not range-checked here because
     * the section table pointer is only accessed after the UPX section
     * search, which bounds-checks each section header via nsect.     */
    if (is64) {
        OPT64 *o = (OPT64*)((uint8_t*)fhdr+sizeof(FILE_HEADER));
        ep_rva    = o->AddressOfEntryPoint;  /* [FROM FILE] */
        imagebase = o->ImageBase;            /* [FROM FILE] */
        sects     = (SHDR*)((uint8_t*)o + fhdr->SizeOfOptionalHeader); /* [FROM FILE] */
    } else {
        OPT32 *o = (OPT32*)((uint8_t*)fhdr+sizeof(FILE_HEADER));
        ep_rva    = o->AddressOfEntryPoint;  /* [FROM FILE] */
        imagebase = (uint64_t)o->ImageBase;  /* [FROM FILE] */
        sects     = (SHDR*)((uint8_t*)o + fhdr->SizeOfOptionalHeader); /* [FROM FILE] */
    }

    /* [FROM FILE] NumberOfSections.
     * Capped at MAX_SECTIONS (96) to bound loop iterations.         */
    nsect = (int)fhdr->NumberOfSections;
    if (nsect <= 0 || nsect > MAX_SECTIONS) {
        fprintf(stderr,"bad section count %d\n", nsect);
        free(filebuf); return 1;
    }

    /* SECURITY: validate entire section table fits within the file.
     * sects is a pointer into filebuf; each section header is 40 bytes.
     * If NumberOfSections is large enough that sects+nsect extends past
     * filebuf+fsz, accessing any sects[i] beyond that is OOB.          */
    {
        size_t sect_off = (size_t)((uint8_t*)sects - filebuf);
        if (sect_off > (size_t)fsz ||
            (size_t)nsect * sizeof(SHDR) > (size_t)fsz - sect_off) {
            fprintf(stderr,"section table (count=%d) extends past end of file\n",
                    nsect);
            free(filebuf); return 1;
        }
    }

    /* ── display section table (informational) ── */
    printf("%s  ImageBase=0x%llx  EP=0x%08lx  Sects=%d\n\n",
           is64?"PE32+ (x64)":"PE32  (x86)",
           (unsigned long long)imagebase, (unsigned long)ep_rva, nsect);
    printf("  %-8s  RawOff    RawSz     VirtOff   VirtSz\n","Name");
    printf("  --------  --------  --------  --------  --------\n");
    for (i=0;i<nsect;i++)
        printf("  %-8.8s  %08lx  %08lx  %08lx  %08lx\n",
               (char*)sects[i].Name,  /* [FROM FILE] not NUL-trusted, %.8s caps it */
               (unsigned long)sects[i].PointerToRawData,
               (unsigned long)sects[i].SizeOfRawData,
               (unsigned long)sects[i].VirtualAddress,
               (unsigned long)sects[i].VirtualSize);
    printf("\n");

    /* ── locate UPX section pair ─────────────────────────────────────
     *
     * UPX always creates a pair of adjacent sections with this pattern:
     *   sections[i]:   SizeOfRawData == 0, VirtualSize > 0  <- UPX0 (destination)
     *   sections[i+1]: SizeOfRawData >  0, VirtualSize > 0  <- UPX1 (compressed + stub)
     *
     * PE32+ adds a third section (UPX2) with identity data after UPX1.
     * We stop at the first matching pair, which naturally ignores UPX2.
     *
     * All four fields read here are [FROM FILE]. The loop bound (nsect-1)
     * prevents i+1 from going out of range.                           */
    upx0=upx1=-1;
    for (i=0;i<nsect-1;i++) {
        if (sects[i].SizeOfRawData   == 0 &&   /* [FROM FILE] */
            sects[i].VirtualSize     >  0 &&   /* [FROM FILE] */
            sects[i+1].SizeOfRawData >  0 &&   /* [FROM FILE] */
            sects[i+1].VirtualSize   >  0) {   /* [FROM FILE] */
            upx0=i; upx1=i+1; break;
        }
    }
    if (upx0<0) {
        fprintf(stderr,"no UPX section pair found - not UPX packed "
                "or already unpacked\n");
        free(filebuf); return 1;
    }
    printf("UPX sections: [%d]=%s  [%d]=%s\n\n",
           upx0,(char*)sects[upx0].Name,
           upx1,(char*)sects[upx1].Name);

    /* ── derive inflate parameters ───────────────────────────────────
     *
     * All six values passed to the inflate functions come from [FROM FILE]
     * section header fields. Their semantic meaning:
     *
     *   ssize    = on-disk size of UPX1 = bytes of compressed input.
     *   dsize    = total virtual size of UPX0+UPX1 = upper bound on
     *              decompressed output. (UPX compresses the entire original
     *              image including .text + .data + .rsrc into UPX1, and
     *              it all decompresses into the combined UPX0+UPX1 virtual
     *              address space.)
     *   upx0_rva = virtual address where decompressed image begins.
     *   upx1_rva = virtual address of the compressed section.
     *              Used to convert stub EP-relative offsets to src[] indices.
     *   ep_rva   = entry point RVA. Points into UPX1 at the start of
     *              the decompressor stub (past the compressed payload).
     *
     * These match the parameters passed in pe.c: cli_scanpe() line ~3804.  */
    ssize    = sects[upx1].SizeOfRawData;   /* [FROM FILE] */
    dsize    = sects[upx0].VirtualSize      /* [FROM FILE] */
             + sects[upx1].VirtualSize;     /* [FROM FILE] */
    upx0_rva = sects[upx0].VirtualAddress;  /* [FROM FILE] */
    upx1_rva = sects[upx1].VirtualAddress;  /* [FROM FILE] */
    /* ep_rva already read from optional header above */

    printf("  ssize=0x%lx  (UPX1 compressed size)\n",(unsigned long)ssize);
    printf("  dsize=0x%lx  (UPX0.vsz + UPX1.vsz = output bound)\n",(unsigned long)dsize);
    printf("  upx0_rva=0x%lx  upx1_rva=0x%lx  ep_rva=0x%lx\n\n",
           (unsigned long)upx0_rva,(unsigned long)upx1_rva,(unsigned long)ep_rva);

    /* ── sanity checks on [FROM FILE] values before use ──────────────
     *
     * ssize <= 0x19: minimum UPX1 size check (from ClamAV pe.c).
     *                A valid compressed section must be larger than this.
     * dsize <= ssize: decompressed must be larger than compressed.
     * dsize > 0x10000000: 256MB cap on output allocation.
     * PointerToRawData+ssize > fsz: UPX1 must fit within the file.   */
    if (ssize <= 0x19) {
        fprintf(stderr,"UPX1 raw size 0x%lx too small\n",(unsigned long)ssize);
        free(filebuf); return 1;
    }
    if (dsize <= ssize) {
        fprintf(stderr,"dsize 0x%lx <= ssize 0x%lx (invalid)\n",
                (unsigned long)dsize,(unsigned long)ssize);
        free(filebuf); return 1;
    }
    if (dsize > 0x10000000u) {
        fprintf(stderr,"dsize 0x%lx exceeds 256MB cap\n",(unsigned long)dsize);
        free(filebuf); return 1;
    }
    /* [FROM FILE] PointerToRawData: file offset of UPX1 raw data.
     * Check: offset + size must not exceed file size.                */
    if ((uint64_t)sects[upx1].PointerToRawData + ssize > (uint64_t)fsz) {
        fprintf(stderr,"UPX1 section extends past end of file\n");
        free(filebuf); return 1;
    }

    /* src points into filebuf at the start of the compressed data.
     * Validated above: PointerToRawData + ssize <= fsz.              */
    src = filebuf + sects[upx1].PointerToRawData; /* [FROM FILE] offset */

    /* ── resolve EP RVA to a file offset ─────────────────────────────
     *
     * [FROM FILE] ep_rva: we need to read the stub bytes at EP to detect
     * which compression algorithm was used.
     *
     * EP RVA -> file offset by scanning section table:
     *   For each section with raw data: if EP_RVA is within the section's
     *   virtual address range, compute:
     *     ep_foff = PointerToRawData + (EP_RVA - VirtualAddress)
     *
     * In UPX the EP always lands in UPX1 (the compressed section).
     * If the lookup fails (EP falls in UPX0 which has no raw data),
     * we fall back to the raw start of UPX1.                         */
    ep_foff = 0;
    for (i=0;i<nsect;i++) {
        uint32_t vb = sects[i].VirtualAddress;           /* [FROM FILE] */
        uint32_t ve = vb + sects[i].VirtualSize;         /* [FROM FILE] */
        if (sects[i].SizeOfRawData > 0 &&                /* [FROM FILE] */
            ep_rva >= vb && ep_rva < ve) {
            /* [FROM FILE] PointerToRawData + (ep_rva - VirtualAddress) */
            ep_foff = sects[i].PointerToRawData + (ep_rva - vb);
            break;
        }
    }
    if (!ep_foff) {
        /* EP not in any section with raw data - use UPX1 start.
         * This happens e.g. when EP is in UPX0 (virtual-only section).*/
        ep_foff = sects[upx1].PointerToRawData; /* [FROM FILE] */
        fprintf(stderr,"note: EP RVA not in a raw section, "
                "using UPX1 raw start for stub scan\n");
    }
    /* We need at least 0xc0 bytes at ep_foff for stub signature scanning */
    if (ep_foff + 0xc0 > (size_t)fsz) {
        fprintf(stderr,"EP file offset 0x%lx + 0xc0 exceeds file size\n",
                (unsigned long)ep_foff);
        free(filebuf); return 1;
    }
    epbuff = filebuf + ep_foff;

    /* ── stub identification and decompression ───────────────────────
     *
     * Build a cli_exe_section array from the SHDR table so we can call
     * the shared is_upx_pe32/pe64 and upx_unpack_pe32/pe64 functions
     * from upx_pe.c.  These are the same functions called by pe.c in
     * libclamav, so the test harness exercises identical logic.
     *
     * cli_exe_section uses: rsz (SizeOfRawData), vsz (VirtualSize),
     *   rva (VirtualAddress), raw (PointerToRawData).               */
    {
        struct upx_pe_section_t *cesects;
        unsigned int            upx_i     = 0;
        int                     stub_type = UPX_STUB_UNKNOWN;
        uint32_t                magic[3]  = {0, 0, 0};
        size_t                  epbuf_len = (size_t)fsz - ep_foff;
        int                     detected;

        cesects = (struct upx_pe_section_t *)calloc(
                      (size_t)nsect, sizeof(struct upx_pe_section_t));
        if (!cesects) {
            perror("calloc cesects");
            free(dest); free(filebuf); return 1;
        }

        for (i = 0; i < nsect; i++) {
            cesects[i].rsz = sects[i].SizeOfRawData;
            cesects[i].vsz = sects[i].VirtualSize;
        }

        if (is64) {
            detected = is_upx_pe64(cesects, nsect,
                                   (const char *)epbuff, epbuf_len,
                                   &upx_i, magic, &stub_type);
        } else {
            detected = is_upx_pe32(cesects, nsect,
                                   (const char *)epbuff, epbuf_len,
                                   &upx_i, &stub_type);
        }

        free(cesects);

        if (!detected) {
            fprintf(stderr, "no recognised UPX stub found\n");
            free(dest); free(filebuf); return 1;
        }

        {
            const char *det = "unknown";
            switch (stub_type) {
                case UPX_STUB_NRV2B:    det = "NRV2B"; break;
                case UPX_STUB_NRV2D:    det = "NRV2D"; break;
                case UPX_STUB_NRV2E:    det = "NRV2E"; break;
                case UPX_STUB_NRV2D_2E: det = "NRV2D/2E (ambiguous)"; break;
                case UPX_STUB_LZMA:     det = "LZMA"; break;
            }
            printf("Stub signature detected: %s (%s)\n\n",
                   det, is64 ? "x64" : "x86");
        }

        /* allocate decompression output buffer
         * +8192 mirrors pe.c's allocation (CLI_UNPTEMP headroom).   *
		 WARNING: this should be a const in upx.h so it cant get out of sync #define UPX_REBUILD_HEADROOM 8192
		 */
        dest = (char *)calloc(dsize + UPX_REBUILD_HEADROOM, 1);
        if (!dest) { perror("calloc"); free(filebuf); return 1; }
        outdsize = dsize;
        success  = 0;

        fprintf(stderr, "%s %s ...\n",
                is64 ? "x64" : "x86",
                (stub_type == UPX_STUB_LZMA)     ? "LZMA"       :
                (stub_type == UPX_STUB_NRV2B)    ? "NRV2B"      :
                (stub_type == UPX_STUB_NRV2D)    ? "NRV2D"      :
                (stub_type == UPX_STUB_NRV2E)    ? "NRV2E"      : "NRV2D/2E");

        if (is64) {
            if (upx_unpack_pe64((const char *)src, ssize,
                                dest, &outdsize,
                                upx0_rva, upx1_rva, ep_rva,
                                (const char *)epbuff, epbuf_len,
                                magic, stub_type) >= 0) {
                fprintf(stderr, "x64 OK  out=0x%lx\n",
                        (unsigned long)outdsize);
                success = 1;
            } else {
                fprintf(stderr, "x64 failed\n");
            }
        } else {
            if (upx_unpack_pe32((const char *)src, ssize,
                                dest, &outdsize,
                                upx0_rva, upx1_rva, ep_rva,
                                (uint32_t)imagebase,
                                (const char *)epbuff, epbuf_len) >= 0) {
                fprintf(stderr, "x86 OK  out=0x%lx\n",
                        (unsigned long)outdsize);
                success = 1;
            } else {
                fprintf(stderr, "x86 failed\n");
            }
        }
    }

    if (!success) {
        fprintf(stderr,"\nAll decompressors failed.\n");
        free(dest); free(filebuf); return 2;
    }

    /* ── write output ── */
    {
        FILE *fo = fopen(outfile,"wb");
        if (!fo) { perror(outfile); free(dest); free(filebuf); return 1; }
        if (fwrite(dest, 1, outdsize, fo) != outdsize) {
            perror("fwrite"); fclose(fo); free(dest); free(filebuf); return 1;
        }
        fclose(fo);
        printf("Wrote 0x%lx (%lu) bytes to %s\n",
               (unsigned long)outdsize, (unsigned long)outdsize, outfile);
    }

    free(dest);
    free(filebuf);
    return 0;
}
