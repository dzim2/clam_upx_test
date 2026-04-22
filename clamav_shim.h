/*
 * clamav_shim.h
 * Minimal stubs replacing the ClamAV framework headers for standalone
 * compilation of upx.c outside the ClamAV build system.
 *
 * Compatible with: GCC, Clang, MSVC 2019/2022
 *
 * Include this instead of clamav.h / others.h / str.h / lzma_iface.h
 */

#ifndef CLAMAV_SHIM_H
#define CLAMAV_SHIM_H

/* ── MSVC compatibility ──────────────────────────────────────────── */
#ifdef _MSC_VER

  /* stdint.h available since VS 2010 */
  #include <stdint.h>

  /* MSVC doesn't have ssize_t */
  #include <basetsd.h>
  typedef SSIZE_T ssize_t;

  /* 'inline' in C mode requires __inline pre-VS2015 */
  #ifndef __cplusplus
    #define inline __inline
  #endif

  /* Suppress warnings common in upx.c integer arithmetic:
   *   4244 - int/uint conversion, possible loss of data
   *   4146 - unary minus applied to unsigned (intentional)
   *   4996 - deprecated CRT functions                      */
  #pragma warning(disable: 4244 4146 4996)

  /* MSVC does not support GCC __attribute__ */
  #define __attribute__(x)

  /* snprintf fixed in VS2015 (_MSC_VER 1900) */
  #if _MSC_VER < 1900
    #define snprintf _snprintf
  #endif

#else
  #include <stdint.h>
#endif  /* _MSC_VER */

/* ── Common includes ─────────────────────────────────────────────── */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>

/* ── Exact-width types (belt-and-suspenders for ancient SDKs) ───────
 * C99 stdint.h should cover this, but define manually if missing.   */
#ifndef UINT32_MAX
  typedef unsigned char      uint8_t;
  typedef unsigned short     uint16_t;
  typedef unsigned int       uint32_t;
  typedef unsigned long long uint64_t;
  typedef signed int         int32_t;
  typedef signed long long   int64_t;
  #define UINT32_MAX   0xFFFFFFFFu
  #define INT32_MAX    0x7FFFFFFF
#endif

/* ── CLI_ISCONTAINED ─────────────────────────────────────────────── */
/*
 * Two variants are needed:
 *
 * CLI_ISCONTAINED_PTR  - the normal case: buf/ptr are char* pointers.
 *
 * CLI_ISCONTAINED_INT  - used in pefromupx() where buf/ptr are
 *   uint32_t RVA values, not pointers.  Casting integers to pointers
 *   is a 64-bit MSVC error (C4312/C2440), so we use pure arithmetic.
 */
#define CLI_ISCONTAINED_PTR(buf, buflen, ptr, len)              \
    ( (size_t)(len) > 0 &&                                      \
      (const char *)(ptr) >= (const char *)(buf) &&             \
      (size_t)((const char *)(ptr) - (const char *)(buf))       \
          + (size_t)(len) <= (size_t)(buflen) )

#define CLI_ISCONTAINED_INT(buf, buflen, ptr, len)              \
    ( (uint32_t)(len) > 0 &&                                    \
      (uint32_t)(ptr) >= (uint32_t)(buf) &&                     \
      (uint64_t)((uint32_t)(ptr) - (uint32_t)(buf))             \
          + (uint64_t)(uint32_t)(len)                           \
          <= (uint64_t)(uint32_t)(buflen) )

/* Default: pointer-based, used at all normal call sites */
#define CLI_ISCONTAINED CLI_ISCONTAINED_PTR

/* ── CLI_SAR: signed arithmetic right shift ──────────────────────── */
/*
 * C doesn't guarantee arithmetic shift of signed integers (UB pre-C23).
 * MSVC warns on right-shift of negative signed values (/W4).
 * This formulation is defined behaviour on all platforms.
 */
#define CLI_SAR(val, shift)                                             \
    ((val) = ((val) < 0)                                                \
        ? (int32_t)(~((uint32_t)(~(uint32_t)(val)) >> (unsigned)(shift)))\
        : (int32_t)((uint32_t)(val) >> (unsigned)(shift)))

/* ── Debug messaging ─────────────────────────────────────────────── */
static inline void cli_dbgmsg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/* ── Memory ──────────────────────────────────────────────────────── */
static inline void *cli_max_calloc(size_t nmemb, size_t size)
{
    /* CLI_MAX_ALLOCATION: 2GB cap - mirrors ClamAV's limit */
    const size_t CLI_MAX_ALLOCATION = (size_t)2 * 1024 * 1024 * 1024;
    size_t total;
    if (!nmemb || !size) return NULL;
    /* overflow check on nmemb * size */
    if (nmemb > CLI_MAX_ALLOCATION / size) return NULL;
    total = nmemb * size;
    if (total > CLI_MAX_ALLOCATION) return NULL;
    return calloc(nmemb, size);
}

/* ── Integer I/O (little-endian, unaligned-safe) ─────────────────── */
/*
 * memcpy-based read/write avoids strict-aliasing UB and x86 alignment
 * faults.  MSVC /O2 and GCC -O2 both collapse these to a single MOV.
 * upx.c targets x86/LE so no byte-swap needed.
 */
static inline uint32_t cli_readint32(const void *v)
{
    uint32_t x;
    memcpy(&x, v, 4);
    return x;
}

static inline void cli_writeint32(void *v, uint32_t x)
{
    memcpy(v, &x, 4);
}

/* ── cli_memstr ──────────────────────────────────────────────────── */
/*
 * Find needle (ndl/nlen) in haystack (hay/hlen).
 * Returns pointer to first match, or NULL.
 * Uses C-style for loop for MSVC C89 compat (/TC mode).
 */
static inline const char *cli_memstr(const char *hay, size_t hlen,
                                     const char *ndl, size_t nlen)
{
    const char *p, *end;
    if (!nlen || nlen > hlen) return NULL;
    end = hay + hlen - nlen;
    for (p = hay; p <= end; p++)
        if (memcmp(p, ndl, nlen) == 0) return p;
    return NULL;
}

/* ── CLI_MAX_ALLOCATION ──────────────────────────────────────────── */
/* Maximum allocation size - mirrors ClamAV's limit (2GB)            */
#ifndef CLI_MAX_ALLOCATION
#define CLI_MAX_ALLOCATION (2147483648UL)  /* 2 GB */
#endif

/* ── LZMA: provided by lzma_iface.c + LzmaDec.c ─────────────────── */
/* Include lzma_iface.h here when building with LZMA support.
 * upx_standalone.c includes it automatically when upx_inflatelzma
 * is called. No stub needed - the real implementation is linked.    */

#endif /* CLAMAV_SHIM_H */
