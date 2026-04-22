/* Types.h - minimal Igor Pavlov 7z SDK types for standalone lzma_iface build
 * Based on public domain 7z SDK. No ClamAV or zlib dependencies. */

#ifndef __7Z_TYPES_H
#define __7Z_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef unsigned char  Byte;
typedef uint16_t       UInt16;
typedef uint32_t       UInt32;
typedef uint64_t       UInt64;
typedef int32_t        Int32;
typedef int64_t        Int64;
typedef size_t         SizeT;
typedef int            SRes;
typedef int            Bool;

#define SZ_OK              0
#define SZ_ERROR_DATA      1
#define SZ_ERROR_MEM       2
#define SZ_ERROR_UNSUPPORTED 4
#define SZ_ERROR_INPUT_EOF 6

#define True  1
#define False 0

typedef struct {
    void *(*Alloc)(void *p, size_t size);
    void  (*Free)(void *p, void *address);
} ISzAlloc;

#define IAlloc_Alloc(p, size) (p)->Alloc((p), (size))
#define IAlloc_Free(p, a)     (p)->Free((p), (a))


/* Calling convention and error-check macros from 7z SDK */
#ifndef MY_FAST_CALL
  #ifdef _MSC_VER
    #define MY_FAST_CALL __fastcall
  #else
    #define MY_FAST_CALL
  #endif
#endif

#ifndef RINOK
  #define RINOK(x) { int __res = (x); if (__res != 0) return __res; }
#endif

#endif /* __7Z_TYPES_H */
