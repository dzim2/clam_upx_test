/*
 * lzma_iface.c - standalone version for clam_upx build
 *
 * Original: ClamAV libclamav/lzma_iface.c (GPL v2, Cisco/Sourcefire)
 * Authors:  aCaB
 * Modified: stripped of ClamAV framework dependencies for standalone use.
 *
 * Uses Igor Pavlov's public domain LzmaDec.c/h directly.
 */

#include "clamav_shim.h"    /* cli_max_calloc, CLI_MAX_ALLOCATION   */
#include "lzma_iface.h"     /* struct CLI_LZMA, return codes        */
#include <stdlib.h>         /* free()                               */

/* ── Igor Pavlov allocator callbacks ─────────────────────────────── */
void *__lzma_wrap_alloc(void *unused, size_t size)
{
    (void)unused;
    if (!size || size > CLI_MAX_ALLOCATION)
        return NULL;
    return cli_max_calloc(1, size);
}

void __lzma_wrap_free(void *unused, void *freeme)
{
    (void)unused;
    free(freeme);
}

static ISzAlloc g_Alloc = { __lzma_wrap_alloc, __lzma_wrap_free };

/* ── Internal: consume one byte from the input stream ────────────── */
static unsigned char lzma_getbyte(struct CLI_LZMA *L, int *fail)
{
    unsigned char c;
    if (!L->next_in || !L->avail_in) {
        *fail = 1;
        return 0;
    }
    *fail    = 0;
    c        = L->next_in[0];
    L->next_in++;
    L->avail_in--;
    return c;
}

/* ── cli_LzmaInit ─────────────────────────────────────────────────── */
int cli_LzmaInit(struct CLI_LZMA *L, uint64_t size_override)
{
    int fail;

    if (!L->init) {
        L->p_cnt = LZMA_PROPS_SIZE;
        if (size_override) {
            L->s_cnt = 0;
            L->usize = size_override;
        } else {
            L->s_cnt = 8;
            L->usize = 0;
        }
        L->init = 1;
    }
    /* (silently ignore late size_override - no cli_warnmsg needed) */

    if (L->freeme) return LZMA_RESULT_OK;

    /* Read LZMA properties header (5 bytes) */
    while (L->p_cnt) {
        L->header[LZMA_PROPS_SIZE - L->p_cnt] = lzma_getbyte(L, &fail);
        if (fail) return LZMA_RESULT_OK;
        L->p_cnt--;
    }

    /* Read uncompressed size (8 bytes, little-endian) if not overridden */
    while (L->s_cnt) {
        uint64_t c = (uint64_t)lzma_getbyte(L, &fail);
        if (fail) return LZMA_RESULT_OK;
        L->usize |= c << (8 * (8 - L->s_cnt));
        L->s_cnt--;
    }

    LzmaDec_Construct(&L->state);
    if (LzmaDec_Allocate(&L->state, L->header, LZMA_PROPS_SIZE,
                         &g_Alloc) != SZ_OK)
        return LZMA_RESULT_DATA_ERROR;
    LzmaDec_Init(&L->state);

    L->freeme = 1;
    return LZMA_RESULT_OK;
}

/* ── cli_LzmaShutdown ─────────────────────────────────────────────── */
void cli_LzmaShutdown(struct CLI_LZMA *L)
{
    if (L->freeme)
        LzmaDec_Free(&L->state, &g_Alloc);
}

/* ── cli_LzmaDecode ───────────────────────────────────────────────── */
int cli_LzmaDecode(struct CLI_LZMA *L)
{
    SRes            res;
    SizeT           outbytes, inbytes;
    ELzmaStatus     status;
    ELzmaFinishMode finish;

    if (!L->freeme) return cli_LzmaInit(L, 0);

    inbytes = L->avail_in;
    if (~L->usize && L->avail_out > L->usize) {
        outbytes = (SizeT)L->usize;
        finish   = LZMA_FINISH_END;
    } else {
        outbytes = L->avail_out;
        finish   = LZMA_FINISH_ANY;
    }

    res = LzmaDec_DecodeToBuf(&L->state,
                              L->next_out, &outbytes,
                              L->next_in,  &inbytes,
                              finish, &status);

    L->avail_in  -= inbytes;
    L->next_in   += inbytes;
    L->avail_out -= outbytes;
    L->next_out  += outbytes;
    if (~L->usize) L->usize -= outbytes;

    if (res != SZ_OK)
        return LZMA_RESULT_DATA_ERROR;
    if (!L->usize || status == LZMA_STATUS_FINISHED_WITH_MARK)
        return LZMA_STREAM_END;
    return LZMA_RESULT_OK;
}
