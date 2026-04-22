/*
 * lzma_iface.h - standalone version for clam_upx build
 * Stripped of ClamAV framework dependencies.
 */

#ifndef __LZMA_IFACE_H
#define __LZMA_IFACE_H

#include "LzmaDec.h"
#include <stdint.h>

struct CLI_LZMA {
    CLzmaDec      state;
    unsigned char header[LZMA_PROPS_SIZE];
    unsigned int  p_cnt;
    unsigned int  s_cnt;
    unsigned int  freeme;
    unsigned int  init;
    uint64_t      usize;
    unsigned char *next_in;
    unsigned char *next_out;
    SizeT          avail_in;
    SizeT          avail_out;
};

int  cli_LzmaInit(struct CLI_LZMA *, uint64_t);
void cli_LzmaShutdown(struct CLI_LZMA *);
int  cli_LzmaDecode(struct CLI_LZMA *);

#define LZMA_STREAM_END      2
#define LZMA_RESULT_OK       0
#define LZMA_RESULT_DATA_ERROR 1

#endif /* __LZMA_IFACE_H */
