#pragma once

#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))
#define ALIGN(x,a)              __ALIGN_MASK(x,(__typeof__(x))(a)-1)

int WriteFile(const char *file, void *buf, int size);
s32 gunzip(u8 *inBuf, u32 inSize, u8 *outBuf, u32 outSize, u32 *realInSize = NULL, bool noHeader = false);

