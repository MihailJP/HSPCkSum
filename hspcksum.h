#ifndef __hspcksum_h
#define __hspcksum_h

#include <Windows.h>
#include "hsp3plugin.h"

extern char hashbuf[256];

unsigned int leftrotate (unsigned int, int);
unsigned int rightrotate (unsigned int, int);
static void *reffunc(int *, int);
EXPORT void WINAPI hsp3cmdinit(HSP3TYPEINFO *);

#endif
