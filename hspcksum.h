#ifndef __hspcksum_h
#define __hspcksum_h

#include <Windows.h>
#include "hsp3plugin.h"

#define HASHBUF_LENGTH 256
extern char hashbuf[HASHBUF_LENGTH];

unsigned int leftrotate (unsigned int, int);
unsigned int rightrotate (unsigned int, int);
static void *reffunc(int *, int);
EXPORT void WINAPI hsp3cmdinit(HSP3TYPEINFO *);

#endif
