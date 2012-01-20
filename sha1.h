#ifndef __sha1_h
#define __sha1_h

#include "hsp3plugin.h"

size_t padding(unsigned char *, unsigned char *, size_t, bool);
char* sha1calc(unsigned char *, size_t);

#endif
