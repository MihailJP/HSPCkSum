#ifndef __sha512_h
#define __sha512_h

unsigned long long rightrotate64 (unsigned long long, int);
size_t padding_sha512(unsigned char *, unsigned char *, size_t);
void sha512_384_calc(unsigned char *, size_t, unsigned long long*);
char* sha512calc(unsigned char *, size_t);
char* sha384calc(unsigned char *, size_t);

#endif
