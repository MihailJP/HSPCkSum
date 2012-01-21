#include <stdlib.h>
#include <stdio.h>
#include "sha1.h"
#include "sha256.h"
#include "hspcksum.h"

extern char hashbuf[HASHBUF_LENGTH];

void sha256_224_calc(unsigned char *inbuf, size_t bufsize, unsigned int* h)
{
	/* Initialize */
	const unsigned int k[64] =
	{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	/* Padding */
	unsigned char *workbuf = (unsigned char *)malloc(bufsize + 128);
	size_t work_size = padding(workbuf, inbuf, bufsize, true);

	unsigned int pos; unsigned int ChunkDat[80]; int i;
	unsigned int wh[16], s0, s1, maj, t2, ch, t1;


	/* Processing */
	for (pos = 0; pos < work_size; pos += 64) {
		/* Break chunk into 16x big-endian int32 */
		for (i = 0; i < 16; i++)
			ChunkDat[i] = (workbuf[pos + i*4] << 24) | (workbuf[pos + i*4 +1] << 16)
				| (workbuf[pos + i*4 +2] << 8) | (workbuf[pos + i*4 +3]);

		/* Extend into 64x int32 */
		for (i = 16; i < 64; i++) {
			s0 = rightrotate(ChunkDat[i-15], 7) ^ rightrotate(ChunkDat[i-15], 18) ^ (ChunkDat[i-15] >> 3);
			s1 = rightrotate(ChunkDat[i-2], 17) ^ rightrotate(ChunkDat[i-2], 19) ^ (ChunkDat[i-2] >> 10);
			ChunkDat[i] = ChunkDat[i-16] + s0 + ChunkDat[i-7] + s1;
		}

		/* Initialize Hash */
		for (i = 0; i < 16; i+=2) wh[i] = h[i];
		for (i = 1; i < 16; i+=2) wh[i] = 0; /* Overflown bytes */

		/* Main loop */
		for (i = 0; i < 64; i++) {
			s0 = rightrotate(wh[0], 2) ^ rightrotate(wh[0], 13) ^ rightrotate(wh[0], 22);
			maj = (wh[0] & wh[2]) ^ (wh[0] & wh[4]) ^ (wh[2] & wh[4]);
			t2 = s0 + maj;
			s1 = rightrotate(wh[8], 6) ^ rightrotate(wh[8], 11) ^ rightrotate(wh[8], 25);
			ch = (wh[8] & wh[10]) ^ ((~wh[8]) & wh[12]);
			t1 = wh[14] + s1 + ch + k[i] + ChunkDat[i];

			wh[14] = wh[12];
			wh[12] = wh[10];
			wh[10] = wh[8];
			wh[8] = wh[6] + t1;
			wh[6] = wh[4];
			wh[4] = wh[2];
			wh[2] = wh[0];
			wh[0] = t1 + t2;
		}

		/* Add hash */
		for (i = 0; i < 16; i+=2) h[i] += wh[i];
		for (i = 1; i < 16; i+=2) h[i] = 0; /* Overflown bytes */
	}
	return;
}

char* sha256calc(unsigned char *inbuf, size_t bufsize)
{
	/* Initialize */
	unsigned int h[16] = {
		0x6a09e667,0, 0xbb67ae85,0, 0x3c6ef372,0, 0xa54ff53a,0,
		0x510e527f,0, 0x9b05688c,0, 0x1f83d9ab,0, 0x5be0cd19,0
	};
	
	/* Calculate */
	sha256_224_calc(inbuf, bufsize, h);

	/* answer */
	sprintf_s(hashbuf, "%08x%08x%08x%08x%08x%08x%08x%08x",
		h[0], h[2], h[4], h[6], h[8], h[10], h[12], h[14]);
	return hashbuf;
}

char* sha224calc(unsigned char *inbuf, size_t bufsize)
{
	/* Initialize */
	unsigned int h[16] = {
		0xc1059ed8,0, 0x367cd507,0, 0x3070dd17,0, 0xf70e5939,0,
		0xffc00b31,0, 0x68581511,0, 0x64f98fa7,0, 0xbefa4fa4,0
	};
	
	/* Calculate */
	sha256_224_calc(inbuf, bufsize, h);

	/* answer */
	sprintf_s(hashbuf, "%08x%08x%08x%08x%08x%08x%08x",
		h[0], h[2], h[4], h[6], h[8], h[10], h[12]);
	return hashbuf;
}
