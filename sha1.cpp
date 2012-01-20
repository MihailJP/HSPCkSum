#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "hspcksum.h"
#include "sha1.h"

extern char hashbuf[256];

/* Padding */
size_t padding(unsigned char *workbuf, unsigned char *inbuf, size_t bufsize, bool endian)
{
	size_t work_size = bufsize;
	FILE *debugbuf = fopen("debug.buf", "w");

	memset(workbuf, 0, sizeof(*workbuf));
	memcpy(workbuf, inbuf, bufsize);
	workbuf[work_size] = 0x80; work_size++;
	while ((work_size % 64) != 56) {
		workbuf[work_size] = 0; work_size++;
	}
	if (endian) {
		/* Big endian */
		workbuf[work_size + 7] = (int)(bufsize<<3) & 0xff; /* Size is given in 32 bits */
		workbuf[work_size + 6] = (int)(bufsize>>5) & 0xff;
		workbuf[work_size + 5] = (int)(bufsize>>13) & 0xff;
		workbuf[work_size + 4] = (int)(bufsize>>21) & 0xff;
		workbuf[work_size + 3] = (int)(bufsize>>29) & 0xff;
		workbuf[work_size + 2] = 0;
		workbuf[work_size + 1] = 0; workbuf[work_size + 0] = 0;
	} else {
		/* Little endian */
		workbuf[work_size + 0] = (int)(bufsize<<3) & 0xff; /* Size is given in 32 bits */
		workbuf[work_size + 1] = (int)(bufsize>>5) & 0xff;
		workbuf[work_size + 2] = (int)(bufsize>>13) & 0xff;
		workbuf[work_size + 3] = (int)(bufsize>>21) & 0xff;
		workbuf[work_size + 4] = (int)(bufsize>>29) & 0xff;
		workbuf[work_size + 5] = 0;
		workbuf[work_size + 6] = 0; workbuf[work_size + 7] = 0;
	}
	work_size += 8;

	fwrite(workbuf, 1, work_size, debugbuf);
	fclose(debugbuf);

	return work_size;
}

/* SHA1 ハッシュ計算 */
char* sha1calc(unsigned char *inbuf, size_t bufsize)
{
	/* Initialize */
	unsigned int hash[10] = {0x67452301, 0, 0xefcdab89, 0, 0x98badcfe, 0, 0x10325476, 0, 0xc3d2e1f0, 0}; /*オーバーフロー対策のため1ワード置きに使用*/
	unsigned char *workbuf = (unsigned char *)malloc(bufsize + 128);
	size_t work_size = padding(workbuf, inbuf, bufsize, true);
	unsigned int pos; unsigned int ChunkDat[80]; int i;
	unsigned int whash[10], f, k, t;

	/* Processing */
	for (pos = 0; pos < work_size; pos += 64) {
		/* Break chunk into 16x big-endian int32 */
		for (i = 0; i < 16; i++)
			ChunkDat[i] = (workbuf[pos + i*4] << 24) | (workbuf[pos + i*4 +1] << 16)
				| (workbuf[pos + i*4 +2] << 8) | (workbuf[pos + i*4 +3]);

		/* Extend into 80x int32 */
		for (i = 16; i < 80; i++)
			ChunkDat[i] = leftrotate(ChunkDat[i-3] ^ ChunkDat[i-8] ^ ChunkDat[i-14] ^ ChunkDat[i-16], 1);

		/* Initialize Hash */
		for (i = 0; i < 10; i+=2) whash[i] = hash[i];
		for (i = 1; i < 10; i+=2) whash[i] = 0; /* Overflown bytes */

		/* Main loop */
		for (i = 0; i < 80; i++) {
			if ((i >= 0)&&(i <= 19)) {
				f = (whash[2] & whash[4]) | ((~whash[2]) & whash[6]);
				k = 0x5a827999;
			} else if ((i >= 20)&&(i <= 39)) {
				f = whash[2] ^ whash[4] ^ whash[6];
				k = 0x6ed9eba1;
			} else if ((i >= 40)&&(i <= 59)) {
				f = (whash[2] & whash[4]) | (whash[2] & whash[6]) | (whash[4] & whash[6]);
				k = 0x8f1bbcdc;
			} else {
				f = whash[2] ^ whash[4] ^ whash[6];
				k = 0xca62c1d6;
			}

			t = leftrotate(whash[0], 5) + f + whash[8] + k + ChunkDat[i];
			whash[8] = whash[6];
			whash[6] = whash[4];
			whash[4] = leftrotate(whash[2], 30);
			whash[2] = whash[0];
			whash[0] = t;
		}

		/* Add hash */
		for (i = 0; i < 10; i+=2) hash[i] += whash[i];
		for (i = 1; i < 10; i+=2) hash[i] = 0; /* Overflown bytes */
	}

	/* answer */
	sprintf_s(hashbuf, "%08x%08x%08x%08x%08x", hash[0], hash[2], hash[4], hash[6], hash[8]);
	return hashbuf;
}
