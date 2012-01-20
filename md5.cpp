#include <stdio.h>
#include "hspcksum.h"
#include "sha1.h"
#include "md5.h"

extern char hashbuf[256];

char* md5calc(unsigned char *inbuf, size_t bufsize)
{
	const unsigned int r[64] =
	{
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	};
	const unsigned int k[64] =
	{
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};

	/* Initialize */
	unsigned int h[8] = {0x67452301,0, 0xefcdab89,0, 0x98badcfe,0, 0x10325476,0};

	/* Padding */
	unsigned char *workbuf = (unsigned char *)malloc(bufsize + 128);
	size_t work_size = padding(workbuf, inbuf, bufsize, false);

	unsigned int wh[8] = {0,0,0,0,0,0,0,0};
	int pos, i; unsigned int ChunkDat[16];
	unsigned int f, g, t;

	/* Processing */
	for (pos = 0; (size_t)pos < work_size; pos += 64) {
		/* Break chunk into 16x little-endian int32 */
		for (i = 0; i < 16; i++)
			ChunkDat[i] = (workbuf[pos + i*4]) | (workbuf[pos + i*4 +1] << 8)
				| (workbuf[pos + i*4 +2] << 16) | (workbuf[pos + i*4 +3] << 24);

		/* Initialize Hash */
		for (i = 0; i < 8; i+=2) wh[i] = h[i];
		for (i = 1; i < 8; i+=2) wh[i] = 0; /* Overflown bytes */

		/* Main loop */
		for (i = 0; i < 64; i++) {
			if ((i >= 0)&&(i <= 15)) {
				f = (wh[2] & wh[4]) | ((~wh[2]) & wh[6]);
				g = i;
			} else if ((i >= 16)&&(i <= 31)) {
				f = (wh[6] & wh[2]) | ((~wh[6]) & wh[4]);
				g = (5 * i + 1) % 16;
			} else if ((i >= 32)&&(i <= 47)) {
				f = wh[2] ^ wh[4] ^ wh[6];
				g = (3 * i + 5) % 16;
			} else {
				f = wh[4] ^ (wh[2] | (~wh[6]));
				g = (7 * i) % 16;
			}

			t = wh[6];
			wh[6] = wh[4];
			wh[4] = wh[2];
			wh[2] += leftrotate(wh[0] + f + k[i] + ChunkDat[g], r[i]);
			wh[0] = t;
		}

		/* Add hash */
		for (i = 0; i < 8; i+=2) h[i] += wh[i];
		for (i = 1; i < 8; i+=2) h[i] = 0; /* Overflown bytes */
	}

	/* answer */
	sprintf_s(hashbuf, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		h[0]&0xff, (h[0]>>8)&0xff, (h[0]>>16)&0xff, (h[0]>>24)&0xff, 
		h[2]&0xff, (h[2]>>8)&0xff, (h[2]>>16)&0xff, (h[2]>>24)&0xff, 
		h[4]&0xff, (h[4]>>8)&0xff, (h[4]>>16)&0xff, (h[4]>>24)&0xff, 
		h[6]&0xff, (h[6]>>8)&0xff, (h[6]>>16)&0xff, (h[6]>>24)&0xff);
	return hashbuf;
}
