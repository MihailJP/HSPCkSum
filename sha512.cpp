#include <stdlib.h>
#include <stdio.h>
#include "sha1.h"
#include "sha512.h"
#include "hspcksum.h"

extern char hashbuf[HASHBUF_LENGTH];

unsigned long long rightrotate64 (unsigned long long val, int digits)
{
	return (val >> digits) | (val << (8 * sizeof(unsigned long long) - digits));
}

/* Padding */
size_t padding_sha512(unsigned char *workbuf, unsigned char *inbuf, size_t bufsize)
{
	size_t work_size = bufsize;
	int i;

	memset(workbuf, 0, sizeof(*workbuf));
	memcpy(workbuf, inbuf, bufsize);
	workbuf[work_size] = 0x80; work_size++;
	while ((work_size % 128) != 112) {
		workbuf[work_size] = 0; work_size++;
	}
	/* Big endian */
	workbuf[work_size + 15] = (int)(bufsize<<3) & 0xff; /* Size is given in 32 bits */
	workbuf[work_size + 14] = (int)(bufsize>>5) & 0xff;
	workbuf[work_size + 13] = (int)(bufsize>>13) & 0xff;
	workbuf[work_size + 12] = (int)(bufsize>>21) & 0xff;
	workbuf[work_size + 11] = (int)(bufsize>>29) & 0xff;
	for (i=10; i>=0; i--) workbuf[work_size + i] = 0;
	work_size += 16;

	return work_size;
}

void sha512_384_calc(unsigned char *inbuf, size_t bufsize, unsigned long long* h)
{
	/* Initialize */
	const unsigned long long k[80] =
	{
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	};

	/* Padding */
	unsigned char *workbuf = (unsigned char *)malloc(bufsize + 128);
	size_t work_size = padding_sha512(workbuf, inbuf, bufsize);

	unsigned int pos; unsigned long long ChunkDat[81]; int i;
	unsigned long long wh[16], s0, s1, maj, t2, ch, t1;


	/* Processing */
	for (pos = 0; pos < work_size; pos += 128) {
		/* Break chunk into 16x big-endian int64 */
		for (i = 0; i < 16; i++)
			ChunkDat[i] = ((unsigned long long)workbuf[pos + i*8] << 56) | ((unsigned long long)workbuf[pos + i*8 +1] << 48)
				| ((unsigned long long)workbuf[pos + i*8 +2] << 40) | ((unsigned long long)workbuf[pos + i*8 +3] << 32)
				| ((unsigned long long)workbuf[pos + i*8 +4] << 24) | ((unsigned long long)workbuf[pos + i*8 +5] << 16)
				| ((unsigned long long)workbuf[pos + i*8 +6] << 8) | ((unsigned long long)workbuf[pos + i*8 +7]);

		/* Extend into 80x int64 */
		for (i = 16; i < 80; i++) {
			s0 = rightrotate64(ChunkDat[i-15], 1) ^ rightrotate64(ChunkDat[i-15], 8) ^ (ChunkDat[i-15] >> 7);
			s1 = rightrotate64(ChunkDat[i-2], 19) ^ rightrotate64(ChunkDat[i-2], 61) ^ (ChunkDat[i-2] >> 6);
			ChunkDat[i] = ChunkDat[i-16] + s0 + ChunkDat[i-7] + s1;
		}

		/* Initialize Hash */
		for (i = 0; i < 16; i+=2) wh[i] = h[i];
		for (i = 1; i < 16; i+=2) wh[i] = 0; /* Overflown bytes */

		/* Main loop */
		for (i = 0; i < 80; i++) {
			s0 = rightrotate64(wh[0], 28) ^ rightrotate64(wh[0], 34) ^ rightrotate64(wh[0], 39);
			maj = (wh[0] & wh[2]) ^ (wh[0] & wh[4]) ^ (wh[2] & wh[4]);
			t2 = s0 + maj;
			s1 = rightrotate64(wh[8], 14) ^ rightrotate64(wh[8], 18) ^ rightrotate64(wh[8], 41);
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

char* sha512calc(unsigned char *inbuf, size_t bufsize)
{
	/* Initialize */
	unsigned long long h[16] = {
		0x6a09e667f3bcc908,0, 0xbb67ae8584caa73b,0, 0x3c6ef372fe94f82b,0, 0xa54ff53a5f1d36f1,0,
		0x510e527fade682d1,0, 0x9b05688c2b3e6c1f,0, 0x1f83d9abfb41bd6b,0, 0x5be0cd19137e2179,0
	};
	
	/* Calculate */
	sha512_384_calc(inbuf, bufsize, h);

	/* answer */
	sprintf_s(hashbuf, "%016llx%016llx%016llx%016llx%016llx%016llx%016llx%016llx",
		h[0], h[2], h[4], h[6], h[8], h[10], h[12], h[14]);
	return hashbuf;
}

char* sha384calc(unsigned char *inbuf, size_t bufsize)
{
	/* Initialize */
	unsigned long long h[16] = {
		0xcbbb9d5dc1059ed8,0, 0x629a292a367cd507,0, 0x9159015a3070dd17,0, 0x152fecd8f70e5939,0,
		0x67332667ffc00b31,0, 0x8eb44a8768581511,0, 0xdb0c2e0d64f98fa7,0, 0x47b5481dbefa4fa4,0
	};
	
	/* Calculate */
	sha512_384_calc(inbuf, bufsize, h);

	/* answer */
	sprintf_s(hashbuf, "%016llx%016llx%016llx%016llx%016llx%016llx",
		h[0], h[2], h[4], h[6], h[8], h[10]);
	return hashbuf;
}
