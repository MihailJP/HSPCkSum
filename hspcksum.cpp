#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include "hsp3plugin.h"
#include "sha1.h"
#include "hspcksum.h"

char *ref_str; /* 返り値文字列 */
char hashbuf[256]; /* ハッシュを格納 */

unsigned int leftrotate (unsigned int val, int digits)
{
	return (val << digits) | (val >> (8 * sizeof(unsigned int) - digits));
}

/* 関数定義 */
static void *reffunc(int *type_res, int cmd)
{
	PVal* pv; char *pbuf; int bufsize; char *refbuf;

	/* 関数か調べる */
	if ( *type != TYPE_MARK ) puterror(HSPERR_INVALID_FUNCPARAM);
	if ( *val != '(' ) puterror(HSPERR_INVALID_FUNCPARAM);
	code_next();

	switch(cmd) {
	case 0x10:
		pv = code_getpval();
		bufsize = code_geti();
		pbuf = (char *)malloc(bufsize);
		memcpy(pbuf, pv->pt, bufsize);
		refbuf = (char *)malloc(24);
		ref_str = hspmalloc(lstrlen(refbuf));
		lstrcpy(ref_str, sha1calc((unsigned char *)pbuf, bufsize));
		*type_res = HSPVAR_FLAG_STR;
		break;
	default:
		puterror(HSPERR_UNSUPPORTED_FUNCTION);
	}

	/* 関数か調べる */
	if ( *type != TYPE_MARK ) puterror(HSPERR_INVALID_FUNCPARAM);
	if ( *val != ')' ) puterror(HSPERR_INVALID_FUNCPARAM);
	code_next();

	if (*type_res == HSPVAR_FLAG_STR) return (void *)ref_str;
	else return (void *)NULL;
}

/* 初期化処理 */
EXPORT void WINAPI hsp3cmdinit(HSP3TYPEINFO *info)
{
	hsp3sdk_init(info);
	info->reffunc = reffunc;
	return;
}
