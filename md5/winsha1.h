// SHA1 Hashing - Using Windows Crypto API
#include <wincrypt.h>

/*
SHA1Context ctxSHA1;
SHA1Init(&ctxSHA1);
SHA1Update(&ctxSHA1, (LPBYTE)lpszSHA1Input, lstrlen(lpszSHA1Input) + ((nLenN + nLenC) & 1));  
SHA1Final(&ctxSHA1);
LPSTR lpszSHA1Bin = dec2bin(ctxSHA1.digest, 8, 20);
*/

extern HCRYPTPROV hCryptProv;

typedef struct {
	unsigned char digest[20];
	unsigned long hHash;
} SHA1Context;


BOOL CryptStartup()
{
	if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0) == 0)
		return FALSE;
	return TRUE;
}

void CryptCleanup()
{
	if(hCryptProv) CryptReleaseContext(hCryptProv, 0);
	hCryptProv = NULL;
}

void inline SHA1Init(SHA1Context *ctx)
{
	CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &ctx->hHash);
}


void inline SHA1Update(SHA1Context *ctx, unsigned char const *buf, unsigned len)
{
	CryptHashData(ctx->hHash, buf, len, 0);
}

void inline SHA1Final(SHA1Context *ctx)
{
	DWORD dwCount = 20;
	CryptGetHashParam(ctx->hHash, HP_HASHVAL, ctx->digest, &dwCount, 0);
	if(ctx->hHash) CryptDestroyHash(ctx->hHash);
	ctx->hHash = 0;
}
