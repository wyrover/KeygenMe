//
// MD5 Hashing Example - Using Windows Crypto API
//
// by Napalm @ NetCore2K
//

#include <windows.h>
#include <wincrypt.h>

extern HCRYPTPROV hCryptProv;
typedef struct {
    unsigned char digest[16];
    unsigned long hHash;
} MD5Context;


BOOL CryptStartup()
{
    if(CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET) == 0){
        if(GetLastError() == NTE_EXISTS){
            if(CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0) == 0)
                return FALSE;
        }else return FALSE;
    }
    return TRUE;
}

void CryptCleanup()
{
    if(hCryptProv) CryptReleaseContext(hCryptProv, 0);
    hCryptProv = NULL;
}

void inline MD5Init(MD5Context *ctx)
{
    CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &ctx->hHash);
}


void inline MD5Update(MD5Context *ctx, unsigned char const *buf, unsigned len)
{
    CryptHashData(ctx->hHash, buf, len, 0);
}

void inline MD5Final(MD5Context *ctx)
{
    DWORD dwCount = 16;
    CryptGetHashParam(ctx->hHash, HP_HASHVAL, ctx->digest, &dwCount, 0);
    if(ctx->hHash) CryptDestroyHash(ctx->hHash);
    ctx->hHash = 0;
}