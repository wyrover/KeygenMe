#define WIN_32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x501
#pragma comment(linker, "/filealign:0x200 /ignore:4078 /merge:.text=.data /merge:.rdata=.data")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/aes.h>
#include "base32/base32.cpp"
#include "md5/winmd5.h"
#define nr_bits 2048 // rsa...

#define _CPUID_GET_EXTENDED_INFO
#define _LOCALTEST // hwid will now match _this_ machine!!
//#define _DEBUG

HCRYPTPROV hCryptProv;

// I'll rename these later but GOD MODE is staying you bastards!
const unsigned int SKILL_YOUCANFLY		= 0x10;
const unsigned int SKILL_GOTGODMODE		= 0x20;
const unsigned int SKILL_PACKHEAT		= 0x30;
const unsigned int SKILL_UNDEAD			= 0x40;

const unsigned int EVAL_EDITION			= 0x50;
const unsigned int TEST_KEY				= 0x60;
const unsigned int STANDARD_KEY			= 0x90;
const unsigned int PRO_KEY				= 0x8080;
const unsigned int KEY_MAGIC 			= 0xBADFA17E;

#ifdef _DEBUG
static void hexdump(FILE *f, const char *title, const unsigned char *s, int l)
{
	int n = 0;
	fprintf(f, "%s", title);
	for(; n < l; ++n){
		if((n % 16) == 0)
			fprintf(f, "\n%04x", n);
			fprintf(f, " %02x", s[n]);
	}
	fprintf(f, "\n");
	return;
}
#endif

#ifdef _LOCALTEST
void GetCPUID(DWORD dwOperation, PDWORD pdwRegs)
{
	unsigned long a, b, c, d;
	__asm {
		mov eax, dwOperation;
		cpuid;
		mov a, eax;
		mov b, ebx;
		mov c, ecx;
		mov d, edx;
	}
	pdwRegs[0] = a; pdwRegs[1] = b; pdwRegs[2] = c; pdwRegs[3] = d;
}

DWORD GetProcessorFeatures(void)
{
	DWORD dwProcessorFeatures = 0;
	DWORD ProcessorInfo[4];

	GetCPUID(1, ProcessorInfo);
	dwProcessorFeatures ^= ProcessorInfo[0];
	dwProcessorFeatures ^= ProcessorInfo[1];
	dwProcessorFeatures ^= ProcessorInfo[2];
	dwProcessorFeatures ^= ProcessorInfo[3];

#ifdef _CPUID_GET_EXTENDED_INFO
	GetCPUID(0x80000001, ProcessorInfo);
	dwProcessorFeatures ^= ProcessorInfo[2];
	dwProcessorFeatures ^= ProcessorInfo[3];
#endif

	return dwProcessorFeatures;
}

DWORD GetSystemVolumeSerial(char *szSystemVolume)
{
	char *lpszVolumeName, *lpszFileSystemName;
	DWORD dwVolumeSerialNumber = 0xFFFFFFFF, dwMaximumComponentLength, dwFileSystemFlags;

	lpszVolumeName = (char *)malloc(MAX_PATH + 1);
	if(lpszVolumeName != NULL){
		lpszFileSystemName = (char *)malloc(MAX_PATH * 1);
		if(lpszFileSystemName != NULL){
			GetVolumeInformation(szSystemVolume, lpszVolumeName, MAX_PATH + 1, &dwVolumeSerialNumber, &dwMaximumComponentLength, &dwFileSystemFlags, lpszFileSystemName, MAX_PATH + 1);
			free(lpszFileSystemName);
		}
		free(lpszVolumeName);
	}
	return dwVolumeSerialNumber;
}
#endif

RSA* RSA_read_from_file(char *filename)
{
	char *buffer;
	int include_private_data = 0, max_hex_size = (nr_bits / 4) + 1;
	FILE* keyfile;
	RSA* rsa;
	
	rsa = RSA_new();
	if(!rsa) return NULL;
	
	buffer = (char *)malloc(max_hex_size);
	if(buffer){
		keyfile = fopen(filename, "r");
		if(keyfile){
			fscanf(keyfile, "%d", &include_private_data);
			fscanf(keyfile, "%s", buffer);
			BN_hex2bn(&rsa->n, buffer);
			fscanf(keyfile, "%s", buffer);
			BN_hex2bn(&rsa->e, buffer);
			if(include_private_data){
				fscanf(keyfile, "%s", buffer);
				BN_hex2bn(&rsa->d, buffer);
				fscanf(keyfile, "%s",buffer);
				BN_hex2bn(&rsa->p, buffer);
				fscanf(keyfile, "%s",buffer);
				BN_hex2bn(&rsa->q, buffer);
				fscanf(keyfile, "%s",buffer);
				BN_hex2bn(&rsa->dmp1, buffer);
				fscanf(keyfile, "%s",buffer);
				BN_hex2bn(&rsa->dmq1, buffer);
				fscanf(keyfile, "%s",buffer);
				BN_hex2bn(&rsa->iqmp, buffer);
			}
			fclose(keyfile);
		}
		free(buffer);
	}
	return rsa;
}

void SignLicenseKey(char *szKey, char **signature_hex)
{
	unsigned char* signature;
	unsigned int slen, verified;

	RSA* private_key = RSA_read_from_file("private.key");
	if(private_key){
		signature = (unsigned char *) malloc(RSA_size(private_key));
		if(signature){
			RSA_sign(NID_md5, (unsigned char *)szKey, strlen(szKey), signature, &slen, private_key);
			*signature_hex = (char *)malloc(slen * 2 + 1);
			if(*signature_hex){
				for(int i = 0; i < slen; i++) sprintf(*signature_hex + i * 2, "%02x", signature[i]);
			}
			
			RSA_free(private_key);
			free(signature);
		}
	}
	
	return;
}

// verifies if our key is signed
int RSAVerifyLicenseKey(char *szKey, char *signature_hex)
{
	unsigned char* signature;
	unsigned int slen, verified = 0;
	
	printf("VerifyLicenseKey()\n");
	
	// convert hex back to ascii
	slen = strlen(signature_hex) / 2;
	signature = (unsigned char *)malloc(slen);
	if(signature){
		for(int i = 0; i < slen; i++)
			sscanf(signature_hex + i * 2, "%02x", signature + i);
		
		// verify the license key using public key
		RSA* public_key = RSA_read_from_file("public.key");
		if(public_key){
			verified = RSA_verify(NID_md5, (unsigned char *)szKey, strlen(szKey), signature, slen, public_key);
			RSA_free(public_key);
		}
		free(signature);
	}
	return verified;
}

int main(int argc, char **argv)
{
	Base32 b32;
	AES_KEY AESEncKey;
	MD5Context ctx;
	unsigned char alphabet[] = "123456789ABCDEFGHJKMNPQRSTUVWXYZ";
	unsigned char szKey32[33]; // AES Key
	unsigned char AESEncryptIv[] = 
			{ 0x55, 0x12, 0x90, 0x32, 0x41, 0x85, 0xBC, 0x54, 0x04, 0x19, 0xAE, 0x49, 0x32, 0x99, 0x2D, 0x08 };
	char *signature = 0; // rsa signature
	
	unsigned char plaintext[33], ciphertext[33], *pKey = 0;
	unsigned char *pSzData32, szData255[33]; 
	int encodeLength = 0, keylength = 0, i, x; // NOTE: TEMP SAMPLE HARDWARE ID USED
	unsigned long int prng, licensetype = 0, features = 0, hwid[2] = { 0xDEADBEEF, 0xCAFEBABE };
	
	//printf(">> KOrUPt's Keygen for KKeygenMe #2\n");
	
	if(argc != 2){
		printf("\tUsage: %s <registration name>\n", argv[0]);
		return -1;
	}else if(strlen(argv[1]) > 9){
		printf("Name too long\n");
		return -1;
	}
	
	SetErrorMode(SEM_NOGPFAULTERRORBOX);
	
	// md5 hash our name
	CryptStartup();
	MD5Init(&ctx);
	MD5Update(&ctx, (unsigned char *)argv[1], strlen(argv[1]));
	MD5Final(&ctx);
	
	memset(ciphertext, 0, sizeof(ciphertext));
	memset(szKey32, 0, sizeof(szKey32));
	
	// set up our AES key(= md5 hashed name)
	for(i = 0; i < 16; i++)
		sprintf((char *)szKey32 + strlen((char *)szKey32), "%02x", ctx.digest[i]);
	CryptCleanup();
	
#ifdef _LOCALTEST
	// we'll encode the key with our local hwid as opposed to one given to us by our customer
	char drive[4] = "A:\\";
	hwid[0] = GetProcessorFeatures();
	
	for(drive[0] = 'A'; drive[0] <= 'Z'; drive[0]++){
		if(GetDriveType(drive) == DRIVE_FIXED){
			hwid[1] = GetSystemVolumeSerial(drive);
			break;
		}
	}
#endif	
	
	// Create key
	srand(GetTickCount());
	memset(plaintext, 0, 33);
	*(u_long *)(plaintext)		= prng = (rand() % 0xffffffff) + 0xdeadbeef;
	*(u_long *)(plaintext + 4)	= KEY_MAGIC;
	*(u_long *)(plaintext + 8)	= prng + 512;
	features |= SKILL_UNDEAD | SKILL_YOUCANFLY;
	*(u_long *)(plaintext + 12)	= features;
	*(u_long *)(plaintext + 16) = hwid[0];
	*(u_long *)(plaintext + 20) = hwid[1];
	licensetype = PRO_KEY;
	*(u_long *)(plaintext + 24) = licensetype; 
	prng = (rand() % 1000000) + 0xBADC0DED;
	*(u_long *)(plaintext + 28) = prng; // this part of the key has to be >= 0xBADCODED

#ifdef _DEBUG
	printf("\n>> Md5 of name: %s\n", szKey32);
	hexdump(stdout, "\n--------\nPlaintext:", plaintext, 32);
#endif
	
	AES_set_encrypt_key(szKey32, 32 * 8, &AESEncKey);
	AES_cbc_encrypt(plaintext, ciphertext, 32, &AESEncKey, AESEncryptIv, AES_ENCRYPT);
	
#ifdef _DEBUG
	hexdump(stdout, "Ciphertext:", ciphertext, 32);
	printf("\nHardware id: %04X-%04X\n", hwid[0], hwid[1]);
#endif
	
	encodeLength = b32.GetEncode32Length(32);
	pSzData32 = (unsigned char *)malloc(encodeLength + 1);
	if(pSzData32){
		memset(pSzData32, 0, encodeLength + 1);
		if(b32.Encode32(ciphertext, 32, pSzData32)){
			b32.Map32(pSzData32, encodeLength, alphabet);
		}else{
			printf("An error occoured during Base32 translation\n");
			free(pSzData32);
			return -1;
		}
		
		// add hypthens
		i = 0, x = 0;
		pKey = (unsigned char *)malloc(encodeLength + 13);
		if(pKey){
			memset(pKey, 0, encodeLength + 13);
			while(x < encodeLength){
				memcpy(pKey + i, pSzData32 + x, 4);
				i += 4, x += 4;
				*(pKey + (i++)) = '-';
			}
			
			// remove trailing hythen
			*(pKey + (encodeLength + 12)) = 0;
			
			// sign key
			SignLicenseKey((char *)pKey, &signature);
			
			// write key details to file
			FILE* signatureFile;
			signatureFile = fopen("license.key", "w");
			if(signatureFile){
				printf("Generated key file license.key\n");
				fprintf(signatureFile, "%s*%s*%s*", argv[1], pKey, signature);
				fclose(signatureFile);
			}
			
			
			free(pKey);
		}
		
		free(pSzData32);
	}
	
	return 0;
}
