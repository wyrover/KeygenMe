/*  *************************************************************************
	*				*** KeygenMe #2  ***							*
	*************************************************************************
*/

#define WIN_32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x501
#pragma comment(linker, "/filealign:0x200 /ignore:4078 /merge:.text=.data /merge:.rdata=.data")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "gdiplus.lib") // oh do I have plans for you...
#pragma comment(lib, "msimg32.lib")

#define _CPUID_GET_EXTENDED_INFO

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include "base32/base32.cpp"
#include "md5/winmd5.h"

#define nr_bits 2048 // number of bits used in our RSA keys
#define xorkey 0x8732AD3C // xor key used to de-obfuscate basic instructions

const unsigned int SKILL_YOUCANFLY		= 0x10;
const unsigned int SKILL_GOTGODMODE		= 0x20;
const unsigned int SKILL_PACKHEAT		= 0x30;
const unsigned int SKILL_UNDEAD			= 0x40;

const unsigned int EVAL_EDITION			= 0x50;
const unsigned int TEST_KEY				= 0x60;
const unsigned int STANDARD_KEY			= 0x90;
const unsigned int PRO_KEY				= 0x8080;
const unsigned int KEY_MAGIC 			= 0xBADFA17E;

// Junk code for us all
#define JUNK_CODE_1 			\
	__asm{push eax} 			\
	__asm{push edx} 			\
	__asm{xor edx, 0x90}		\
	__asm{push edx}				\
	__asm{sub edx, 0x80}		\
	__asm{pop eax}				\
	__asm{add eax, edx}			\
	__asm{pop edx}				\
	__asm{pop eax}				

#define JUNK_CODE_2				\
	__asm{push eax}				\
    __asm{xor eax, eax}			\
    __asm{setpo al}				\
    __asm{push edx}				\
    __asm{xor edx, eax}			\
    __asm{sal edx, 2}			\
    __asm{xchg eax, edx}		\
    __asm{pop edx}				\
    __asm{or eax, ecx}			\
    __asm{pop eax}				

// instruction to jmp over our registration call
#define JmpInstruction 0x17A28CD7 // xorkey ^ 0x909021EB = 0x17A28CD7
// memory CRC to ensure memory hasn't been altered
#define InternalRoutinesCrc 0x2479fe52 // memory crc


HCRYPTPROV hCryptProv;

// function prototypes
void GetCPUID(DWORD dwOperation, PDWORD pdwRegs);
DWORD GetProcessorFeatures(void);
DWORD GetSystemVolumeSerial(char *szSystemVolume);
void CRC32_Generate_Table();
unsigned long CRC32_Generate_CRC(unsigned char *lpBuffer, unsigned long nSize);
int RSAVerifyLicenseKey(char *szKey, char *signature_hex);
int RealRegistrationRoutine(char *, unsigned char *, char *);
int FakeRegistrationRoutine(char *, unsigned char *, char *);
void CheckKeyFormat(char *, char *);

// use a fake registration routine unless our key format criteria is met
int (*RegisterApplication)(char *, unsigned char *, char *) = &FakeRegistrationRoutine;
static unsigned long nCRCTable[256];

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
#

void InternalRoutinesStart(void){} // label marks the start of all our internal routines
int RealRegistrationRoutine(char *szName, unsigned char *szKey, char *szSignatureText)
{
	Base32 b32;
	AES_KEY AESDecKey;
	MD5Context ctx;
	char drive[4] = "A:\\";
	unsigned char szAlphabet[] = "123456789ABCDEFGHJKMNPQRSTUVWXYZ";
	unsigned char *pSzDecode255, *pTemp, *pKeyBackup, szDecryptedKey[33], szAESKey32[33], szTemp[53];
	unsigned char szAESDecryptIv[] = 
			{ 0x55, 0x12, 0x90, 0x32, 0x41, 0x85, 0xBC, 0x54, 0x04, 0x19, 0xAE, 0x49, 0x32, 0x99, 0x2D, 0x08 };
	unsigned long licensetype = 0, features = 0, hwid[2];
	int i;
	
	printf("RealRegistrationRoutine()\n");
	
	// backup key
	pKeyBackup = (unsigned char *)strdup((char *)szKey);
	if(!pKeyBackup){
		printf(">> Fatal error... Aborting.");
		return 0; 
	}
	
	// remove hythens
	pTemp = szTemp;
	while(*szKey){
		if(*(szKey) == '-') szKey++;
		*pTemp++ = *szKey++;
	}
	szKey = szTemp;
	
	// decode base32
	b32.Unmap32(szTemp, 52, szAlphabet);
	pSzDecode255 = (unsigned char *)malloc(32);
	if(pSzDecode255){
		b32.Decode32(szTemp, 52, pSzDecode255);		
		memset(szAESKey32, 0, sizeof(szAESKey32));
		memset(szDecryptedKey, 0, 33);
		
		// md5 hash our name
		CryptStartup();
		MD5Init(&ctx);
		MD5Update(&ctx, (unsigned char *)szName, strlen(szName));
		MD5Final(&ctx);
		
		// set up our AES key(= md5 hashed name)
		for(i = 0; i < 16; i++)
			sprintf((char *)szAESKey32 + strlen((char *)szAESKey32), "%02x", ctx.digest[i]);
		CryptCleanup();
		
		// decrypt our key using the hashed name
		AES_set_decrypt_key(szAESKey32, 32 * 8, &AESDecKey);
		AES_cbc_encrypt(pSzDecode255, szDecryptedKey, 32, &AESDecKey, szAESDecryptIv, AES_DECRYPT);
		free(pSzDecode255);
		
		//hexdump(stdout, "DecryptedKey:", szDecryptedKey, 32);
		
		// check key signature
		if(*(u_long *)(szDecryptedKey + 4) == KEY_MAGIC){
			printf(">> Key decoded successfully!\n");

			// check PRN's are within range
			if(*(u_long *)(szDecryptedKey) > 0xdeadbeef)
			{
				if(*(u_long *)(szDecryptedKey + 8) == (*(u_long *)(szDecryptedKey) + 512))
				{
					if(*(u_long *)(szDecryptedKey + 28) >= 0xBADC0DED)
					{
						printf(">> Pseudo Random Numbers within range!\n");

						// check features
						printf("-----\n");
						licensetype = *(u_long *)(szDecryptedKey + 24);
						features 	= *(u_long *)(szDecryptedKey + 12);
						
						// just a test key, no features
						if(licensetype == TEST_KEY)
							printf(">> Key type: Test key\n");
						// pro key, pro features allowed
						else if(licensetype == PRO_KEY){
							printf(">> Key type: Pro key\n");
							if(SKILL_UNDEAD == (features & SKILL_UNDEAD))
								printf(">> An eerie myst shrouds your undead aurua o.0\n");
							else if(SKILL_GOTGODMODE == (features & SKILL_GOTGODMODE))
								printf(">> Godlike :/\n");
						}else if(licensetype == STANDARD_KEY){				
							// standard key, only a few features allowed
							if(SKILL_YOUCANFLY == (features & SKILL_YOUCANFLY)) 
								printf(">> You can fly\n");
							
							if(SKILL_PACKHEAT == (features & SKILL_PACKHEAT))
								printf(">> You're packin heat now :p\n");
						}else{
							printf(">> License type invalid\n");
							free(pKeyBackup);
							return 0;
						}
						
						printf("-----\n");
						
						// get hardware id
						hwid[0] = GetProcessorFeatures();
						for(drive[0] = 'A'; drive[0] <= 'Z'; drive[0]++){
							if(GetDriveType(drive) == DRIVE_FIXED){
								hwid[1] = GetSystemVolumeSerial(drive);
								break;
							}
						}
						
						printf(">> Key hardware id: %04X-%04X\n>> Local hardware id: %04X-%04X\n", 
							*(u_long *)(szDecryptedKey + 16), *(u_long *)(szDecryptedKey + 20),
							hwid[0], hwid[1]);
						
						// check local hardware ID against key hardware ID
						if(*(u_long *)(szDecryptedKey + 16) == hwid[0]){
							if(*(u_long *)(szDecryptedKey + 20) == hwid[1]){
								printf(">> Hardware fingerprint valid\n>> Checking Key signature\n");
								// verify that key is signed
								if(RSAVerifyLicenseKey((char *)pKeyBackup, szSignatureText)){
									printf(">> License key valid!!\n");
									free(pSzDecode255);
									free(pKeyBackup);
									return 1;
								}
								else printf(">> License key signature invalid!\n");
							}
						}
						else printf(">> Hardware fingerprint mismatch\n");
					}
				}
			}		
		}
		printf(">> Key invalid!\n");
		free(pSzDecode255);
	}
	
	free(pKeyBackup);
	return 0;
}

// It's a fake... What more to say.
int FakeRegistrationRoutine(char *szUser, unsigned char *szKey, char * szSignature)
{
	printf("FakeRegistrationRoutine()\n");
	return 0;
}

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

// first hwid
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

// second hwid
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

// Performs a few simple format checks...
void CheckKeyFormat(char *szKey, char *szName)
{
	int i;
	char *pKey;
	
	printf("CheckKeyFormat()\n");
	
	// check length of key, name and check for hythens
	if(strlen(szKey) == 64 && strlen(szName) <= 9){
		for(i = 4; i < 64; i += 5) if(szKey[i] != '-') return;
		
		RegisterApplication = &RealRegistrationRoutine; // use real registration routine!
		printf(">> Key format valid!\n");
	}
	
	return;
}

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

// Mem scans :p
__forceinline int ScanForSwBreakpoints(void *pMemory, DWORD dwSize)
{
	unsigned char *pTmp = (unsigned char *)pMemory, tmpchar[2] = {0};
    
	printf("ScanForSwBreakpoints()\n");
	
	for(DWORD i = 0; i < dwSize; i++){
        tmpchar[0] = pTmp[i], tmpchar[1] = pTmp[i + 1];
		// Check for 0xCD03 and 0xEBFE
        if((tmpchar[0] ^ 0x56) == 0x9B && (tmpchar[1] ^ 0x56) == 0x55 || (tmpchar[0] ^ 0x57) == 0xBC && (tmpchar[1] ^ 0x57) == 0xA9)
            return 1; // breakpoint detected
	} 
	
    return 0;
}

// hardware breakpoints won't last :p
__forceinline int DetectHwBreakpoints()
{
	HANDLE hThread;
	CONTEXT ctx = {0}; // typical that sizeof(CONTEXT) == 0xCC(which is detected as a SW breakpoint)...
	
	printf("DetectHwBreakpoints()\n");
	
	ctx.ContextFlags = 0x1008c ^ 0x9C;  // == CONTEXT_DEBUG_REGISTERS
    hThread	= GetCurrentThread();
	if(GetThreadContext(hThread, &ctx) != 0){
		// Now we could also set the thread context here, 
		// which seems to cause a virgin olly to loose sight of its debuggee...
		if(ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
			return 1;
	}
    return 0;
}

__forceinline void CRC32_Generate_Table() // By Napalm
{
    unsigned long nPoly; 
	register unsigned long nCRC;
	int i;
	
	printf("CRC32_Generate_Table()\n");
	
	nPoly = 0xEDB88320L;
    for(i = 0; i < 256; i++){
		nCRC = i;
        for(int j = 8; j > 0; j--){
            if(nCRC & 1) nCRC = ((nCRC >> 1) ^ nPoly);
            else nCRC >>= 1;
		}
        nCRCTable[i] = nCRC;
	}
}

__forceinline unsigned long CRC32_Generate_CRC(unsigned char *lpBuffer, unsigned long nSize) // By Napalm
{
    register unsigned long nCRC; 
	
	printf("CRC32_Generate_CRC()\n");
	
	nCRC = 0xFFFFFFFF;
    while(nSize--) nCRC = ((nCRC >> 8) ^ nCRCTable[((nCRC ^ *lpBuffer++) & 0xFF)]);	
    return (nCRC ^ 0xFFFFFFFF);
}

// Mem CRC check :p
__forceinline unsigned long VerifyMemory(void *pMemory, DWORD dwSize, unsigned long origcrc)
{
	unsigned long filecrc = 0;
	CRC32_Generate_Table();
	
	printf("VerifyMemory()\n");
	filecrc = CRC32_Generate_CRC((unsigned char *)pMemory, dwSize);
	printf(">> Memory CRC = 0x%x\n", filecrc);
	return (filecrc == origcrc);
}
void InternalRoutinesEnd(void){} // end of our internal routines

int main(int argc, char *argv[])
{
	char *szUser, *szKey, *szRsaSignature, *szData;
	
	FILE* signatureFile;
	unsigned int filesize;
	
	// read key file
	if(!(signatureFile = fopen("license.key", "r"))){
		printf("Error reading license file\n");
		return 0;
	}
	else{
		fseek(signatureFile, 0, SEEK_END);
		filesize = ftell(signatureFile);
		fseek(signatureFile, 0, SEEK_SET);
		szData = (char *)malloc(filesize + 1);
		if(szRsaSignature){
			memset(szData, 0, filesize + 1);
			fread(szData, 1, filesize, signatureFile);
			
			if(!(szUser = strtok(strdup(szData), "*")))
				return printf("Error reading name\n");
			if(!(szKey  = strtok(strdup(szData + strlen(szUser)), "*")))
				return printf("Error reading key\n");
			if(!(szRsaSignature = strdup(strtok(szData + strlen(szUser) + strlen(szKey) + 1, "*"))))
				return printf("Error reading signature\n");
			free(szData);
			printf("\n---------\nName: %s\nKey: %s\nSignature: ...\n---------\n\n", szUser, szKey);
		}
		fclose(signatureFile);
	}	
	
	// hardware breakpoints in use?
	if(DetectHwBreakpoints()){
		printf(">> Hardware Breakpoints detected!\n");
		
		__asm{	// Oops!
			add esp, 512
			mov ebp, edx // note: will throw a compiler warning, this is hazardous but intentional
			mov edx, offset pCrashAndBurn
			jmp edx // no reference jmp points to pCrashAndBurn from this location, dynamic jmps :p...  
		}
	}
	
	// are any of our internal routines ridden with breakpoints?
	if(ScanForSwBreakpoints(&InternalRoutinesStart, ((DWORD)InternalRoutinesEnd - (DWORD)InternalRoutinesStart)) == 1){
		printf(">> Software Breakpoints detected!\n");
		
		__asm{	// hide our registration routine(it will be jumped over upon detection)
			push edi
			push ecx
			mov ecx, pRegistrationCallAddr
			JUNK_CODE_2
			mov edi, JmpInstruction
			xor edi, xorkey
			mov dword ptr [pRegistrationCallAddr], edi
			pop ecx
			pop edi
		}
	}

	// check our internal routines aren't modified
	if(!(VerifyMemory(&InternalRoutinesStart, ((DWORD)InternalRoutinesEnd - (DWORD)InternalRoutinesStart), InternalRoutinesCrc))){
		printf(">> Memory corrupt!\n");
		
		__asm{	// hide our registration routine(it will be jumped over upon detection)
			push eax
			push edx
			mov eax, pRegistrationCallAddr
			JUNK_CODE_1
			mov edx, JmpInstruction
			xor edx, xorkey
			mov dword ptr [pRegistrationCallAddr], edx
			pop edx
			pop eax
		}
		
	}
	
	// if our key format isn't valid we'll call into a fake registration routine 
	__asm{
		pCheckKeyFormat:
		push dword ptr szUser
		push dword ptr szKey
		JUNK_CODE_2
		call CheckKeyFormat
	}
	
	// registration routine gets jumped over upon debugger detection
	__asm{
		pRegistrationCallAddr:
		push dword ptr szRsaSignature
		push dword ptr szKey
		push dword ptr szUser
		JUNK_CODE_1
		call RegisterApplication // << don't you just love function pointers
	}
	
	return 0;
	
	__asm{ // what better way to crash spectacularly :p.
		pCrashAndBurn:
		push eax
		retn
	}
}
