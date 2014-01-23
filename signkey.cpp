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
#define nr_bits 2048 // rsa...


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

int main(int argc, char **argv)
{
	char *signature = 0; // rsa signature
	
	if(argc != 2){
		printf("\tUsage: %s <Key to sign>\n", argv[0]);
		return -1;
	}
	

	// sign key
	SignLicenseKey((char *)argv[1], &signature);
	
	// write key details to file
	FILE* signatureFile;
	signatureFile = fopen("signature.txt", "w");
	if(signatureFile){
		printf("Generated signature for key %s\n", argv[1]);
		fprintf(signatureFile, "%s", signature);
		fclose(signatureFile);
	}
	
	return 0;
}
