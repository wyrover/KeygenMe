// Generates our RSA keys
#pragma comment(linker, "/filealign:0x200 /ignore:4078 /merge:.text=.data /merge:.rdata=.data")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")
#define _WIN32_WINNT 0x501

#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#define nr_bits 2048

RSA* RSA_read_from_file(char* filename)
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

// used to write our public and private keys
void RSA_write_to_file(RSA* rsa, char* filename, int include_private_data)
{
	FILE* keyfile = fopen(filename,"w");
	if(keyfile){
		fprintf(keyfile, "%d\r\n", include_private_data);
		fprintf(keyfile, "%s\r\n", BN_bn2hex(rsa->n));
		fprintf(keyfile, "%s\r\n", BN_bn2hex(rsa->e));
		if(include_private_data){
			fprintf(keyfile, "%s\r\n", BN_bn2hex(rsa->d));
			fprintf(keyfile, "%s\r\n", BN_bn2hex(rsa->p));
			fprintf(keyfile, "%s\r\n", BN_bn2hex(rsa->q));
			fprintf(keyfile, "%s\r\n", BN_bn2hex(rsa->dmp1));
			fprintf(keyfile, "%s\r\n", BN_bn2hex(rsa->dmq1));
			fprintf(keyfile, "%s\r\n", BN_bn2hex(rsa->iqmp));
		}
		fclose(keyfile);
	}
	return;
}

int main(void)
{
	// generate public and private keys
	RSA *rsa = RSA_generate_key(nr_bits, 65537, NULL, NULL);
	if(rsa){
		RSA_write_to_file(rsa, "private.key", 1);
		RSA_write_to_file(rsa, "public.key", 0);
		RSA_free(rsa);
	}
	
	printf("RSA Keypair generated;\n");
	return 0;
}