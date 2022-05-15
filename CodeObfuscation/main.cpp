#include <stdio.h>
#include "encryptclass.h"

int main()
{
	cEncryptClass gEncrypt;
	if(gEncrypt.OpenFile("Test.exe"))
		if(gEncrypt.EncryptBuffer())
			if(gEncrypt.WriteEncryptedFile("TestEncrypted.exe"))
				printf("Exe SUCCESS!\n"),gEncrypt.RelaseBuffer();
			else printf("Exe FAIL Writing File!\n"),gEncrypt.RelaseBuffer();
		else printf("Exe FAIL Encrypting File!\n"),gEncrypt.RelaseBuffer();
	else printf("Exe FAIL Opening/Reading File!\n"),gEncrypt.RelaseBuffer();
	getchar();
	return 0;
}