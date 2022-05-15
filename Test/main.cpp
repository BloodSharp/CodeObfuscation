#include <stdio.h>
#include <math.h>
#include "codeencryption.h"

#pragma optimize("",off)
_declspec(noinline)int addOperation(int a, int b)
{
	int iRetval;
	CodeEncryption cdProtection;
	cdProtection.dwPassWord = 0xDEADBAFF;
	cdProtection.biOptions = ENCRYPTION_PAGE_PROTECTIONS | ENCRYPTION_CLEAR_CODE;
	iRetval = a;
	BeginEncryption(&cdProtection);
	iRetval += b;
	EndEncryption(&cdProtection);
	return iRetval;
}

_declspec(noinline)int addAndSquareRoot(int a, int b)
{
	int iRetval;
	CodeEncryption cdProtection;
	cdProtection.dwPassWord = 0xDEADBAFF;
	cdProtection.biOptions = ENCRYPTION_PAGE_PROTECTIONS | ENCRYPTION_CLEAR_CODE;
	iRetval = a;
	BeginEncryption(&cdProtection);
	iRetval += b;
	iRetval = (int)sqrt(iRetval);
	EndEncryption(&cdProtection);
	return iRetval;
}
#pragma optimize("",on)

int main()
{
	int a = 4, b = 21;
	printf("%i+%i=%i\n", a, b, addOperation(a, b));
	printf("%i+%i=%i\n", a, b, addOperation(a, b));
	getchar();
	printf("sqrt(%i+%i)=%i\n", a, b, addAndSquareRoot(a, b));
	printf("sqrt(%i+%i)=%i\n", a, b, addAndSquareRoot(a, b));
	getchar();
	return 0;
}