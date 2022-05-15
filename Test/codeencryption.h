#ifndef CODE_OBFUSCATION_H
#define CODE_OBFUSCATION_H

#define ENCRYPTION_PAGE_PROTECTIONS 1
#define ENCRYPTION_CLEAR_CODE (1<<1)

typedef struct CodeEncryption_s
{
	unsigned char *dwCodeBegin;
	unsigned char *dwCodeBeginClear;
	unsigned long dwSizeOfCode;
	unsigned long dwSizeOfCodeClear;
	unsigned long dwPassWord;
	unsigned long dwOldPageProtection;
	unsigned char biOptions;
}CodeEncryption;

void _stdcall BeginEncryptCode(unsigned long dwPassWord, CodeEncryption* lpEncryptStruct);
void _stdcall EndEncryptCode(CodeEncryption* lpEncryptStruct, unsigned long dwDeadBuffer);

#define BeginEncryption(AddressOfCodeEncryptionStruct) \
	BeginEncryptCode(0xDEADBAFF,AddressOfCodeEncryptionStruct)
	/*
	__asm push AddressOfCodeObfuscationStruct;\
	__asm push 0xDEADBAFF;\
	__asm call BeginEncryptCode;
	*/

#define EndEncryption(AddressOfCodeEncryptionStruct) \
	EndEncryptCode(AddressOfCodeEncryptionStruct,0xDEADBAFF)
	/*
	__asm push 0xDEADBAFF;\
	__asm push AddressOfCodeObfuscationStruct;\
	__asm call EndEncryptCode;
	*/

#endif //CODE_OBFUSCATION_H