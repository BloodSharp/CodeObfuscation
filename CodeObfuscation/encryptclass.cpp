#include "encryptclass.h"
#include <Windows.h>

bool cEncryptClass::OpenFile(LPSTR szFileName)
{
	DWORD dwBytesReaded;
	dwFileSize = 0, gFileBuffer = 0;
	HANDLE hFile = CreateFile(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile)
	{
		dwFileSize = GetFileSize(hFile, NULL);
		gFileBuffer = new BYTE[dwFileSize];
		if (ReadFile(hFile, gFileBuffer, dwFileSize, &dwBytesReaded, NULL))
			if (CloseHandle(hFile))
				return true;
	}
	return false;
}

bool cEncryptClass::WriteEncryptedFile(LPSTR szFileName)
{
	DWORD dwBytesWriten;
	HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile)
		if (WriteFile(hFile, gFileBuffer, dwFileSize, &dwBytesWriten, NULL))
			if (CloseHandle(hFile))
				return true;
	return false;
}

bool cEncryptClass::EncryptBuffer()
{
	PIMAGE_DOS_HEADER IDH;
	PIMAGE_NT_HEADERS INTH;
	PIMAGE_SECTION_HEADER ISH;
	PBYTE lpCodeToEncrypt;
	DWORD dwCodeToEncryptSize;
	DWORD i;

	IDH = (PIMAGE_DOS_HEADER)gFileBuffer;
	if (IDH->e_magic != IMAGE_DOS_SIGNATURE)
		return false;
	INTH = (PIMAGE_NT_HEADERS)&gFileBuffer[IDH->e_lfanew];
	if (INTH->Signature != IMAGE_NT_SIGNATURE)
		return false;
	for (i = 0; i < INTH->FileHeader.NumberOfSections; i++)
	{
		ISH = (PIMAGE_SECTION_HEADER)&gFileBuffer[IDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i];
		if (!strcmp((PCHAR)ISH->Name, ".reloc"))
			return false;
	}
	for (i = 0; i < INTH->FileHeader.NumberOfSections; i++)
	{
		ISH = (PIMAGE_SECTION_HEADER)&gFileBuffer[IDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i];
		if (ISH->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			for (PBYTE j = &gFileBuffer[ISH->PointerToRawData]; j < &gFileBuffer[ISH->PointerToRawData + ISH->SizeOfRawData - 10]/*PUSH AND CALL*/; j++)
			{
				//IF BeginEncryptCode
				if (j[0] == 0x68//PUSH OPCODE
					&& j[1] == 0xFF//0xDEADBAFF
					&& j[2] == 0xBA
					&& j[3] == 0xAD
					&& j[4] == 0xDE
					&& j[5] == 0xE8//CALL OPCODE
					)
				{
					lpCodeToEncrypt = j + 10;
					dwCodeToEncryptSize = 0;
					for (PBYTE h = lpCodeToEncrypt; h < &gFileBuffer[ISH->PointerToRawData + ISH->SizeOfRawData - 5]/*PUSH 0xDEADBAFF*/; h++)
					{
						if (h[0] == 0x68//PUSH OPCODE
							&& h[1] == 0xFF//0xDEADBAFF
							&& h[2] == 0xBA
							&& h[3] == 0xAD
							&& h[4] == 0xDE)
							break;
						dwCodeToEncryptSize++;
					}
					//Encrypt & Set Password
					*(PDWORD)(j + 1) = EncryptCode(lpCodeToEncrypt, dwCodeToEncryptSize);
				}
			}
		}
	}
	return true;
}

void cEncryptClass::RelaseBuffer()
{
	if (gFileBuffer)delete[]gFileBuffer;
}

static ULONG myrandseed=0;
ULONG __stdcall myrand()
{
	return (((myrandseed = myrandseed * 214013L + 2531011L) >> 16) & 0x7fff);;
}

LPSTR RC4(LPSTR szBuf, LPSTR szKey, DWORD dwBufLen, DWORD dwKeyLen)
{
	int i, j = 0, s[256];
	DWORD dw;
	BYTE tmp;
	LPBYTE Buf = (LPBYTE)szBuf;
	LPBYTE Key = (LPBYTE)szKey;
	for (i = 0; i < 256; i++)
		s[i] = i;
	for (i = 0; i < 256; i++)
	{
		j = (j + s[i] + Key[i % dwKeyLen]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
	for (dw = 0; dw < dwBufLen; dw++)
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		Buf[dw] ^= s[(s[i] + s[j]) % 256];
	}
	return (LPSTR)Buf;
}

DWORD cEncryptClass::EncryptCode(PBYTE lpBeginCode, DWORD dwSizeOfCode)
{
	DWORD dwPassWord = 0xDEADBAFF;
	while (dwPassWord == 0xDEADBAFF)
	{
		myrandseed = timeGetTime();
		dwPassWord = myrand();
	}
	RC4((LPSTR)lpBeginCode, (LPSTR)&dwPassWord, dwSizeOfCode, 4);
	if (dwSizeOfCode >= 5)
	{
		for (PBYTE i = lpBeginCode; i < (PBYTE)((DWORD)lpBeginCode + dwSizeOfCode); i++)
			if (i[0] == 0x68//PUSH OPCODE
				&& i[1] == 0xFF//0xDEADBAFF
				&& i[2] == 0xBA
				&& i[3] == 0xAD
				&& i[4] == 0xDE)
			{
				RC4((LPSTR)lpBeginCode, (LPSTR)&dwPassWord, dwSizeOfCode, 4);
				dwPassWord = EncryptCode(lpBeginCode, dwSizeOfCode);
			}
	}
	return dwPassWord;
}