#include "codeencryption.h"
#include <Windows.h>

#pragma optimize("",off)

_declspec(noinline)LPSTR RC4(LPSTR szBuf,LPSTR szKey,DWORD dwBufLen,DWORD dwKeyLen)
{
	int i,j=0,s[256];
	DWORD dw;
	BYTE tmp;
	LPBYTE Buf=(LPBYTE)szBuf;
	LPBYTE Key=(LPBYTE)szKey;
	for(i=0;i<256;i++)
		s[i]=i;
	for(i=0;i<256;i++)
	{
		j=(j+s[i]+Key[i%dwKeyLen])%256;
		tmp=s[i];
		s[i]=s[j];
		s[j]=tmp;
	}
	for(dw=0;dw<dwBufLen;dw++)
	{
		i=(i+1)%256;
		j=(j+s[i])%256;
		tmp=s[i];
		s[i]=s[j];
		s[j]=tmp;
		Buf[dw]^=s[(s[i]+s[j])%256];
	}
	return (LPSTR)Buf;
}

_declspec(noinline)void _stdcall BeginEncryptCode(DWORD dwPassWord,CodeEncryption *lpEncryptStruct)
{
	PBYTE lpInstructionPointer;
	if(dwPassWord!=0xDEADBAFF)
	{
		_asm
		{
			push eax;
			push ecx;
			mov eax,[ebp+12];//lpEncryptStruct
			mov ecx,[ebp+4];//RetCaller
			mov [eax],ecx;//lpEncryptStruct->dwCodeBegin=RetCaller;
			pop ecx;
			pop eax;
		}
		lpInstructionPointer=lpEncryptStruct->dwCodeBegin;
		lpEncryptStruct->dwPassWord=dwPassWord;
		lpEncryptStruct->dwSizeOfCode=0;
		while(true)
		{
			if(lpInstructionPointer[0]==0x68//PUSH OPCODE
				&&lpInstructionPointer[1]==0xFF
				&&lpInstructionPointer[2]==0xBA
				&&lpInstructionPointer[3]==0xAD
				&&lpInstructionPointer[4]==0xDE)
				break;
			lpInstructionPointer++,lpEncryptStruct->dwSizeOfCode++;
		}
		if(lpEncryptStruct->biOptions&ENCRYPTION_CLEAR_CODE)
		{
			lpEncryptStruct->dwCodeBeginClear=lpEncryptStruct->dwCodeBegin-10;//PUSH DEADBAFF y CALL BeginEncryptCode
			lpEncryptStruct->dwSizeOfCodeClear=lpEncryptStruct->dwSizeOfCode;
			while(true)
			{
				if(lpInstructionPointer[0]==0xE8//CALL OPCODE
					&&*(PDWORD)(lpInstructionPointer+1)==((DWORD)EndEncryptCode-(DWORD)lpInstructionPointer)-5)
					break;
				lpInstructionPointer++,lpEncryptStruct->dwSizeOfCodeClear++;
			}
		}
		if(lpEncryptStruct->biOptions&ENCRYPTION_PAGE_PROTECTIONS)
			VirtualProtect(lpEncryptStruct->dwCodeBegin,lpEncryptStruct->dwSizeOfCode,PAGE_EXECUTE_READWRITE,&lpEncryptStruct->dwOldPageProtection);
		//Descifrado
		RC4((LPSTR)lpEncryptStruct->dwCodeBegin,(LPSTR)&lpEncryptStruct->dwPassWord,lpEncryptStruct->dwSizeOfCode,4);
		if(lpEncryptStruct->biOptions&ENCRYPTION_PAGE_PROTECTIONS)
			VirtualProtect(lpEncryptStruct->dwCodeBegin,lpEncryptStruct->dwSizeOfCode,lpEncryptStruct->dwOldPageProtection,0);
	}
}

_declspec(noinline)void _stdcall EndEncryptCode(CodeEncryption *lpEncryptStruct,DWORD dwDeadBuffer)
{
	UINT i;
	if(lpEncryptStruct->dwPassWord!=dwDeadBuffer)
	{
		if(lpEncryptStruct->biOptions&ENCRYPTION_PAGE_PROTECTIONS)
			VirtualProtect(lpEncryptStruct->dwCodeBegin,lpEncryptStruct->dwSizeOfCode,PAGE_EXECUTE_READWRITE,&lpEncryptStruct->dwOldPageProtection);
		if(lpEncryptStruct->biOptions&ENCRYPTION_CLEAR_CODE)
		{
			for(i=0;i<lpEncryptStruct->dwSizeOfCodeClear;i++)
				lpEncryptStruct->dwCodeBeginClear[i]=0x90;//NOP OPCODE
			//ADD ESP,4
			lpEncryptStruct->dwCodeBeginClear[0]=0x83;
			lpEncryptStruct->dwCodeBeginClear[1]=0xC4;
			lpEncryptStruct->dwCodeBeginClear[2]=0x04;
		}
		else//CifrarOtraVez
			RC4((LPSTR)lpEncryptStruct->dwCodeBegin,(LPSTR)&lpEncryptStruct->dwPassWord,lpEncryptStruct->dwSizeOfCode,4);
		if(lpEncryptStruct->biOptions&ENCRYPTION_PAGE_PROTECTIONS)
			VirtualProtect(lpEncryptStruct->dwCodeBegin,lpEncryptStruct->dwSizeOfCode,lpEncryptStruct->dwOldPageProtection,0);
	}
}

#pragma optimize("",on)