#ifndef ENCRYPT_CLASS_H
#define ENCRYPT_CLASS_H

class cEncryptClass
{
	public:
		bool OpenFile(char* szFileName);
		bool WriteEncryptedFile(char *szFileName);
		bool EncryptBuffer();
		void RelaseBuffer();
	private:
		unsigned long EncryptCode(unsigned char* lpBeginCode,unsigned long dwSizeOfCode);
		unsigned long dwFileSize;
		unsigned char *gFileBuffer;
};

#endif //ENCRYPT_CLASS_H