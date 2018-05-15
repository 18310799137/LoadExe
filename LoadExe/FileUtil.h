#pragma once
#include "stdafx.h"

/*����PE�ļ�ͷ�ṹ�� ���ڷ�װPE�ļ�ͷ��Ϣ*/
typedef struct PEHeads{
	char* fileBuff;
	IMAGE_DOS_HEADER* DosHeader;
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_FILE_HEADER* FileHeader;
	IMAGE_OPTIONAL_HEADER32*  OptionalHeader;
	IMAGE_SECTION_HEADER* sectionHeader;
}ThePeHeaders,*PThePeHeaders;

/*���ļ�����*/
void FileBufferToImageBuffer(PThePeHeaders  thePeHeaders, char** _i_buff,size_t* iBuffSize);

/*0��ȡ�ļ�,��0Ϊ�����ļ�*/
void chooseFile(WCHAR** retPath,int operation,PWCHAR hint);

/*�ṩ�ļ�·��,��ȡ�ļ����ڴ���*/
void  ReadPEFileToBuffer(WCHAR* filePath,char** fileBuff,size_t* retFileSize);

/*����PE�ṹ*/
void LoadPeHeaders(PThePeHeaders thePeHeaders);
/*���ļ�buff��  д��Ӳ��*/
void WriteBufferToFile(int _ibuff_size, char* _i_buff);