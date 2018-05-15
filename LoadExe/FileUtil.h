#pragma once
#include "stdafx.h"

/*定义PE文件头结构体 用于封装PE文件头信息*/
typedef struct PEHeads{
	char* fileBuff;
	IMAGE_DOS_HEADER* DosHeader;
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_FILE_HEADER* FileHeader;
	IMAGE_OPTIONAL_HEADER32*  OptionalHeader;
	IMAGE_SECTION_HEADER* sectionHeader;
}ThePeHeaders,*PThePeHeaders;

/*将文件拉伸*/
void FileBufferToImageBuffer(PThePeHeaders  thePeHeaders, char** _i_buff,size_t* iBuffSize);

/*0读取文件,非0为保存文件*/
void chooseFile(WCHAR** retPath,int operation,PWCHAR hint);

/*提供文件路径,读取文件到内存中*/
void  ReadPEFileToBuffer(WCHAR* filePath,char** fileBuff,size_t* retFileSize);

/*解析PE结构*/
void LoadPeHeaders(PThePeHeaders thePeHeaders);
/*将文件buff的  写入硬盘*/
void WriteBufferToFile(int _ibuff_size, char* _i_buff);