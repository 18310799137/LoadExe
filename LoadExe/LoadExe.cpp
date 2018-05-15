// LoadExe.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
int main(int argc, _TCHAR* argv[])
{
	//选择可执行文件路径
	WCHAR* filePath=NULL;
	chooseFile(&filePath,0,L"请选择要打开的文件");
	if (filePath==NULL)
	{
		return 0;
	}
	/**
	 * 读取文件到缓存中
	 */
	char* fileBuff=NULL;
	size_t fbuffSize =0;
	ReadPEFileToBuffer(filePath,&fileBuff,&fbuffSize);

	if (fileBuff==NULL)
	{
		printf("文件加载缓存失败!");
	}
	
	ThePeHeaders  thePeHeaders={0}; 
	thePeHeaders.fileBuff=fileBuff;
	//在FileBuffer中加载PE头部信息
	LoadPeHeaders(&thePeHeaders);

	char* imageBuff=NULL;
	size_t iBuffSize =0;
	FileBufferToImageBuffer(&thePeHeaders,&imageBuff,&iBuffSize);
	if (imageBuff==NULL||iBuffSize==0)
	{
		printf("ImageBuff 加载失败!");
	}

	//将ImageBuff写入硬盘文件
	//WriteBufferToFile(iBuffSize,imageBuff);
	thePeHeaders.fileBuff=imageBuff;
	//在ImageBuff中加载PE头部信息
	LoadPeHeaders(&thePeHeaders);
	restoreIBuffImpTable(&thePeHeaders);

	/* 修复重定位表 拉伸后的状态*/
	restoreIbuffRelocationTable(imageBuff);
	DWORD oldProtect=0;
	//修改页属性
	VirtualProtect(imageBuff,iBuffSize,PAGE_EXECUTE_READWRITE,&oldProtect);
	//创建线程 执行加载的exe入口函数
	HANDLE executeThread =  CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)(imageBuff+thePeHeaders.OptionalHeader->AddressOfEntryPoint),filePath,0,NULL);


	//等待加载的可执行文件执行完毕 程序退出
	WaitForSingleObject(executeThread,INFINITE);
	//getchar();
	return 0;
}

