// LoadExe.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
//#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
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
		return 0;
	}
	
	ThePeHeaders  thePeHeaders={0}; 
	thePeHeaders.fileBuff=fileBuff;
	//在FileBuffer中加载PE头部信息
	LoadPeHeaders(&thePeHeaders);
	//记录文件大小
	DWORD sizeOfImage = thePeHeaders.OptionalHeader->SizeOfImage;
	DWORD imageBase = thePeHeaders.OptionalHeader->ImageBase;
	char* imageBuff=NULL;
	size_t iBuffSize =0;
	//将FileBuffer转换为内存镜像  并释放文件Buffer
	FileBufferToImageBuffer(&thePeHeaders,&imageBuff,&iBuffSize);
	if (imageBuff==NULL||iBuffSize==0)
	{
		printf("ImageBuff 加载失败!");
		return 0;
	}

	//将ImageBuff写入硬盘文件
	//WriteBufferToFile(iBuffSize,imageBuff);
	//申请虚拟内存
	CHAR* vir = (CHAR*)VirtualAlloc((LPVOID)imageBase,sizeOfImage,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if(vir==NULL)
	{
		MessageBoxW(NULL,L"内存申请失败!",L"信息提示",MB_ICONERROR);
		return 0;
	}

	memcpy(vir,imageBuff,sizeOfImage);
	//释放ImageBuffer
	free(imageBuff);
	thePeHeaders.fileBuff=vir;
	//在ImageBuff中加载PE头部信息
	LoadPeHeaders(&thePeHeaders);
	restoreIBuffImpTable(&thePeHeaders);

	/* 修复重定位表 拉伸后的状态*/
	restoreIbuffRelocationTable(vir);
	DWORD oldProtect=0;
	free(filePath);
	//创建线程 执行加载的exe入口函数
	HANDLE executeThread =  CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)(vir+thePeHeaders.OptionalHeader->AddressOfEntryPoint),NULL,0,NULL);


	//等待加载的可执行文件执行完毕 程序退出
	WaitForSingleObject(executeThread,INFINITE);
	//getchar();
	return 0;
}

