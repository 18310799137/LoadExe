// LoadExe.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
//#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
int main(int argc, _TCHAR* argv[])
{
	//ѡ���ִ���ļ�·��
	WCHAR* filePath=NULL;
	chooseFile(&filePath,0,L"��ѡ��Ҫ�򿪵��ļ�");
	if (filePath==NULL)
	{
		return 0;
	}
	/**
	 * ��ȡ�ļ���������
	 */
	char* fileBuff=NULL;
	size_t fbuffSize =0;
	ReadPEFileToBuffer(filePath,&fileBuff,&fbuffSize);

	if (fileBuff==NULL)
	{
		printf("�ļ����ػ���ʧ��!");
		return 0;
	}
	
	ThePeHeaders  thePeHeaders={0}; 
	thePeHeaders.fileBuff=fileBuff;
	//��FileBuffer�м���PEͷ����Ϣ
	LoadPeHeaders(&thePeHeaders);
	//��¼�ļ���С
	DWORD sizeOfImage = thePeHeaders.OptionalHeader->SizeOfImage;
	DWORD imageBase = thePeHeaders.OptionalHeader->ImageBase;
	char* imageBuff=NULL;
	size_t iBuffSize =0;
	//��FileBufferת��Ϊ�ڴ澵��  ���ͷ��ļ�Buffer
	FileBufferToImageBuffer(&thePeHeaders,&imageBuff,&iBuffSize);
	if (imageBuff==NULL||iBuffSize==0)
	{
		printf("ImageBuff ����ʧ��!");
		return 0;
	}

	//��ImageBuffд��Ӳ���ļ�
	//WriteBufferToFile(iBuffSize,imageBuff);
	//���������ڴ�
	CHAR* vir = (CHAR*)VirtualAlloc((LPVOID)imageBase,sizeOfImage,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if(vir==NULL)
	{
		MessageBoxW(NULL,L"�ڴ�����ʧ��!",L"��Ϣ��ʾ",MB_ICONERROR);
		return 0;
	}

	memcpy(vir,imageBuff,sizeOfImage);
	//�ͷ�ImageBuffer
	free(imageBuff);
	thePeHeaders.fileBuff=vir;
	//��ImageBuff�м���PEͷ����Ϣ
	LoadPeHeaders(&thePeHeaders);
	restoreIBuffImpTable(&thePeHeaders);

	/* �޸��ض�λ�� ������״̬*/
	restoreIbuffRelocationTable(vir);
	DWORD oldProtect=0;
	free(filePath);
	//�����߳� ִ�м��ص�exe��ں���
	HANDLE executeThread =  CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)(vir+thePeHeaders.OptionalHeader->AddressOfEntryPoint),NULL,0,NULL);


	//�ȴ����صĿ�ִ���ļ�ִ����� �����˳�
	WaitForSingleObject(executeThread,INFINITE);
	//getchar();
	return 0;
}

