// LoadExe.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
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
	}
	
	ThePeHeaders  thePeHeaders={0}; 
	thePeHeaders.fileBuff=fileBuff;
	//��FileBuffer�м���PEͷ����Ϣ
	LoadPeHeaders(&thePeHeaders);
	//��¼�ļ���С
	DWORD sizeOfImage = thePeHeaders.OptionalHeader->SizeOfImage;
	char* imageBuff=NULL;
	size_t iBuffSize =0;
	//��FileBufferת��Ϊ�ڴ澵��  ���ͷ��ļ�Buffer
	FileBufferToImageBuffer(&thePeHeaders,&imageBuff,&iBuffSize);
	if (imageBuff==NULL||iBuffSize==0)
	{
		printf("ImageBuff ����ʧ��!");
	}

	//��ImageBuffд��Ӳ���ļ�
	//WriteBufferToFile(iBuffSize,imageBuff);
	//���������ڴ�
	CHAR* vir = (CHAR*)VirtualAlloc(NULL,sizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	if(vir==NULL)
	{
		MessageBoxW(NULL,L"�ڴ�����ʧ��!",L"��Ϣ��ʾ",MB_ICONERROR);
	}

	memcpy(vir,imageBuff,sizeOfImage);
	delete imageBuff;
	thePeHeaders.fileBuff=vir;
	//��ImageBuff�м���PEͷ����Ϣ
	LoadPeHeaders(&thePeHeaders);
	restoreIBuffImpTable(&thePeHeaders);

	/* �޸��ض�λ�� ������״̬*/
	restoreIbuffRelocationTable(vir);
	DWORD oldProtect=0;
	//�޸�ҳ����
	//VirtualProtect(imageBuff,iBuffSize,PAGE_EXECUTE_READWRITE,&oldProtect);
	//�����߳� ִ�м��ص�exe��ں���
	HANDLE executeThread =  CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)(vir+thePeHeaders.OptionalHeader->AddressOfEntryPoint),filePath,0,NULL);


	//�ȴ����صĿ�ִ���ļ�ִ����� �����˳�
	WaitForSingleObject(executeThread,INFINITE);
	//getchar();
	return 0;
}

