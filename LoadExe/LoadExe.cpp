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

	char* imageBuff=NULL;
	size_t iBuffSize =0;
	FileBufferToImageBuffer(&thePeHeaders,&imageBuff,&iBuffSize);
	if (imageBuff==NULL||iBuffSize==0)
	{
		printf("ImageBuff ����ʧ��!");
	}

	//��ImageBuffд��Ӳ���ļ�
	//WriteBufferToFile(iBuffSize,imageBuff);
	thePeHeaders.fileBuff=imageBuff;
	//��ImageBuff�м���PEͷ����Ϣ
	LoadPeHeaders(&thePeHeaders);
	restoreIBuffImpTable(&thePeHeaders);

	/* �޸��ض�λ�� ������״̬*/
	restoreIbuffRelocationTable(imageBuff);
	DWORD oldProtect=0;
	//�޸�ҳ����
	VirtualProtect(imageBuff,iBuffSize,PAGE_EXECUTE_READWRITE,&oldProtect);
	//�����߳� ִ�м��ص�exe��ں���
	HANDLE executeThread =  CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)(imageBuff+thePeHeaders.OptionalHeader->AddressOfEntryPoint),filePath,0,NULL);


	//�ȴ����صĿ�ִ���ļ�ִ����� �����˳�
	WaitForSingleObject(executeThread,INFINITE);
	//getchar();
	return 0;
}

