#include "StdAfx.h"

/**
 * �޸������
 */
void restoreIBuffImpTable(PThePeHeaders  thePeHeaders)
{
	char* pData = thePeHeaders->fileBuff;
	IMAGE_OPTIONAL_HEADER*  opHeader= thePeHeaders->OptionalHeader;
	//��ȡ������ַ
	IMAGE_IMPORT_DESCRIPTOR*   impTable = (IMAGE_IMPORT_DESCRIPTOR*)(pData + opHeader->DataDirectory[1].VirtualAddress);
	DWORD oldPro = 0;
	//	BOOL IsSuccess = VirtualProtect((LPVOID)pData, opHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldPro);
	if (impTable->TimeDateStamp == 0)
	{
		if (impTable->OriginalFirstThunk == 0)
		{
			MessageBoxA(NULL, "û�е����", "��Ϣ��ʾ", MB_OK);
			return;
		}
		//��ӡ��Ϣʹ��
		char  buff[100] = { 0 };
		//ѭ��������ṹ�壬������Ҫ���õ�����PEģ�� �жϽṹ���
		while (impTable->OriginalFirstThunk != 0)
		{
			_IMAGE_THUNK_DATA32*  IntThunkData = (_IMAGE_THUNK_DATA32*)(pData + impTable->OriginalFirstThunk);
			_IMAGE_THUNK_DATA32*  IatThunkData = (_IMAGE_THUNK_DATA32*)(pData + impTable->FirstThunk);

			//���������  ����DLL���Ƽ���DLL
			HMODULE dllModule = LoadLibraryA(pData+impTable->Name);


			//�ж�INT��������
			while (IntThunkData->u1.Ordinal != 0)
			{
				//��ȡ����������
				DWORD numOrName = IntThunkData->u1.Ordinal;
				//ȡ����� �ж�Ϊ��ŵ��뻹�����ֵ���
				DWORD flag = numOrName & 0x80000000;

				PDWORD addTemp = (PDWORD)IatThunkData;
				if (flag == 0x80000000)
				{
					DWORD number = numOrName & 0x7FFFFFFF;
					//��ŵ���
					//	sprintf_s(buff, 100, "OriginalFirstThunk - �������Ϊ:%d(%XH)   FirstThunk - %X  ", number, number, iatFunNameAddr);
					//�޸�������а���ŵ���ĺ�����ַ
					DWORD funAddr = (DWORD)GetProcAddress(dllModule, MAKEINTRESOURCEA(number));
					*addTemp = funAddr;
					char sss[200] = { 0 };
					sprintf_s(sss, 200, "number:%x funAddr:%x dllName:%s", number, funAddr, pData + impTable->Name);
					printf("����ŵ��룺%s\n",sss);
				}
				else {
					CHAR*  namefoaAddr =  numOrName + pData;
					IMAGE_IMPORT_BY_NAME* impByName = (IMAGE_IMPORT_BY_NAME*)namefoaAddr;
					//�޸�������а����ֵ���ĺ�����ַ
					DWORD funAddr = (DWORD)GetProcAddress(dllModule, (LPCSTR)impByName->Name);
					*addTemp = funAddr;
					char sss[200] = { 0 };
					sprintf_s(sss, 200,  "Name:%s funAddr:%x dllName:%s", impByName->Name, funAddr, pData + impTable->Name);
					printf("�����ֵ��룺%s\n",sss);
				}

				//ָ����һ��INT��
				IntThunkData++;
				//ָ����һ��IAT��
				IatThunkData++;
			}
			//ָ����һ������� �ṹ��
			impTable++;
		}
		/*MessageBoxA(NULL, "�����ģ���������", "��Ϣ��ʾ", MB_OK);*/
	}
	else {
		MessageBoxA(NULL, "ʹ�ð󶨵����", "��Ϣ��ʾ", MB_OK);
	}
}





/* �޸��ض�λ�� ������״̬*/
void restoreIbuffRelocationTable(char * _i_buff)
{

	_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_i_buff;
	_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_i_buff + _dos->e_lfanew);
	IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
	//�����ض�λ���ָ��,Ҳ���ض�λ��������׸����ַ
	IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_i_buff +   _data_table[5].VirtualAddress );


	DWORD  _image_base = _nt->OptionalHeader.ImageBase;
	//ImageBase ��ƫ����
	DWORD   _image_base_offset = ((DWORD)_i_buff - _image_base);
	//�����ض�λ��Ŀ�����
	int _lump_count = 0;
	while (_first_relocation_table_addr->SizeOfBlock>0x10 && _first_relocation_table_addr->VirtualAddress)
	{
		printf("�ض�λ���%d�鿪ʼ========================\n", ++_lump_count);
		DWORD block = _first_relocation_table_addr->SizeOfBlock;
		DWORD _virtual_addr = _first_relocation_table_addr->VirtualAddress;
		//����ÿ���ض�λ���е�ÿ�������������ĵ�ַ����
		size_t _addr_count = (block - sizeof(block) - sizeof(_virtual_addr)) / sizeof(WORD);
		printf("�����й� %d����ַ\n", _addr_count);
		//����һ����ʱָ�����ÿ�����еĵ�ַ
		WORD* _temp_relocation = (WORD*)_first_relocation_table_addr;
		_temp_relocation += 4;
		for (size_t i = 0; i < _addr_count; i++)
		{
			WORD _relocation_addr_ = *_temp_relocation;
			//ȡ������λ��ֵ���������λ��������������Ч�ĵ�ַ
			int _valid_flag = _relocation_addr_ >> 12;
			if (_valid_flag == 3)
			{
				DWORD valid_relocation_addr = _virtual_addr + (_relocation_addr_ & 0x0fff);
				char* _changeAddr = _i_buff +  valid_relocation_addr ;
				DWORD _changeAddrNum = *((DWORD*)_changeAddr);
				*((DWORD*)_changeAddr) = _changeAddrNum + _image_base_offset;

				printf("��Ч��ַ%2d: %XH Base��ֵΪ:%XH \n", i + 1, valid_relocation_addr, _virtual_addr);
			}
			else {
				printf("��Ч��ַ%2d: -  \t\t - \n", i + 1);
			}
			_temp_relocation += 1;
		}
		//ָ����һ���ض�λ��ṹ
		_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

		printf("�ض�λ���%d�����========================\n", _lump_count);
	}
	printf("�ض�λ����%d��", _lump_count);
}