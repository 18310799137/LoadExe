#include "StdAfx.h"

/**
 * 修复导入表
 */
void restoreIBuffImpTable(PThePeHeaders  thePeHeaders)
{
	char* pData = thePeHeaders->fileBuff;
	IMAGE_OPTIONAL_HEADER*  opHeader= thePeHeaders->OptionalHeader;
	//获取导入表地址
	IMAGE_IMPORT_DESCRIPTOR*   impTable = (IMAGE_IMPORT_DESCRIPTOR*)(pData + opHeader->DataDirectory[1].VirtualAddress);
	DWORD oldPro = 0;
	//	BOOL IsSuccess = VirtualProtect((LPVOID)pData, opHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldPro);
	if (impTable->TimeDateStamp == 0)
	{
		if (impTable->OriginalFirstThunk == 0)
		{
			MessageBoxA(NULL, "没有导入表", "信息提示", MB_OK);
			return;
		}
		//打印信息使用
		char  buff[100] = { 0 };
		//循环导出表结构体，遍历所要调用的所有PE模块 判断结构标记
		while (impTable->OriginalFirstThunk != 0)
		{
			_IMAGE_THUNK_DATA32*  IntThunkData = (_IMAGE_THUNK_DATA32*)(pData + impTable->OriginalFirstThunk);
			_IMAGE_THUNK_DATA32*  IatThunkData = (_IMAGE_THUNK_DATA32*)(pData + impTable->FirstThunk);

			//遍历导入表  根据DLL名称加载DLL
			HMODULE dllModule = LoadLibraryA(pData+impTable->Name);


			//判断INT表结束标记
			while (IntThunkData->u1.Ordinal != 0)
			{
				//获取导入表的名字
				DWORD numOrName = IntThunkData->u1.Ordinal;
				//取出标记 判断为序号导入还是名字导入
				DWORD flag = numOrName & 0x80000000;

				PDWORD addTemp = (PDWORD)IatThunkData;
				if (flag == 0x80000000)
				{
					DWORD number = numOrName & 0x7FFFFFFF;
					//序号导入
					//	sprintf_s(buff, 100, "OriginalFirstThunk - 导入序号为:%d(%XH)   FirstThunk - %X  ", number, number, iatFunNameAddr);
					//修复导入表中按序号导入的函数地址
					DWORD funAddr = (DWORD)GetProcAddress(dllModule, MAKEINTRESOURCEA(number));
					*addTemp = funAddr;
					char sss[200] = { 0 };
					sprintf_s(sss, 200, "number:%x funAddr:%x dllName:%s", number, funAddr, pData + impTable->Name);
					printf("按序号导入：%s\n",sss);
				}
				else {
					CHAR*  namefoaAddr =  numOrName + pData;
					IMAGE_IMPORT_BY_NAME* impByName = (IMAGE_IMPORT_BY_NAME*)namefoaAddr;
					//修复导入表中按名字导入的函数地址
					DWORD funAddr = (DWORD)GetProcAddress(dllModule, (LPCSTR)impByName->Name);
					*addTemp = funAddr;
					char sss[200] = { 0 };
					sprintf_s(sss, 200,  "Name:%s funAddr:%x dllName:%s", impByName->Name, funAddr, pData + impTable->Name);
					printf("按名字导入：%s\n",sss);
				}

				//指向下一个INT表
				IntThunkData++;
				//指向下一个IAT表
				IatThunkData++;
			}
			//指向下一个导入表 结构体
			impTable++;
		}
		/*MessageBoxA(NULL, "导入表模块遍历结束", "信息提示", MB_OK);*/
	}
	else {
		MessageBoxA(NULL, "使用绑定导入表", "信息提示", MB_OK);
	}
}





/* 修复重定位表 拉伸后的状态*/
void restoreIbuffRelocationTable(char * _i_buff)
{

	_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_i_buff;
	_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_i_buff + _dos->e_lfanew);
	IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
	//创建重定位表的指针,也是重定位表数组的首个表地址
	IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_i_buff +   _data_table[5].VirtualAddress );


	DWORD  _image_base = _nt->OptionalHeader.ImageBase;
	//ImageBase 的偏移量
	DWORD   _image_base_offset = ((DWORD)_i_buff - _image_base);
	//计算重定位表的块数量
	int _lump_count = 0;
	while (_first_relocation_table_addr->SizeOfBlock>0x10 && _first_relocation_table_addr->VirtualAddress)
	{
		printf("重定位表第%d块开始========================\n", ++_lump_count);
		DWORD block = _first_relocation_table_addr->SizeOfBlock;
		DWORD _virtual_addr = _first_relocation_table_addr->VirtualAddress;
		//计算每个重定位表中的每个块中所包含的地址数量
		size_t _addr_count = (block - sizeof(block) - sizeof(_virtual_addr)) / sizeof(WORD);
		printf("本块中共 %d个地址\n", _addr_count);
		//创建一个临时指针遍历每个块中的地址
		WORD* _temp_relocation = (WORD*)_first_relocation_table_addr;
		_temp_relocation += 4;
		for (size_t i = 0; i < _addr_count; i++)
		{
			WORD _relocation_addr_ = *_temp_relocation;
			//取出高四位的值，如果高四位等于三，则是有效的地址
			int _valid_flag = _relocation_addr_ >> 12;
			if (_valid_flag == 3)
			{
				DWORD valid_relocation_addr = _virtual_addr + (_relocation_addr_ & 0x0fff);
				char* _changeAddr = _i_buff +  valid_relocation_addr ;
				DWORD _changeAddrNum = *((DWORD*)_changeAddr);
				*((DWORD*)_changeAddr) = _changeAddrNum + _image_base_offset;

				printf("有效地址%2d: %XH Base的值为:%XH \n", i + 1, valid_relocation_addr, _virtual_addr);
			}
			else {
				printf("无效地址%2d: -  \t\t - \n", i + 1);
			}
			_temp_relocation += 1;
		}
		//指向下一个重定位表结构
		_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

		printf("重定位表第%d块结束========================\n", _lump_count);
	}
	printf("重定位表共有%d块", _lump_count);
}