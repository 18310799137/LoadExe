#include "StdAfx.h"

/*解析PE结构*/
void LoadPeHeaders(PThePeHeaders thePeHeaders)
{
	thePeHeaders->DosHeader = (IMAGE_DOS_HEADER*) thePeHeaders->fileBuff;
	thePeHeaders->ntHeader = (IMAGE_NT_HEADERS*)(thePeHeaders->fileBuff + thePeHeaders->DosHeader->e_lfanew);
	thePeHeaders->FileHeader = &(thePeHeaders->ntHeader->FileHeader);
	thePeHeaders->OptionalHeader = &((thePeHeaders->ntHeader)->OptionalHeader);
	char* sect = ((char*)(thePeHeaders->FileHeader) + (thePeHeaders->FileHeader)->SizeOfOptionalHeader) + sizeof(IMAGE_FILE_HEADER);
	thePeHeaders->sectionHeader = (IMAGE_SECTION_HEADER*)sect;
}

/*读取文件到内存中*/
void  ReadPEFileToBuffer(WCHAR* filePath,char** fileBuff,size_t* retFileSize)
{
	//初始化文件指针，读取exe路径
	FILE *fileRead;
	int readAble = _wfopen_s(&fileRead, filePath, L"rb");
	if (readAble) {
		printf(" - file stream not open !");
		*retFileSize=0;
		return;
	}
	wprintf(L"ReadPEFileToBuffer: - %s\n", filePath);
	//获取文件大小
	fseek(fileRead, 0, SEEK_END); //定位到文件末

	long fileSize = ftell(fileRead);
	fseek(fileRead, 0, SEEK_SET);
	//创建文件大小的数组
	char* _f_buff = new char[fileSize];
	*fileBuff = _f_buff;
	*retFileSize=fileSize;
	fread(_f_buff, fileSize, 1,  fileRead);

	//关闭 读入和写出流
	fclose(fileRead);
	return;
}




/**
  *拷贝字符串,从source拷贝到target ,拷贝大小为size
  */
void MemoryCopy(char* source, char* target,int size) {
	char* temp_source = source;
	char* temp_target = target;
	int i = 0;
	while (i < size) {
			*temp_target = *temp_source;
			temp_target++;
			temp_source++;
			i++;
	}
}

/*将硬盘状态转换为内存状态 - 文件在内存中拉伸状态，将文件对齐   称为filebuffer -> imagebuffer*/
void FileBufferToImageBuffer(PThePeHeaders thePeHeaders, char** _i_buff,size_t* iBuffSize)
{
		//节数量
		WORD sectionNum = thePeHeaders->FileHeader->NumberOfSections;
		//计算可选PE头大小
		WORD SizeOfOpeHead = thePeHeaders->FileHeader->SizeOfOptionalHeader;
		//内存对齐大小
		DWORD   _mem_Alignment = thePeHeaders->OptionalHeader->SectionAlignment;
		//程序内存镜像基址
		DWORD  _image_base = thePeHeaders->OptionalHeader->ImageBase;
		//程序内存中入口偏移地址
		DWORD  _image_buffer_oep = thePeHeaders->OptionalHeader->AddressOfEntryPoint;
		//计算_image_buffer所需内存大小
		DWORD  _size_image = thePeHeaders->OptionalHeader->SizeOfImage;

		DWORD  _file_Alignment = thePeHeaders->OptionalHeader->FileAlignment;
		//计算标准PE头大小
		size_t fSize = sizeof(thePeHeaders->FileHeader);

		//转换为指向节数组的 结构体指针
		_IMAGE_SECTION_HEADER* _section_header = thePeHeaders->sectionHeader;

		//取出最后一个节区描述信息
		_IMAGE_SECTION_HEADER _last_section = _section_header[sectionNum - 1];
		/*判断共需要几个内存对齐长度*/
		int _size_ = _last_section.SizeOfRawData / _mem_Alignment;
		_size_=(_size_ + (_last_section.SizeOfRawData % _mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;

		// 所需内存拉伸长度 = 内存偏移+文件对齐长度 
		SIZE_T fileBufferSize = _last_section.VirtualAddress + _size_;
		//取出可选PE头中的 内存镜像大小，如果此值大于计算出的（最后节偏移+内存对齐）则使用此值做为 imagebuffer的大小
		fileBufferSize = _size_image > fileBufferSize ? _size_image : fileBufferSize;
		//创建内存镜像 填充可执行文件
		*_i_buff = new char[fileBufferSize];
		char* _temp_ibuff = *_i_buff;
		//初始化为0
		memset(_temp_ibuff, 0, fileBufferSize);

		//修改文件对齐为内存对齐
		thePeHeaders->OptionalHeader->FileAlignment = _section_header[0].VirtualAddress;
		thePeHeaders->OptionalHeader->SizeOfHeaders = _section_header[0].VirtualAddress;

		for (size_t i = 0; i < sectionNum; i++)
		{
				//取出节在内存中的偏移
				DWORD _vAddr = _section_header[i].VirtualAddress;
				DWORD _point_section = _section_header[i].PointerToRawData;
				DWORD _size_section = _section_header[i].SizeOfRawData;

				if (_size_section % _mem_Alignment != 0) {
						//按内存对齐
						_section_header[i].SizeOfRawData = (_size_section / _mem_Alignment + (_size_section % _mem_Alignment==0?0:1))*_mem_Alignment;
				}
				_section_header[i].PointerToRawData = _vAddr;
				//拷贝节区中 文件偏移和对齐后的大小
				MemoryCopy(thePeHeaders->fileBuff + _point_section, _temp_ibuff + _vAddr, _size_section);
				//oep入口点
				if(_image_buffer_oep>_section_header[i].VirtualAddress && _image_buffer_oep < (_section_header[i].VirtualAddress + _section_header[i].SizeOfRawData))
				{
						printf("入口点OEP在第%d节中,名称为[%s],地址为%0X\n", i + 1, _section_header[i].Name, _image_buffer_oep);
				}
		}
		/*拷贝头部信息， 后面两种方式都可以
		1.取出可选PE头中的 header大小描述 _nt_header->OptionalHeader.SizeOfHeaders
		2.判断第一个节的文件偏移位置 _section_header[0].PointerToRawData
		*/

		DWORD  _headers_offset = _section_header[0].PointerToRawData;
		MemoryCopy(thePeHeaders->fileBuff,_temp_ibuff, _headers_offset);
		*iBuffSize=fileBufferSize;
		//删除FileBuff
		delete thePeHeaders->fileBuff;
}



/*0读取文件,非0为保存文件*/
void chooseFile(WCHAR** retPath,int operation,PWCHAR hint)
{
loop:
	OPENFILENAME optionFile = { 0 };
	TCHAR filePathBuffer[MAX_PATH] = { 0 };//用于接收文件名                                                            
	optionFile.lStructSize = sizeof(OPENFILENAME);//结构体大小                                                           
	optionFile.hwndOwner = NULL;//拥有着窗口句柄，为NULL表示对话框是非模态的，实际应用中一般都要有这个句柄                                            
	optionFile.lpstrFilter = TEXT("选择文件*.*\0*.*\0可执行程序*.exe\0*.exe\0动态链接库文件*.dll\0*.dll\0\0 ");//设置过滤                                
	optionFile.nFilterIndex = 1;//过滤器索引                                                                             
	optionFile.lpstrFile = filePathBuffer;//接收返回的文件名，注意第一个字符需要为NULL                                                    
	optionFile.nMaxFile = sizeof(filePathBuffer);//缓冲区长度                                                               
	optionFile.lpstrInitialDir = NULL;//初始目录为默认                                                                     
	optionFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;//文件、目录必须存在，隐藏只读选项                  

	if (operation) {
		optionFile.lpstrTitle = hint;//使用系统默认标题留空即可 
		if (!GetSaveFileName(&optionFile))//返回0 则用户取消选择
		{
			return;
		}
	}
	else {
		optionFile.lpstrTitle = hint;//使用系统默认标题留空即可
		if (!GetOpenFileName(&optionFile))//返回0 则用户取消选择
		{
			return;
		}
	}
	wchar_t * filePath = new wchar_t[MAX_PATH];
	wmemset(filePath,0,MAX_PATH);
	wcscpy(filePath,filePathBuffer);
	*retPath=filePath;
	return;
}


/*将文件buff的  写入硬盘*/
void WriteBufferToFile(int _ibuff_size, char* _i_buff)
{
	wchar_t* savePath;
	chooseFile(&savePath,1, L"请选择保存路径");
	if (savePath==NULL)
	{
		return;
	}
	wprintf(L"\nwill save file to: \n-> %s \n", savePath);

	FILE* fileWrite;
	int writeAble = _wfopen_s(&fileWrite, savePath, L"wb+");
	if (writeAble) {
		printf("\n- get write stream fail!");
	}
	fwrite(_i_buff, sizeof(char), _ibuff_size, fileWrite);
	//刷新缓冲区
	fflush(fileWrite);

	fclose(fileWrite);
	printf("\n- save file over program will exit! ");
	Sleep(3000);
}