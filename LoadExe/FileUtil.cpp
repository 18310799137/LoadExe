#include "StdAfx.h"

/*����PE�ṹ*/
void LoadPeHeaders(PThePeHeaders thePeHeaders)
{
	thePeHeaders->DosHeader = (IMAGE_DOS_HEADER*) thePeHeaders->fileBuff;
	thePeHeaders->ntHeader = (IMAGE_NT_HEADERS*)(thePeHeaders->fileBuff + thePeHeaders->DosHeader->e_lfanew);
	thePeHeaders->FileHeader = &(thePeHeaders->ntHeader->FileHeader);
	thePeHeaders->OptionalHeader = &((thePeHeaders->ntHeader)->OptionalHeader);
	char* sect = ((char*)(thePeHeaders->FileHeader) + (thePeHeaders->FileHeader)->SizeOfOptionalHeader) + sizeof(IMAGE_FILE_HEADER);
	thePeHeaders->sectionHeader = (IMAGE_SECTION_HEADER*)sect;
}

/*��ȡ�ļ����ڴ���*/
void  ReadPEFileToBuffer(WCHAR* filePath,char** fileBuff,size_t* retFileSize)
{
	//��ʼ���ļ�ָ�룬��ȡexe·��
	FILE *fileRead;
	int readAble = _wfopen_s(&fileRead, filePath, L"rb");
	if (readAble) {
		printf(" - file stream not open !");
		*retFileSize=0;
		return;
	}
	wprintf(L"ReadPEFileToBuffer: - %s\n", filePath);
	//��ȡ�ļ���С
	fseek(fileRead, 0, SEEK_END); //��λ���ļ�ĩ

	long fileSize = ftell(fileRead);
	fseek(fileRead, 0, SEEK_SET);
	//�����ļ���С������
	char* _f_buff = new char[fileSize];
	*fileBuff = _f_buff;
	*retFileSize=fileSize;
	fread(_f_buff, fileSize, 1,  fileRead);

	//�ر� �����д����
	fclose(fileRead);
	return;
}




/**
  *�����ַ���,��source������target ,������СΪsize
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

/*��Ӳ��״̬ת��Ϊ�ڴ�״̬ - �ļ����ڴ�������״̬�����ļ�����   ��Ϊfilebuffer -> imagebuffer*/
void FileBufferToImageBuffer(PThePeHeaders thePeHeaders, char** _i_buff,size_t* iBuffSize)
{
		//������
		WORD sectionNum = thePeHeaders->FileHeader->NumberOfSections;
		//�����ѡPEͷ��С
		WORD SizeOfOpeHead = thePeHeaders->FileHeader->SizeOfOptionalHeader;
		//�ڴ�����С
		DWORD   _mem_Alignment = thePeHeaders->OptionalHeader->SectionAlignment;
		//�����ڴ澵���ַ
		DWORD  _image_base = thePeHeaders->OptionalHeader->ImageBase;
		//�����ڴ������ƫ�Ƶ�ַ
		DWORD  _image_buffer_oep = thePeHeaders->OptionalHeader->AddressOfEntryPoint;
		//����_image_buffer�����ڴ��С
		DWORD  _size_image = thePeHeaders->OptionalHeader->SizeOfImage;

		DWORD  _file_Alignment = thePeHeaders->OptionalHeader->FileAlignment;
		//�����׼PEͷ��С
		size_t fSize = sizeof(thePeHeaders->FileHeader);

		//ת��Ϊָ�������� �ṹ��ָ��
		_IMAGE_SECTION_HEADER* _section_header = thePeHeaders->sectionHeader;

		//ȡ�����һ������������Ϣ
		_IMAGE_SECTION_HEADER _last_section = _section_header[sectionNum - 1];
		/*�жϹ���Ҫ�����ڴ���볤��*/
		int _size_ = _last_section.SizeOfRawData / _mem_Alignment;
		_size_=(_size_ + (_last_section.SizeOfRawData % _mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;

		// �����ڴ����쳤�� = �ڴ�ƫ��+�ļ����볤�� 
		SIZE_T fileBufferSize = _last_section.VirtualAddress + _size_;
		//ȡ����ѡPEͷ�е� �ڴ澵���С�������ֵ���ڼ�����ģ�����ƫ��+�ڴ���룩��ʹ�ô�ֵ��Ϊ imagebuffer�Ĵ�С
		fileBufferSize = _size_image > fileBufferSize ? _size_image : fileBufferSize;
		//�����ڴ澵�� ����ִ���ļ�
		*_i_buff = new char[fileBufferSize];
		char* _temp_ibuff = *_i_buff;
		//��ʼ��Ϊ0
		memset(_temp_ibuff, 0, fileBufferSize);

		//�޸��ļ�����Ϊ�ڴ����
		thePeHeaders->OptionalHeader->FileAlignment = _section_header[0].VirtualAddress;
		thePeHeaders->OptionalHeader->SizeOfHeaders = _section_header[0].VirtualAddress;

		for (size_t i = 0; i < sectionNum; i++)
		{
				//ȡ�������ڴ��е�ƫ��
				DWORD _vAddr = _section_header[i].VirtualAddress;
				DWORD _point_section = _section_header[i].PointerToRawData;
				DWORD _size_section = _section_header[i].SizeOfRawData;

				if (_size_section % _mem_Alignment != 0) {
						//���ڴ����
						_section_header[i].SizeOfRawData = (_size_section / _mem_Alignment + (_size_section % _mem_Alignment==0?0:1))*_mem_Alignment;
				}
				_section_header[i].PointerToRawData = _vAddr;
				//���������� �ļ�ƫ�ƺͶ����Ĵ�С
				MemoryCopy(thePeHeaders->fileBuff + _point_section, _temp_ibuff + _vAddr, _size_section);
				//oep��ڵ�
				if(_image_buffer_oep>_section_header[i].VirtualAddress && _image_buffer_oep < (_section_header[i].VirtualAddress + _section_header[i].SizeOfRawData))
				{
						printf("��ڵ�OEP�ڵ�%d����,����Ϊ[%s],��ַΪ%0X\n", i + 1, _section_header[i].Name, _image_buffer_oep);
				}
		}
		/*����ͷ����Ϣ�� �������ַ�ʽ������
		1.ȡ����ѡPEͷ�е� header��С���� _nt_header->OptionalHeader.SizeOfHeaders
		2.�жϵ�һ���ڵ��ļ�ƫ��λ�� _section_header[0].PointerToRawData
		*/

		DWORD  _headers_offset = _section_header[0].PointerToRawData;
		MemoryCopy(thePeHeaders->fileBuff,_temp_ibuff, _headers_offset);
		*iBuffSize=fileBufferSize;
		//ɾ��FileBuff
		delete thePeHeaders->fileBuff;
}



/*0��ȡ�ļ�,��0Ϊ�����ļ�*/
void chooseFile(WCHAR** retPath,int operation,PWCHAR hint)
{
loop:
	OPENFILENAME optionFile = { 0 };
	TCHAR filePathBuffer[MAX_PATH] = { 0 };//���ڽ����ļ���                                                            
	optionFile.lStructSize = sizeof(OPENFILENAME);//�ṹ���С                                                           
	optionFile.hwndOwner = NULL;//ӵ���Ŵ��ھ����ΪNULL��ʾ�Ի����Ƿ�ģ̬�ģ�ʵ��Ӧ����һ�㶼Ҫ��������                                            
	optionFile.lpstrFilter = TEXT("ѡ���ļ�*.*\0*.*\0��ִ�г���*.exe\0*.exe\0��̬���ӿ��ļ�*.dll\0*.dll\0\0 ");//���ù���                                
	optionFile.nFilterIndex = 1;//����������                                                                             
	optionFile.lpstrFile = filePathBuffer;//���շ��ص��ļ�����ע���һ���ַ���ҪΪNULL                                                    
	optionFile.nMaxFile = sizeof(filePathBuffer);//����������                                                               
	optionFile.lpstrInitialDir = NULL;//��ʼĿ¼ΪĬ��                                                                     
	optionFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;//�ļ���Ŀ¼������ڣ�����ֻ��ѡ��                  

	if (operation) {
		optionFile.lpstrTitle = hint;//ʹ��ϵͳĬ�ϱ������ռ��� 
		if (!GetSaveFileName(&optionFile))//����0 ���û�ȡ��ѡ��
		{
			return;
		}
	}
	else {
		optionFile.lpstrTitle = hint;//ʹ��ϵͳĬ�ϱ������ռ���
		if (!GetOpenFileName(&optionFile))//����0 ���û�ȡ��ѡ��
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


/*���ļ�buff��  д��Ӳ��*/
void WriteBufferToFile(int _ibuff_size, char* _i_buff)
{
	wchar_t* savePath;
	chooseFile(&savePath,1, L"��ѡ�񱣴�·��");
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
	//ˢ�»�����
	fflush(fileWrite);

	fclose(fileWrite);
	printf("\n- save file over program will exit! ");
	Sleep(3000);
}