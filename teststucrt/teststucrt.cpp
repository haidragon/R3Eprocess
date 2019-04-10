//#include "stdafx.h"
//#include <windows.h>
////#include <cstdio>
////#include <winternl.h>
////#include <atlstr.h>
////
////typedef enum _MEMORY_INFORMATION_CLASS
////{
////	MemoryBasicInformation,
////	MemoryWorkingSetList,
////	MemorySectionName
////}MEMORY_INFORMATION_CLASS;
////
////typedef
////NTSTATUS
////(WINAPI *ZWQUERYVIRTUALMEMORY)
////(
////	IN HANDLE ProcessHandle,
////	IN PVOID BaseAddress,
////	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
////	OUT PVOID MemoryInformation,
////	IN ULONG MemoryInformationLength,
////	OUT PULONG ReturnLength OPTIONAL
////	);
////
////
////VOID EnumProcessForModule()
////{
////	ZWQUERYVIRTUALMEMORY QueryVirtualMemoryFunction = NULL;
////	DWORD Index = 0;
////	NTSTATUS NtStatus = 0;
////	MEMORY_BASIC_INFORMATION InfoMation;
////	BYTE Buffer[MAX_PATH * 2 + 4] = { 0 };
////	PUNICODE_STRING SectionName = NULL;
////	DWORD Counter;
////	CString ModuleAddress;
////	CString ModuleName;
////
////	QueryVirtualMemoryFunction = (ZWQUERYVIRTUALMEMORY)
////		::GetProcAddress
////		(
////			GetModuleHandle("ntdll.dll"), //ntdll.dll=地府
////			_T("ZwQueryVirtualMemory") //ZwQueryVirtualMemory=鬼魂名
////		);
////
////	if (QueryVirtualMemoryFunction == NULL)
////	{
////		printf("别瞎TM扯淡啦！");
////	}
////	else
////	{
////		for (Index; Index < 0x80000000; Index += 0x1000)
////		{
////			NtStatus = QueryVirtualMemoryFunction
////			(
////				(HANDLE)-1,
////				(PULONG)Index,
////				MemoryBasicInformation,
////				&InfoMation,
////				sizeof(InfoMation),
////				NULL
////			);
////
////			if (NtStatus >= 0)
////			{
////				if (InfoMation.Type == MEM_IMAGE)
////				{
////					if ((DWORD)InfoMation.AllocationBase == Index)
////					{
////						//        这么做是为什么,因为你不这样过滤,你会得到几千个模块,为什么呢？因为模块之间互相映射,唉,挺乱的,实话说我解释的不太清楚,如果你真的想知道你要花几个星期的时间去深入学习下PE啦,如果你不在意你就按照我的方法做就行啦,他其实就是过滤掉同名的模块。
////						NtStatus = QueryVirtualMemoryFunction
////						(
////							(HANDLE)-1,
////							(PULONG)Index,
////							MemorySectionName,
////							Buffer,
////							//                                             typedef struct MEMORY_SECTION_NAME
////							//                                         {
////							//                                             UNICODE_STRING SectionFileName;
////							//                                             WCHAR       NameBuffer[ANYSIZE_ARRAY];
////							//                                         } *PMEMORY_SECTION_NAME;
////							// 
////							// 但是为什么不用它呢？因为它更底层一些在R3层用它很麻烦,所以放弃它,定义一个和他同样大小的数组,一样可以接收数据,关键在于这个尺寸问题,因为这个结构是在宽字节环境所以我们来计算一下这个结构到底有多大。首先来看第一个成员UNICODE_STRING他的最大值就是MAX_PATH这
////							// 个宏表示260个字节,又因为它是宽字符环境所以就要*2啦,再来看第二个成员WCHAR大家知道这个宏[ANYSIZE_ARRAY]表示2,同样因为UNICODE的关系要*2也就是4,所以这个结构最大不会超过[MAX_PATH*2+4],那么定义这个尺寸的一个数组接收数据就绰绰有余啦,大家知道数组作为参数的时候会自动降级为指针, 怎么样？还好理解吧？继续......
////							sizeof(Buffer),
////							NULL
////						);
////
////						if (NtStatus >= 0)
////						{
////							SectionName = (PUNICODE_STRING)Buffer;
////							ModuleName = SectionName->Buffer;
////							printf("Address:%08X ModuleName %s \n",
////								Index, ModuleName);
////
////							//        ModuleAddress.Format(_T("%x"),Index);
////							//                                             Counter=ListGoodsFilter.InsertItem(Counter,ModuleAddress);
////							//                                             ListGoodsFilter.SetItemText(Counter,1,ModuleName);
////							//                                             这些都是界面编程和字符串的事,我就不解释啦,
////						}
////					}
////				}
////			}
////		}
////	}
////}
////
////
////int  main()
////{
////	EnumProcessForModule();
////	system("pause");
////	return 0;
////}
////#include "sha256.h"
////#include <windows.h>
////#include <tchar.h>
////#include <stack>
////#include <iostream>
////using namespace std;
////typedef struct FILE_CHARACTERISTICS {
////	WORD struct_IMAGE_FILE_RELOCS_STRIPPED : 1;
////	WORD struct_IMAGE_FILE_EXECUTABLE_IMAGE : 1;
////	WORD struct_IMAGE_FILE_LINE_NUMS_STRIPPED : 1;
////	WORD struct_IMAGE_FILE_LOCAL_SYMS_STRIPPED : 1;
////	WORD struct_IMAGE_FILE_AGGRESIVE_WS_TRIM : 1;
////	WORD struct_IMAGE_FILE_LARGE_ADDRESS_AWARE : 1;
////	WORD struct_IMAGE_FILE_BYTES_REVERSED_LO : 1;
////	WORD struct_IMAGE_FILE_32BIT_MACHINE : 1;
////	WORD struct_IMAGE_FILE_DEBUG_STRIPPED : 1;
////	WORD struct_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP : 1;
////	WORD struct_IMAGE_FILE_NET_RUN_FROM_SWAP : 1;
////	WORD struct_IMAGE_FILE_SYSTEM : 1;
////	WORD struct_IMAGE_FILE_DLL : 1;
////	WORD struct_IMAGE_FILE_UP_SYSTEM_ONLY : 1;
////	WORD struct_IMAGE_FILE_BYTES_REVERSED_HI : 1;
////}ST_Characteristics, *PST_Characteristics;
//////定义回调函数
////typedef VOID(*FPTENUMCALLBACK)(LPCTSTR szFullPath, VOID *ptUser);
////std::string Get_PE_Sh256_By_Path(std::string path)
////{
////	//return "NULL";
////	SHA256 sha256;
////	std::string return_string = "NULL";
////	HANDLE hFile;
////	LARGE_INTEGER dwFileSize;
////	BYTE* g_pFileImageBase = NULL;
////	PIMAGE_NT_HEADERS g_pNt = 0;
////	try {
////		hFile = CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
////		//如果是无效的句柄
////		if (hFile == INVALID_HANDLE_VALUE) {
////			//throw  1;
////			goto end;
////		}
////		//获取文件大小
////		GetFileSizeEx(hFile, &dwFileSize);
////		LONGLONG L_fileSize = dwFileSize.QuadPart;
////		//判断文件大小
////		if (L_fileSize < 0x40)
////		{
////			goto end;
////		}
////		//判断文件大小
////		if (L_fileSize > 1024 * 1024 * 10)//50M
////		{
////			goto end;
////		}
////		g_pFileImageBase = new BYTE[dwFileSize.QuadPart]{};
////		DWORD dwRead;
////		if (g_pFileImageBase == NULL)
////		{
////			goto end;
////		}
////		bool bRet = ReadFile(hFile, g_pFileImageBase, 0x40, &dwRead, NULL);
////		if (!bRet)
////		{
////
////			goto end;
////		}
////		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_pFileImageBase;
////		if (pDos->e_magic != IMAGE_DOS_SIGNATURE)//0x5A4D('MZ')
////		{
////			goto end;
////		}
////		bRet = ReadFile(hFile, g_pFileImageBase + 0x40, (pDos->e_lfanew - 0x40 + 4), &dwRead, NULL);
////		if (!bRet)
////		{
////
////			goto end;
////		}
////		g_pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + g_pFileImageBase);
////		if (g_pNt->Signature != IMAGE_NT_SIGNATURE)//0x00004550('PE')
////		{
////			goto end;
////		}
////		DWORD len = 0x40 + (pDos->e_lfanew - 0x40 + 4);
////		bRet = ReadFile(hFile, g_pFileImageBase + len, dwFileSize.QuadPart - len, &dwRead, NULL);
////		if (!bRet)
////		{
////
////			goto end;
////		}
////		PST_Characteristics pst_charter = (PST_Characteristics)&(g_pNt->FileHeader.Characteristics);//EXECUTABLE
////		if ((g_pNt->FileHeader.Characteristics&IMAGE_FILE_EXECUTABLE_IMAGE) != IMAGE_FILE_EXECUTABLE_IMAGE) {
////			goto end;
////		}
////		return_string = sha256((char*)g_pFileImageBase, dwFileSize.QuadPart);
////
////	}
////	catch (std::exception &e) {
////		if (hFile != NULL)
////		{
////			CloseHandle(hFile);
////		}
////		if (g_pFileImageBase != NULL)
////		{
////			delete[] g_pFileImageBase;
////			g_pFileImageBase = NULL;
////		}
////		return return_string;
////	};
////end:
////	if (hFile != NULL)
////	{
////		CloseHandle(hFile);
////	}
////	if (g_pFileImageBase != NULL)
////	{
////		delete[] g_pFileImageBase;
////		g_pFileImageBase = NULL;
////	}
////	return return_string;
////}
////
////
////VOID FilePath(LPCTSTR szFullPath, VOID *ptUser)
////{
////	if (NULL == szFullPath)
////	{
////		return;
////	}
////	//输出所有内容 
////	printf("%s==%s\n", szFullPath, Get_PE_Sh256_By_Path(szFullPath).c_str());
////	 
////
////}
////
////
////BOOL EnumDirectory(LPCTSTR szDirectoryPath, FPTENUMCALLBACK EnumCallBack, VOID *ptUser)
////{
////	if (NULL == szDirectoryPath || NULL == EnumCallBack)
////	{
////		return FALSE;
////	}
////
////	LPTSTR szBaseDirectory = new TCHAR[MAX_PATH * 2];
////	if (NULL == szBaseDirectory)
////	{
////		return FALSE;
////	}
////
////	_tcscpy_s(szBaseDirectory, MAX_PATH * 2, szDirectoryPath);
////	if (_T('\\') != szBaseDirectory[_tcslen(szBaseDirectory) - 1])
////	{
////		_tcscat_s(szBaseDirectory, MAX_PATH * 2, _T("\\"));
////	}
////
////	stack<LPTSTR> skTasklist;
////	skTasklist.push(szBaseDirectory);
////
////	HANDLE hFind = NULL;
////	WIN32_FIND_DATA stFindData;
////
////	//开始操作任务栈
////	while (FALSE == skTasklist.empty())
////	{
////		LPTSTR szTask = skTasklist.top();
////		skTasklist.pop();
////
////		if (NULL == szTask)
////		{
////			continue;
////		}
////
////		_tcscat_s(szTask, MAX_PATH * 2, _T("*"));
////
////		hFind = FindFirstFile(szTask, &stFindData);
////		if (INVALID_HANDLE_VALUE == hFind)
////		{
////			delete[] szTask;
////			continue;
////		}
////
////		do
////		{
////			LPCTSTR szFileName = stFindData.cFileName;
////			if (0 == _tcscmp(szFileName, _T(".")) || 0 == _tcscmp(szFileName, _T("..")))
////			{
////				continue;
////			}
////
////			LPTSTR szFullFileName = new TCHAR[MAX_PATH * 2];
////			memset(szFullFileName, 0, sizeof(TCHAR) * MAX_PATH * 2);
////
////			_tcscpy_s(szFullFileName, MAX_PATH * 2, szTask);
////			_tcscpy_s(&(szFullFileName[_tcslen(szFullFileName) - 1]), MAX_PATH * 2, szFileName);
////			if (stFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
////			{
////				if (_T('\\') != szFullFileName[_tcslen(szFullFileName) - 1])
////				{
////					_tcscat_s(szFullFileName, MAX_PATH * 2, _T("\\"));
////				}
////				skTasklist.push(szFullFileName);
////			}
////			else
////			{
////				EnumCallBack(szFullFileName, ptUser);		//调用回调函数
////				delete[] szFullFileName;
////			}
////		} while (FindNextFile(hFind, &stFindData));
////
////		delete[] szTask;
////		FindClose(hFind);
////	}
////	return TRUE;
////}
//#include "stdio.h"
//
//typedef DWORD(WINAPI *ZWQUERYSYSTEMINFORMATION)(DWORD, PVOID, DWORD, PDWORD);
//typedef unsigned long ULONG;
//typedef ULONG *PULONG;
//typedef unsigned short USHORT;
//typedef USHORT *PUSHORT;
//typedef unsigned char UCHAR;
//typedef UCHAR *PUCHAR;
//typedef struct _UNICODE_STRING {
//	USHORT Length;
//	USHORT MaximumLength;
//	PWSTR  Buffer;
//} UNICODE_STRING;
//typedef struct _SYSTEM_PROCESS_INFORMATION {
//	DWORD   NextEntryDelta;
//	DWORD   ThreadCount;
//	DWORD   Reserved1[6];
//	FILETIME  ftCreateTime;
//	FILETIME  ftUserTime;
//	FILETIME  ftKernelTime;
//	UNICODE_STRING ProcessName;      // 进程名.
//	DWORD   BasePriority;
//	DWORD   ProcessId;
//	DWORD   InheritedFromProcessId;
//	DWORD   HandleCount;
//	DWORD   Reserved2[2];
//	DWORD   VmCounters;
//	DWORD   dCommitCharge;
//	PVOID   ThreadInfos[1];
//} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
//
//#define SystemProcessesAndThreadsInformation 5
//
//void main2()
//{
//	HMODULE hNtDLL = GetModuleHandle("ntdll.dll");
//	if (!hNtDLL)
//		return;
//
//	ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)
//		GetProcAddress(hNtDLL, "ZwQuerySystemInformation");
//
//	ULONG cbBuffer = 0x200000;  //默认
//	LPVOID pBuffer = NULL;
//	ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, NULL, 0, &cbBuffer);//获取大小
//	pBuffer = malloc(cbBuffer);
//
//	if (pBuffer == NULL)
//		return;
//
//	ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, pBuffer, cbBuffer, NULL);
//	PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
//
//	for (;;)
//	{
//		printf("ProcessID: %d (%ls)\n", pInfo->ProcessId, pInfo->ProcessName.Buffer);
//
//		if (pInfo->NextEntryDelta == 0)
//			break;
//
//		// 查找下一个进程的结构地址.
//		pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryDelta);
//	}
//
//	free(pBuffer);
//	getchar();  //暂停.
//}
//
////int main(int argc, char* argv[]) {
////	while (1)
////	{
////		BOOL bError = EnumDirectory("C:", FilePath, NULL);
////	}
////	return 1;
////}
