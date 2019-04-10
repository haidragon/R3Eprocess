//#include <ntsecapi.h>
#include <windows.h>
#include <iostream>
using namespace std;
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
typedef NTSTATUS(WINAPI *ZWQUERYSYSTEMINFORMATION)(DWORD, PVOID, DWORD, PDWORD);
typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation,
} OBJECT_INFORMATION_CLASS;
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef NTSTATUS(NTAPI *NTQUERYOBJECT)(
	HANDLE Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS( *NtQueryObject)(
	HANDLE                   Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID                    ObjectInformation,
	ULONG                    ObjectInformationLength,
	PULONG                   ReturnLength
);
typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
}SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
HMODULE hNtDLL;
typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[1];
}SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
#define SystemHandleInformation 0x10  // 16
LPVOID GetSystemProcessHandleInfo()
{
	ULONG cbBuffer = 0x4000;
	LPVOID pBuffer = NULL;
	NTSTATUS sts;
	do
	{
		pBuffer = malloc(cbBuffer);
		if (pBuffer == NULL)
		{
			cout << "error alloc memory:" << GetLastError() << endl;
			return NULL;
		}
		memset(pBuffer, 0, cbBuffer);
		hNtDLL = GetModuleHandle("ntdll.dll");
		if (!hNtDLL)
			return 0;

		ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)
			GetProcAddress(hNtDLL, "ZwQuerySystemInformation");
		sts = ZwQuerySystemInformation(SystemHandleInformation,pBuffer, cbBuffer, NULL);
		if (sts == STATUS_INFO_LENGTH_MISMATCH)
		{
			free(pBuffer);
			pBuffer = NULL;
			cbBuffer = cbBuffer + 0x4000; // 初始分配的空间不足+4000h
		}
	} while (sts == STATUS_INFO_LENGTH_MISMATCH);
	return pBuffer;
}
void EnumObjInfo(LPVOID pBuffer, DWORD pid)
{
	char szType[128] = { 0 };
	char szName[512] = { 0 };
	DWORD dwFlags = 0;
	POBJECT_NAME_INFORMATION pNameInfo;
	POBJECT_NAME_INFORMATION pNameType;
	PSYSTEM_HANDLE_INFORMATION_EX pInfo = (PSYSTEM_HANDLE_INFORMATION_EX)pBuffer;
	ULONG OldPID = 0;
	for (DWORD i = 0; i < pInfo->NumberOfHandles; i++)
	{
		if (OldPID != pInfo->Information[i].ProcessId)
		{
			if (pInfo->Information[i].ProcessId == pid)
			{

				HANDLE newHandle;
				NtQueryObject p_NtQueryObject=(NtQueryObject)GetProcAddress(hNtDLL, "NtQueryObject");
			    if (p_NtQueryObject==NULL)
			    {
					return;
			    }
				DuplicateHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pInfo->Information[i].ProcessId), (HANDLE)pInfo->Information[i].Handle, GetCurrentProcess(), &newHandle, DUPLICATE_SAME_ACCESS, FALSE, DUPLICATE_SAME_ACCESS);
				NTSTATUS status1 = p_NtQueryObject(newHandle, ObjectNameInformation, szName, 512, &dwFlags);
				NTSTATUS status2 = p_NtQueryObject(newHandle, ObjectTypeInformation, szType, 128, &dwFlags);
				if (strcmp(szName, "") && strcmp(szType, "") && status1 != 0xc0000008 && status2 != 0xc0000008)
				{
					pNameInfo = (POBJECT_NAME_INFORMATION)szName;
					pNameType = (POBJECT_NAME_INFORMATION)szType;
					printf("%wZ   ", pNameType);
					printf("%wZ \n", pNameInfo);
				}
			}
		}
	}
}
int main() {
	EnumObjInfo(GetSystemProcessHandleInfo(), 15220);
	getchar();
}