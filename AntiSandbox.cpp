#include "AntiSandbox.h"

#pragma warning(disable:4996)

void FetchExeName(PCHAR	szBuffer,DWORD	nSize)
{
	CHAR buffer[MAX_PATH] = { 0 };
	for (size_t i = nSize - 1; i > 1; i--)
	{
		if (szBuffer[i-1] == '\\')
		{
			strcpy(buffer, &szBuffer[i]);
			ZeroMemory(szBuffer, nSize);
			strcpy(szBuffer, buffer);
		}
	}
}


void AntiSandbox::AntiSandboxByName(CHAR* szExeName)
{
	CHAR szFileName1[MAX_PATH] = { 0 };
	CHAR szFileName2[MAX_PATH] = { 0 };
	DWORD dwSize = MAX_PATH;

	GetModuleFileName(NULL, szFileName1, MAX_PATH);
	FetchExeName(szFileName1, sizeof(szFileName1));
	//MessageBox(NULL, szFileName, 0, MB_OK);

	QueryFullProcessImageName(GetCurrentProcess(), PROCESS_NAME_NATIVE, szFileName2, &dwSize);
	FetchExeName(szFileName2, sizeof(szFileName2));
	//MessageBox(NULL, szFileName, 0, MB_OK);

	if (strcmp(szExeName, szFileName1) || strcmp(szExeName, szFileName2))
	{
		TerminateProcess(GetCurrentProcess(), 0);
		ExitProcess(0);
	}
	return;
}


EXTERN_C
ULONGLONG
WINAPI
MyGetTickCount64Kernel32(
	VOID
);

void AntiSandbox::AntiSandboxByRuntime()
{
	__int64 lasttime = MyGetTickCount64Kernel32();
	Sleep(300);
	__int64 duration = MyGetTickCount64Kernel32() - 300 - lasttime;

	if (duration > 100)
	{
		//MessageBox(0, 0, 0, 0);
		TerminateProcess(GetCurrentProcess(), 0);
		ExitProcess(0);
	}
	else
		return;
}
