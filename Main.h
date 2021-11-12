#pragma once
#include"Windows.h"
#include"stdio.h"
#include"tlhelp32.h"


DWORD GetProcessIdByProcessName(const WCHAR ProcessName[MAX_PATH])
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		//printf("CreateToolhelp32Snapshot() Fail! ERROR_CODE=%x\n", GetLastError());
		return FALSE;
	}
	PROCESSENTRY32 pe32;
	ZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}
	do {
		//printf("%ls",pe32.szExeFile);
		if (!wcscmp(pe32.szExeFile, ProcessName))
		{
			return pe32.th32ProcessID;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	return FALSE;
}

