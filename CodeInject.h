#pragma once
#include <Windows.h>
#include<TlHelp32.h>
#include <stdio.h>

#define INIT_CODEBUFFER(s) { sizeof(s), s }

typedef struct _CodeBuffer
{
	SIZE_T BufferSize;
	BYTE* pBuffer;
}CodeBuffer;


namespace CodeInject
{
	//Զ�߳�ע��
	BOOL ZwCreateThreadExCodeInject(DWORD dwPid, CodeBuffer Buffer);
	//ͨ������ʽ�������̣�HOOK������ڵ�ִ��ShellCode
	BOOL CreateProcessCodeInject(const PCHAR pszTarget, CodeBuffer Buffer);
	//APCע��
	BOOL QueueUserAPCCodeInject(DWORD dwPid, CodeBuffer Buffer);
	//�߳̽ٳ�
	
	//���ܽ���-�ڴ澵���滻

};


