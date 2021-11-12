#pragma once
#include <Windows.h>
#include<TlHelp32.h>
#include <stdio.h>

#define DEBUG 1

#define INIT_CODEBUFFER(s) { sizeof(s), s }

typedef struct _CodeBuffer
{
	SIZE_T BufferSize;
	BYTE* pBuffer;

}CodeBuffer;

class CodeInject
{
public:

	//远线程注入
	static BOOL ZwCreateThreadExCodeInject(DWORD dwPid, CodeBuffer Buffer);
	//通过挂起方式创建进程，HOOK程序入口点执行ShellCode
	static BOOL CreateProcessCodeInject(const WCHAR* pszTarget, CodeBuffer Buffer);
	//APC注入
	static BOOL QueueUserAPCCodeInject(DWORD dwPid, CodeBuffer Buffer);
	//线程劫持
	
	//傀儡进程-内存镜像替换

};


