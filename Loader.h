#pragma once
#include <Windows.h>

namespace Loader
{
	void RunShellCode_1(unsigned char* shellcode);
	void RunShellCode_2(unsigned char* shellcode);
	void InjectShellCode_1(unsigned char* shellcode);
	void CertEnumSystemStoreCallbackRunShellcode(unsigned char* shellcode);
	void VehRunShellcode(unsigned char* shellcode);
};


