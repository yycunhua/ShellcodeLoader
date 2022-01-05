#pragma once
#include <Windows.h>


namespace AntiSandbox
{
	//判断是否被改名
	void AntiSandboxByName(CHAR* szExeName);
	//通过运行时常判断是否被调试
	void AntiSandboxByRuntime();
};


