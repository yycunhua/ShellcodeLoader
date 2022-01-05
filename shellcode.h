#pragma once
#pragma comment(linker,"/subsystem:\"Windows\" /entry:\"mainCRTStartup\"")
//#pragma comment(linker,"/subsystem:\"Windows\" /entry:\"main\"")

#define KEY 0x11
//#define ENCODE


#ifndef ENCODE
#endif
///////////////////////////////////////////////////
#ifdef ENCODE
unsigned char shellcode[] = "";
#else
unsigned char shellcode[] = { 0 };
#endif
///////////////////////////////////////////////////
int size = sizeof(shellcode);