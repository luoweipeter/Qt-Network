#ifndef MY_NET_TOOLS_H
#define MY_NET_TOOLS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

struct Raw_Mac{
	unsigned char un[6];
};

int EndianConvert(void* _In_Un,size_t Size);
struct Raw_Mac CStrMacToRawMac(char* In_Str_Mac);
char* RawMacToCStrMac(struct Raw_Mac* In_Raw_Mac);
unsigned long CalcBroadAddr(unsigned long Raw_IP, unsigned long Raw_Mask);
unsigned long CalcNetAddr(unsigned long Raw_IP, unsigned long Raw_Mask);
char* RawIPToCStr(unsigned long Raw_IP);
void* LineSearch(const void* Key, const void* Base, size_t NumOfElements, size_t SizeofElements,
	int(*PtFuncCompare)(const void*, const void*));

#ifdef __cplusplus
}
#endif
#endif
