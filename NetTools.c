#include "NetTools.h"

char* RawMacToCStrMac(struct Raw_Mac* In_Raw_Mac)
{
	char* ret = malloc(sizeof(unsigned char) * 18);
	sprintf(ret, "%x-%x-%x-%x-%x-%x", In_Raw_Mac->un[0], In_Raw_Mac->un[1],
										In_Raw_Mac->un[2], In_Raw_Mac->un[3],
										In_Raw_Mac->un[4], In_Raw_Mac->un[5]);

    return ret;
}

struct Raw_Mac CStrMacToRawMac(char* In_Str_Mac)
{
	struct Raw_Mac ret;
	memset(ret.un, '\0', 6);
	int ndelim = 0;
	/*if (In_len < 16)
		return;
	if (In_len > 18)
		return;
		*/
    const char* pchr=In_Str_Mac;
	int flag = 0;
	unsigned char cur = 0;
	for(pchr;*pchr!='\0';pchr++)
	{
		if (*pchr == '-')
		{
			if (ndelim > 6)
			{
				return;
			}
			ret.un[ndelim] = cur;
			ndelim++;
			cur=0;
			flag = 0;
		}else if (*pchr <= '9' && *pchr >= '0')
		{
			if (flag==0)
			{
				cur += *pchr - '0';
				flag = 1;
			}else{
				cur = cur << 4;
				cur += *pchr - '0';
				flag = 0;
			}
		}else if (*pchr <= 'F' && *pchr >= 'A')
		{
			if (flag == 0)
			{
				cur += *pchr - 'A' + 10;
				flag = 1;
			}else{
				cur = cur << 4;
				cur += *pchr - 'A'+10;
				flag = 0;
			}
		}else if (*pchr <="f" && *pchr>='a'){
			if (flag == 0)
			{
				cur += *pchr - 'a' + 10;
				flag = 1;
			}else{
				cur = cur << 4;
				cur += *pchr - 'a' + 10;
				flag = 0;
			}
		}
		else
		{
            //printf("无法解析的字符");
			return;
		}
		
	}
	ret.un[ndelim] = cur;

	return ret;
}

int EndianConvert(void* _In_Un,size_t Size)
{
	unsigned char tmp;
	unsigned char *Un = _In_Un;
	int i = 0;
	int j = Size - 1;
	while (i != j && i<=j)
	{
		tmp = Un[i];
		Un[i] = Un[j];
		Un[j] = tmp;
		i++;
		j--;
	}

	return 0;
}
unsigned long CalcBroadAddr(unsigned long Raw_IP, unsigned long Raw_Mask)
{
	unsigned char *un_Ip = (unsigned char *)&Raw_IP;
	unsigned char *un_Mask = (unsigned char *)&Raw_Mask;
	unsigned long BroadAddr=0;
	unsigned char *un_BA = (unsigned char *)&BroadAddr;
	for (int i = 0; i < sizeof(unsigned long); i++)
	{
		un_BA[i] = un_Ip[i] & un_Mask[i];
		un_BA[i] = un_Ip[i] | (~un_Mask[i]);
	}
	return BroadAddr;
}

unsigned long CalcNetAddr(unsigned long Raw_IP, unsigned long Raw_Mask)
{
	unsigned char *un_Ip = (unsigned char *)&Raw_IP;
	unsigned char *un_Mask = (unsigned char *)&Raw_Mask;
	unsigned long NetAddr = 0;
	unsigned char *un_NA = (unsigned char *)&NetAddr;

	for (int i = 0; i < sizeof(unsigned long); i++)
	{
		un_NA[i] = un_Ip[i] & un_Mask[i];
	}
	return NetAddr;
}

char* RawIPToCStr(unsigned long Raw_IP)
{
	unsigned char *un_Ip = (unsigned char *)&Raw_IP;
	char* pIPStr = malloc(16 * sizeof(char));
	memset(pIPStr, '\0', 16);
	sprintf(pIPStr, "%u\.%u\.%u\.%u", un_Ip[0], un_Ip[1], un_Ip[2], un_Ip[3]);

	return pIPStr;
}

unsigned long Raw_IP_Pool(unsigned char* Ip_Addr, unsigned char* Mask, int IsInit)
{
	u_char un[4];
	static unsigned long retIP=0;
	unsigned long raw_BA=0;
	unsigned long raw_NA=0;
	static unsigned long raw_High_IP = 0;
	static unsigned long raw_Low_IP = 0;
	unsigned char * un_IP = (unsigned char *)&retIP;
	
	
	if (IsInit==0)
	{
		unsigned long raw_Ip = inet_addr(Ip_Addr);
		unsigned long raw_Mask = inet_addr(Mask);
		raw_BA = CalcBroadAddr(raw_Ip, raw_Mask);
		raw_NA = CalcNetAddr(raw_Ip, raw_Mask);
		raw_High_IP = raw_BA;
		raw_Low_IP = raw_NA;
		retIP = raw_Low_IP;
		EndianConvert(&raw_High_IP, sizeof(unsigned long));
		EndianConvert(&raw_Low_IP, sizeof(unsigned long));
		return retIP;
	}else{
		EndianConvert(&retIP, sizeof(unsigned long));
		retIP++;
		if (retIP >= raw_High_IP || retIP <= raw_Low_IP)
		{
			goto MyERROR;
		}
		EndianConvert(&retIP, sizeof(unsigned long));
		return retIP;
	}
	
MyERROR:
	return 0;
}

//struct RawIP_Iter Create_IPIter(char* CStr_IP, char* CStr_Mask)
//{
//	u_long ip = inet_addr(CStr_IP);
//	u_long mask = inet_addr(CStr_Mask);
	
//	struct RawIP_Iter iter;

//	iter._raw_High_IP = CalcBroadAddr(ip, mask);
//	EndianConvert(&(iter._raw_High_IP), sizeof(iter._raw_High_IP));
//	iter._raw_Low_IP = CalcNetAddr(ip, mask);
//	EndianConvert(&(iter._raw_Low_IP), sizeof(iter._raw_Low_IP));
//	iter._raw_Cur_IP = iter._raw_Low_IP;
//	iter.Index = 0;
//	iter.State = 0;
	
//	iter.Size = 1;
//	for (int i = 0; i < 32; i++)
//	{
//		int chk = mask&(1 << i);
//		if (chk == 0)
//		{
//			iter.Size = iter.Size << 1;
//		}
//	}
//	iter.Size -= 2;
//	return iter;
//}
//u_long NextRawIP(struct RawIP_Iter* Iter)
//{
//	u_long low = Iter->_raw_Low_IP;
//	u_long high = Iter->_raw_High_IP;
//	u_long *cur = &(Iter->_raw_Cur_IP);
//	u_long ret = NULL;

//	(*cur)++;
//	if (*cur >= high || *cur < low)
//	{
//		Iter->State = 1;
//		return NULL;
//	}
//	Iter->Index++;
//	ret = *cur;
//	EndianConvert(&ret, sizeof(ret));
//	return ret;

//}

void* LineSearch(const void* Key, const void* Base, size_t NumOfElements, size_t SizeofElements,
	int(*PtFuncCompare)(const void*, const void*))
{
	for (int i = 0; i < NumOfElements; i++)
	{
		char* cur = (const char*)Base + i*SizeofElements;
		if (PtFuncCompare(Key, cur) == 0)
		{
			return cur;
		}
	}

	return NULL;
}
#ifdef TEST
int main()
{
	struct Raw_Mac raw_mac=StrMacToRawMac("1-1-1-1-1-1");

	//printf("%x-%x-%x-%x-%x-%x\n", raw_mac.un[0], raw_mac.un[1], raw_mac.un[2], raw_mac.un[3], raw_mac.un[4], raw_mac.un[5]);
	printf("%s\n", RawMacToCStrMac(&raw_mac));
	raw_mac = StrMacToRawMac("84-C9-B2-29-54-C0");
	//printf("%x-%x-%x-%x-%x-%x\n", raw_mac.un[0], raw_mac.un[1], raw_mac.un[2], raw_mac.un[3], raw_mac.un[4], raw_mac.un[5]);
	printf("%s\n", RawMacToCStrMac(&raw_mac));

	u_long dst_addr = inet_addr("10.10.10.123");
	u_long mask_addr = inet_addr("255.255.240.0");
	char* Ip_Str = RawIPToCStr(dst_addr);
	printf("%s\n", Ip_Str);
	u_long raw_BA=CalcBroadAddr(dst_addr, mask_addr);
	printf("%s\n", RawIPToCStr(raw_BA));
	printf("%s\n", RawIPToCStr(raw_BA-(1<<24)));
	u_long raw_NA = CalcNetAddr(dst_addr, mask_addr);
	printf("%s\n", RawIPToCStr(raw_NA));
	printf("%s\n", RawIPToCStr(raw_NA +(1 << 24)));

	for (int i = 0; i < sizeof(dst_addr); i++)
	{
		printf("%x ", ((unsigned char*)(&dst_addr))[i]);
	}
	puts("\n");
	u_long hl = htonl(dst_addr);
	for (int i = 0; i < sizeof(dst_addr); i++)
	{
		printf("%x ", ((unsigned char*)(&hl))[i]);
	}
	puts("\n");
	//u_long nl = ntohl(dst_addr)+1;
	EndianConvert(&dst_addr, sizeof(u_long));
	dst_addr+=255;
	for (int i = 0; i < sizeof(dst_addr); i++)
	{
		printf("%x ", ((unsigned char*)(&dst_addr))[i]);
	}
	puts("\n");
	EndianConvert(&dst_addr, sizeof(u_long));
	for (int i = 0; i < sizeof(dst_addr); i++)
	{
		printf("%x ", ((unsigned char*)(&dst_addr))[i]);
	}
	puts("\n");

	//u_long Cur_IP = Raw_IP_Pool("192.168.10.1", "255.255.240.0",0);
	//while (Cur_IP = Raw_IP_Pool("192.168.10.1", "255.255.240.0", 1))
	//{
	//	printf("%s\n", RawIPToCStr(Cur_IP));
	//	getchar();
	//}

	struct RawIP_Iter raw_ip_iter = Create_IPIter("10.10.10.123","255.255.240.0");
	u_long cur_ip = NULL;
	while (cur_ip = NextRawIP(&raw_ip_iter))
	{
		
		printf("%ld/%ld: %s\n", raw_ip_iter.Index,raw_ip_iter.Size,RawIPToCStr(cur_ip));
	}
	getchar();
	return;
}
#endif
