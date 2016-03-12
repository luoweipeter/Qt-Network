#include "IP_Range.h"
#include "NetTools.h"
IP_Range::IP_Range(QString Begin_IP,QString End_IP,QString Mask)
{
    char* cstr_begin_ip;
    char* cstr_end_ip;
    char* cstr_mask;
    QByteArray begin_ip_byte_data=Begin_IP.toLocal8Bit();
    QByteArray end_iP_byte_data=End_IP.toLocal8Bit();
    QByteArray mask_byte_data=Mask.toLocal8Bit();
    cstr_begin_ip= begin_ip_byte_data.data();
    cstr_end_ip= end_iP_byte_data.data();
    cstr_mask= mask_byte_data.data();

   _Begin_IP=inet_addr(cstr_begin_ip);
   _End_IP=inet_addr(cstr_end_ip);
   _Mask=inet_addr(cstr_mask);
   _Cur_IP=_Begin_IP;

   _Net_Addr=::CalcNetAddr(_End_IP,_Mask);
   _Broad_Addr=::CalcBroadAddr(_Begin_IP,_Mask);

    EndianConvert(&_Net_Addr,sizeof(unsigned long));
    EndianConvert(&_Broad_Addr,sizeof(unsigned long));
    EndianConvert(&_Begin_IP,sizeof(unsigned long));
    EndianConvert(&_End_IP,sizeof(unsigned long));

    if(_Begin_IP<=_Net_Addr||_End_IP>=_Broad_Addr||_Begin_IP>_End_IP)
    {
        throw IP_RangeException("Out of Range.");
    }

    _Index=0;

    long max_len=1;
    for(int i=0;i<32;i++)
    {
        int chk=_Mask&(1<<i);
        if(chk==0)
        {
            max_len=max_len<<1;
        }
    }
    max_len -=2;
    _Max_Length=max_len;
    _Length=_End_IP-_Begin_IP;

    //当前地址指向起始地址的前一位,保证从_Begin_IP到_End_IP都取到
    EndianConvert(&_Cur_IP,sizeof(unsigned long));
    _Cur_IP--;
    EndianConvert(&_Cur_IP,sizeof(unsigned long));

}
long IP_Range::Length(){
    return _Length;

}
bool IP_Range::HaveNext(){
    if(_Index<=_Length)
        return true;
    return false;
}
unsigned long IP_Range::NextRawIP(){
    EndianConvert(&_Cur_IP,sizeof(unsigned long));
    if(_Cur_IP<_Begin_IP-2 ||_Cur_IP>_End_IP)
    {
        return 0;
    }
    _Cur_IP +=1;
    EndianConvert(&_Cur_IP,sizeof(unsigned long));
    _Index++;
    return _Cur_IP;

}
IP_RangeException::~IP_RangeException()throw()
{}
