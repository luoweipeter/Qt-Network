#include "ArpScanThread.h"
#include "NetProtocol.h"
#include "NetTools.h"
#include <exception>
#include <stdexcept>

bool IsValidMac(Raw_Mac chkMac)
{
    u_char* pMac=(u_char*)(&chkMac);
    for(int i=0;i<sizeof(Raw_Mac);i++)
    {
        if(pMac[i]!=0)
        {
            return true;
        }
    }
    return false;
}
void ArpScanThread::run()
{
    char* dev_name;
    if(_Dev_Name==NULL )
    {
        emit SendError("you should set Dev_Name first!");
        return;
    }
    QByteArray dev_name_byte=_Dev_Name.toLocal8Bit();
    dev_name=dev_name_byte.data();


//    if(_Src_Mac==NULL)
//    {
//        emit SendError("Src_Mac don't Set");
//        return;
//    }
    if ((_Scan_fp = pcap_open(dev_name,            // 设备名
            100,                // 要捕获的部分 (只捕获前100个字节)
            PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
            1000,               // 读超时时间
            NULL,               // 远程机器验证
            _Err_Buf              // 错误缓冲
            )) == NULL)
        {
            emit SendError("\nUnable to open the adapter. %s is not supported by WinPcap.");
            return;
        }

    try{
        while(_IP_Range->HaveNext())
        {
            u_long cur_ip=_IP_Range->NextRawIP();
            struct Raw_Mac DST_Mac = CStrMacToRawMac("FF-FF-FF-FF-FF-FF");
            struct Raw_Mac SRC_Mac = _Src_Mac;
            u_long src_addr=inet_addr("10.10.9.123");
            u_long dst_addr=cur_ip;
            unsigned char* scanPack=NULL;
            size_t pack_len = BuildArPacket(&scanPack,
                                            0x01,//arp.opcode==0x01
                                            (u_char*)&SRC_Mac,(u_char*)&src_addr, //源Mac地址和源IP地址
                                            (u_char*)&DST_Mac,(u_char*)&dst_addr);//目的Mac地址和目的IP地址

            if (pcap_sendpacket(_Scan_fp, scanPack, pack_len /* size */) != 0)
               {
                    QString dst_ip=RawIPToCStr(cur_ip);
                    emit SendError("Error sending the packet to"+dst_ip );
                    return;
               }
        }
    }catch(const std::exception &e)
    {
         throw;
    }



}
void ArpScanThread::SetScanSrcMac(QString Mac)
{
    QByteArray mac_byte_data=Mac.toLocal8Bit();
    char* mac_cstr=mac_byte_data.data();
    _Src_Mac=CStrMacToRawMac(mac_cstr);
    if(!IsValidMac(_Src_Mac))
    {
        throw std::invalid_argument("please set a vaild mac");
    }
//    if(_Src_Mac==NULL)
//    {
//        throw std::invalid_argument("Invalid argument~!!");
//    }

}

void ArpScanThread::SetScanRange(QString Begin_IP,QString End_IP,QString Mask) throw()
{
    try{
        _IP_Range=new IP_Range(Begin_IP,End_IP,Mask);
    }catch(const IP_RangeException &e)
    {
        throw std::invalid_argument("invaild argument for scan range.");
    }
}



