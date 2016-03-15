#include "ArpScanThread.h"
#include "NetProtocol.h"
#include "NetTools.h"
#include <exception>
#include <stdexcept>
#define M_QStrToCStr(QStr) ({QByteArray QStr##tmp_ = QStr.toLocal8Bit();\
                                 QStr##tmp_.data();})
bool IsValidMac(Raw_Mac chkMac)
{
    u_char* pMac=(u_char*)(&chkMac);
    for(unsigned int i=0;i<sizeof(Raw_Mac);i++)
    {
        if(pMac[i]!=0)
        {
            return true;
        }
    }
    return false;
}
int ArpScanThread::_OpenPcap()
{

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
    if ((_Scan_fp = pcap_open(dev_name,            // 设备名
            100,                // 要捕获的部分 (只捕获前100个字节)
            PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
            1000,               // 读超时时间
            NULL,               // 远程机器验证
            _Err_Buf              // 错误缓冲
            )) == NULL)
        {
            emit SendError("Unable to open the adapter. %s is not supported by WinPcap.");
            return ;
        }

    Arp_Packet arp_send_packet;
    arp_send_packet.SetEtherDestMac("FF-FF-FF-FF-FF-FF");
    arp_send_packet.SetArpDestMac("FF-FF-FF-FF-FF-FF");
    arp_send_packet.SetEtherSrcMac(_Src_Mac);
    arp_send_packet.SetArpSrcMac(_Src_Mac);
    arp_send_packet.SetArpSrcIP(_Src_IP);
    arp_send_packet.SetArpOperationCode(0x01);

    try{
        while(_IP_Range->HaveNext())
        {
            unsigned long cur_ip=_IP_Range->NextRawIP();
            arp_send_packet.SetArpDestIP(cur_ip);
            const unsigned char* scanPack=(const unsigned char*)arp_send_packet.Dump();
            size_t pack_len=arp_send_packet.GetPacketSize();

            if (pcap_sendpacket(_Scan_fp, scanPack, pack_len /* size */) != 0)
               {
                    QString dst_ip=RawIPToCStr(cur_ip);
                    emit SendError("Error sending the packet to"+dst_ip );
                    return;
               }
            emit SendStatu(QString("Send a packet to ")+arp_send_packet.GetArpDestIP());
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
    if(IsValidMac(_Src_Mac)==false)
    {
        throw std::invalid_argument("please set a vaild mac");
    }

}
 void ArpScanThread::SetScanIP(QString IP)
 {
    char* ip=M_QStrToCStr(IP);
    _Src_IP=inet_addr(ip);

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



