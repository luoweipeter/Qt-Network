#include "CaptureThread.h"
#include "NetProtocolTools.h"
void CaptureThread::run()
{
    char* dev_name;
    char* packet_filter;
    if(_Dev_Name==NULL || _Parse_Rule==NULL)
    {
        emit SendError("you should set Dev_Name and or Parse rule first~!");
        return;
    }
    QByteArray dev_name_byte=_Dev_Name.toLocal8Bit();
    dev_name=dev_name_byte.data();

    QByteArray _parse_rule_byte;
    _parse_rule_byte=_Parse_Rule.toLocal8Bit();
    //char* packet_filter="arp";
    packet_filter=_parse_rule_byte.data();

    struct bpf_program fcode;
    if ( (_Cap_fp= pcap_open_live(dev_name,  // 设备名
                                65536,     // 要捕捉的数据包的部分
                                           // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                                PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
                                1000,      // 读取超时时间
                                _Err_Buf     // 错误缓冲池
                                ) ) == NULL)
       {
            QString info="Unable to open the adapter. %s is not supported by WinPcap";
           emit SendError(info);
           return;
       }

    if (pcap_datalink(_Cap_fp) != DLT_EN10MB)
        {
            QString info="This program works only on Ethernet networks";
            emit SendError(info);
            /* 释放设备列表 */
            return;
        }
    QByteArray mask_byte_data=_Mask.toLocal8Bit();
    u_long netmask = inet_addr(mask_byte_data.data());
    if (pcap_compile(_Cap_fp, &fcode, packet_filter, 1, netmask) <0)
        {
            QString info="Unable to compile the packet filter. Check the syntax.";
            emit SendError(info);
            return;
        }
    //设置过滤器
        if (pcap_setfilter(_Cap_fp, &fcode)<0)
        {
            emit SendError("Error setting the filter.");
            return;
        }
        emit SendStatu("Arp捕获线程设置完毕,开始捕获数据.");
        int res=0;
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        QByteArray cap_data;

        while ((res = pcap_next_ex(_Cap_fp, &header, &pkt_data)) >= 0){
            if(this->_IsStop)
            {
                emit SendStatu("Arp捕获线程正在结束.");
                return;

            }
            if(header->caplen<=0||header->len<=0)
            {
                continue;
            }
//            QByteArray cap_data((const char*)pkt_data,header->len);
            cap_data.setRawData((const char*)pkt_data,header->len);
            SendStatu("RCV:"+QString::number(header->caplen)+"bytes");
            Arp_Packet arp_pack;
            arp_pack.BuildFromRawData(cap_data.data(),cap_data.length());
            unsigned short opcode=arp_pack.GetArpOperationCode();
            QString dest_mac=arp_pack.GetEtherDestMac();
            QString src_mac=arp_pack.GetEtherSrcMac();
            QString arp_dest_mac=arp_pack.GetArpDestMac();
            QString arp_src_mac=arp_pack.GetArpSrcMac();
            QString dest_ip=arp_pack.GetArpDestIP();
            QString src_ip=arp_pack.GetArpSrcIP();
            //cap_data.append((const char*)pkt_data,header->len);
            emit SendData(cap_data);
        }
}

