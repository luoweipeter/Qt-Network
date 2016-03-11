#include "NetProtocolTools.h"
#include <QtCore>
#define M_QStrToCStr(QStr) ({QByteArray QStr##tmp_ = QStr.toLocal8Bit();\
                                 QStr##tmp_.data();})
/*Base class NetPacket Begin*/
NetPacket::NetPacket()
{
    _Capacity=DefaultPackSize;
    Packet_Data=new char[_Capacity];
    memset(Packet_Data,0,DefaultPackSize);
    _FillSize=0;
}
NetPacket::NetPacket(int Pack_Capacity)
{
    _Capacity=Pack_Capacity;
    Packet_Data=new char[_Capacity];
    memset(Packet_Data,0,_Capacity);
    _FillSize=0;
}
int NetPacket::GetPacketSize()
{
    return _FillSize;
}
int NetPacket::GetPacketCapacity()
{
    return _Capacity;
}
const char* NetPacket::Dump() const
{
    return Packet_Data;
}
NetPacket::~NetPacket()
{
    delete[] Packet_Data;
}
/*NetPacket protected function*/
void NetPacket::ExpandCapacity(int New_Size)
{
    if(New_Size<_FillSize||New_Size<_Capacity)
    {
        throw std::invalid_argument("New Size is too small");
    }
    char* temp=new char[New_Size];
    memcpy(temp,Packet_Data,_FillSize);
    delete[] Packet_Data;
    Packet_Data=temp;
}
void NetPacket::AppendData(int Size)
{
    if(_FillSize+Size>_Capacity)
    {
        throw std::invalid_argument("capacity is too small,you should expand first!");
    }
    _FillSize+=Size;
}
/*Base class NetPacket End*/
/*class Ether_Packet Begin*/
Ether_Packet::Ether_Packet()
{
    assert(GetPacketSize()==0);
    _Begin_Pos=GetPacketSize();
    _End_Pos=_Begin_Pos+sizeof(ether_hdr);
    AppendData(sizeof(ether_hdr));
    _Ether_Header=(ether_hdr*)Packet_Data;

}
Ether_Packet::Ether_Packet(int Size):NetPacket(Size)
{
    _Begin_Pos=Ether_Begin_Pos;
    _End_Pos=Ether_End_Pos;
    AppendData(sizeof(ether_hdr));
    _Ether_Header=(ether_hdr*)Packet_Data;
}
void Ether_Packet::SetEtherDestMac(QString Mac)
{
    QByteArray temp=Mac.toLocal8Bit();
    char* mac_cstr=temp.data();
    Raw_Mac temp_mac=CStrMacToRawMac(mac_cstr);
    memcpy(&(_Ether_Header->EtherDestHost),
           &temp_mac,
           sizeof(char)*sizeof(Raw_Mac));

}
void Ether_Packet::SetEtherDestMac(Raw_Mac Mac)
{
    memcpy(&(_Ether_Header->EtherDestHost),
           &Mac,
           sizeof(char)*sizeof(Raw_Mac));
}
void Ether_Packet::SetEtherSrcMac(QString Mac)
{
    QByteArray temp=Mac.toLocal8Bit();
    char* mac_cstr=temp.data();
    Raw_Mac temp_mac=CStrMacToRawMac(mac_cstr);
    memcpy(&(_Ether_Header->EtherSrcHost),
           &temp_mac,
           sizeof(char)*sizeof(Raw_Mac));

}
void Ether_Packet::SetEtherSrcMac(Raw_Mac Mac)
{
    memcpy(&(_Ether_Header->EtherSrcHost),
           &Mac,
           sizeof(char)*sizeof(Raw_Mac));

}
void Ether_Packet::SetEtherType(unsigned short Type)
{
    _Ether_Header->EtherType=htons(Type);
}

QString Ether_Packet::GetEtherDestMac()
{
    Raw_Mac tmp;
    memcpy(&tmp,&(_Ether_Header->EtherDestHost),sizeof(unsigned char)*6);
    QString tmp_qstr;
    tmp_qstr=RawMacToCStrMac(&tmp);
    return tmp_qstr;
}
Raw_Mac Ether_Packet::GetRawEtherDestMac()
{
    Raw_Mac tmp;
    memcpy(&tmp,&(_Ether_Header->EtherDestHost),sizeof(unsigned char)*6);
    return tmp;
}
QString Ether_Packet::GetEtherSrcMac()
{
    Raw_Mac tmp;
    memcpy(&tmp,&(_Ether_Header->EtherSrcHost),sizeof(unsigned char)*6);
    QString tmp_qstr;
    tmp_qstr=RawMacToCStrMac(&tmp);
    return tmp_qstr;
}
Raw_Mac Ether_Packet::GetRawEtherSrcMac()
{
    Raw_Mac tmp;
    memcpy(&tmp,&(_Ether_Header->EtherSrcHost),sizeof(unsigned char)*6);
    return tmp;
}
unsigned short Ether_Packet::GetEtherType()
{
    return ntohs(_Ether_Header->EtherType);
}
/*class Ether_Packet End*/
/*class Arp_Packet Begin*/
Arp_Packet::Arp_Packet()
    :Ether_Packet(sizeof(ether_hdr)+sizeof(arp_hdr))
{
    assert(GetPacketSize()==(sizeof(ether_hdr)));
    _Begin_Pos=GetPacketSize();
    _End_Pos=_Begin_Pos+sizeof(arp_hdr);
    AppendData(sizeof(arp_hdr));
    _Arp_Header=(arp_hdr*)(Packet_Data+_Begin_Pos);
    SetEtherType(0x0806);
    SetEtherDestMac("FF-FF-FF-FF-FF-FF");
    SetArpDestMac("FF-FF-FF-FF-FF-FF");
    SetArpSrcMac("00-00-00-00-00-00");
    SetArpHardwareType(0x0001);
    SetArpHardwareLength(0x06);
    SetArpProtocolType(0x0800);
    SetArpProtocolLength(0x04);

}
void Arp_Packet::SetArpDestMac(QString Mac)
{
    QByteArray temp=Mac.toLocal8Bit();
    char* mac_cstr=temp.data();
    Raw_Mac temp_mac=CStrMacToRawMac(mac_cstr);
    memcpy(&(_Arp_Header->EtherDestHost),
           &temp_mac,
           sizeof(char)*sizeof(Raw_Mac));

}
void Arp_Packet::SetArpDestMac(Raw_Mac Mac)
{
    memcpy(&(_Arp_Header->EtherDestHost),
           &Mac,
           sizeof(char)*sizeof(Raw_Mac));
}
 void Arp_Packet::SetArpSrcMac(QString Mac)
{
     QByteArray temp=Mac.toLocal8Bit();
     char* mac_cstr=temp.data();
     Raw_Mac temp_mac=CStrMacToRawMac(mac_cstr);
     memcpy(&(_Arp_Header->EtherSrcHost),
            &temp_mac,
            sizeof(char)*sizeof(Raw_Mac));
}
void Arp_Packet::SetArpSrcMac(Raw_Mac Mac)
{
    memcpy(&(_Arp_Header->EtherSrcHost),
           &Mac,
           sizeof(char)*sizeof(Raw_Mac));
}
 void Arp_Packet::SetArpDestIP(QString IP)
{
     QByteArray temp=IP.toLocal8Bit();
     char* IP_cstr=temp.data();
     unsigned long ip_tmp=inet_addr(IP_cstr);
     memcpy(&(_Arp_Header->DestIp),&ip_tmp,
            sizeof(unsigned long));
}
void Arp_Packet::SetArpSrcIP(QString IP)
 {
    QByteArray temp=IP.toLocal8Bit();
    char* IP_cstr=temp.data();
    unsigned long ip_tmp=inet_addr(IP_cstr);
    memcpy(&(_Arp_Header->SrcIp),&ip_tmp,
           sizeof(unsigned long));
 }
void Arp_Packet::SetArpOperationCode(unsigned short Opcode)
{
    _Arp_Header->OperationCode=htons(Opcode);
}
void Arp_Packet::SetArpHardwareType(unsigned short Type)
{
    _Arp_Header->HardwareType=htons(Type);
}
void Arp_Packet::SetArpHardwareLength(unsigned char Length)
{
    _Arp_Header->HardwareLength=Length;
}
void Arp_Packet::SetArpProtocolType(unsigned short Type)
{
    _Arp_Header->ProtocolType=htons(Type);
}
void Arp_Packet::SetArpProtocolLength(unsigned char Length)
{
    _Arp_Header->ProtocolLength=Length;
}
QString Arp_Packet::GetArpDestMac()
{
    Raw_Mac tmp;
    memcpy(&tmp,&(_Arp_Header->EtherDestHost),sizeof(unsigned char)*6);
    QString tmp_qstr;
    tmp_qstr=RawMacToCStrMac(&tmp);
    return tmp_qstr;
}
Raw_Mac Arp_Packet::GetRawArpDestMac()
{
    Raw_Mac tmp;
    memcpy(&tmp,&(_Arp_Header->EtherDestHost),sizeof(unsigned char)*6);
    return tmp;
}
QString Arp_Packet::GetArpSrcMac()
{
    Raw_Mac tmp;
    memcpy(&tmp,&(_Arp_Header->EtherSrcHost),sizeof(unsigned char)*6);
    QString tmp_qstr;
    tmp_qstr=RawMacToCStrMac(&tmp);
    return tmp_qstr;

}
Raw_Mac Arp_Packet::GetRawArpSrcMac()
{
    Raw_Mac tmp;
    memcpy(&tmp,&(_Arp_Header->EtherSrcHost),sizeof(unsigned char)*6);
    return tmp;
}
QString Arp_Packet::GetArpDestIP()
{
   unsigned long tmp;
   memcpy(&tmp,&(_Arp_Header->DestIp),sizeof(unsigned char)*4);
   char* cstr_tmp=RawIPToCStr(tmp);
   return QString(cstr_tmp);
}
unsigned long Arp_Packet::GetRawArpDestIP()
{
    unsigned long tmp;
    memcpy(&tmp,&(_Arp_Header->DestIp),sizeof(unsigned char)*4);
    return tmp;
}
QString Arp_Packet::GetArpSrcIP()
{
    unsigned long tmp;
    memcpy(&tmp,&(_Arp_Header->SrcIp),sizeof(unsigned char)*4);
    char* cstr_tmp=RawIPToCStr(tmp);
    return QString(cstr_tmp);
}
unsigned long Arp_Packet::GetRawArpSrcIP()
{
    unsigned long tmp;
    memcpy(&tmp,&(_Arp_Header->SrcIp),sizeof(unsigned char)*4);
    return tmp;
}
unsigned short Arp_Packet::GetArpOperationCode()
{
    return ntohs(_Arp_Header->OperationCode);
}
unsigned short Arp_Packet::GetArpHardwareType()
{
    return ntohs(_Arp_Header->HardwareType);
}
unsigned char Arp_Packet::GetArpHardwareLength()
{
    return _Arp_Header->HardwareLength;
}
unsigned short Arp_Packet::GetArpProtocolType()
{
    return ntohs(_Arp_Header->ProtocolType);
}
unsigned char Arp_Packet::GetArpProtocolLength()
{
    return _Arp_Header->ProtocolLength;
}

/*class Arp_Packet End*/
