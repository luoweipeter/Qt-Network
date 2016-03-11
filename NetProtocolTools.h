#ifndef NETPROTOCOLTOOLS_H
#define NETPROTOCOLTOOLS_H
#include "NetProtocol.h"
#include "NetTools.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <QByteArray>
#include <exception>
#include <stdexcept>

#define Ether_Begin_Pos 0
#define Ether_End_Pos Ether_Begin_Pos+sizeof(ether_hdr)
#define Arp_Begin_Pos Ether_End_Pos
#define Arp_End_Pos Arp_Begin_Pos+sizeof(arp_hdr)

#define DefaultPackSize 256
class NetPacket
{
public:
    NetPacket()
    {
        _Capacity=DefaultPackSize;
        Packet_Data=new char[_Capacity];
        memset(Packet_Data,0,DefaultPackSize);
        _FillSize=0;
    }
    NetPacket(int Pack_Capacity)
    {
        _Capacity=Pack_Capacity;
        Packet_Data=new char[_Capacity];
        memset(Packet_Data,0,_Capacity);
        _FillSize=0;
    }
    int GetPacketSize()
    {
        return _FillSize;
    }
    int GetPacketCapacity()
    {
        return _Capacity;
    }
    const char* Dump() const;
    virtual void BuildFromRawData(const char* Data);
    ~NetPacket()
    {
        delete[] Packet_Data;
    }
protected:
    void ExpandCapacity(int New_Size)
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
    void AppendData(int Size)
    {
        if(_FillSize+Size>_Capacity)
        {
            throw std::invalid_argument("capacity is too small,you should expand first!");
        }
        _FillSize+=Size;
    }
    char* Packet_Data;
private:
    int _Capacity;
    int _FillSize;
};
class Ether_Packet:public NetPacket
{
public:
    Ether_Packet()
    {
        assert(GetPacketSize()==0);
        _Begin_Pos=GetPacketSize();
        _End_Pos=_Begin_Pos+sizeof(ether_hdr);
        AppendData(sizeof(ether_hdr));
        _ether_header=(ether_hdr*)Packet_Data;

    }
    Ether_Packet(int Size)
    {
        NetPacket(Size);
        _Begin_Pos=Ether_Begin_Pos;
        _End_Pos=Ether_End_Pos;
        AppendData(sizeof(ether_hdr));
        _ether_header=(ether_hdr*)Packet_Data;
    }
    SetEtherDestMac(QString Mac)
    {
        QByteArray temp=Mac.toLocal8Bit();
        char* mac_cstr=temp.data();
        Raw_Mac temp_mac=CStrMacToRawMac(mac_cstr);
        memcpy(&(_Ether_Header->EtherDestHost),
               &temp_mac,
               sizeof(char)*sizeof(Raw_Mac));

    }
    SetEtherDestMac(Raw_Mac Mac)
    {
        memcpy(&(_Ether_Header->EtherDestHost),
               &Mac,
               sizeof(char)*sizeof(Raw_Mac));
    }
    SetEtherSrcMac(QString Mac)
    {
        QByteArray temp=Mac.toLocal8Bit();
        char* mac_cstr=temp.data();
        Raw_Mac temp_mac=CStrMacToRawMac(mac_cstr);
        memcpy(&(_Ether_Header->EtherSrcHost),
               &temp_mac,
               sizeof(char)*sizeof(Raw_Mac));

    }
    SetEtherSrcMac(Raw_Mac Mac)
    {
        memcpy(&(_Ether_Header->EtherSrcHost),
               &Mac,
               sizeof(char)*sizeof(Raw_Mac));

    }
    SetEtherType(unsigned short Type)
    {
        _Ether_Header->EtherType=htons(Type);
    }

private:
    int _Begin_Pos;
    int _End_Pos;
    ether_hdr* _Ether_Header;

};

class Arp_Packet:public Ether_Packet
{
public:
    Arp_Packet()
    {
        Ether_Packet(sizeof(ether_hdr)+sizeof(arp_hdr));
        assert(GetPacketSize()==(sizeof(ether_hdr)));
        _Begin_Pos=GetPacketSize();
        _End_Pos=_Begin_Pos+sizeof(arp_hdr);
        AppendData(sizeof(arp_hdr));
        _Arp_Header=(arp_hdr*)(Packet+_Begin_Pos);
        SetEtherType(0x0806);
        SetEtherDestMac("FF-FF-FF-FF-FF-FF");
        SetArpDestMac("FF-FF-FF-FF-FF-FF");
        SetArpSrcMac("00-00-00-00-00-00");
        SetArpHardwareType(0x0001);
        SetArpHardwareLength(0x06);
        SetArpProtocolType(0x0800);
        SetArpProtocolLength(0x04);

    }
    void SetArpDestMac(QString Mac)
    {
        QByteArray temp=Mac.toLocal8Bit();
        char* mac_cstr=temp.data();
        Raw_Mac temp_mac=CStrMacToRawMac(mac_cstr);
        memcpy(&(_Arp_Header->EtherDestHost),
               &temp_mac,
               sizeof(char)*sizeof(Raw_Mac));

    }
    void SetArpDestMac(Raw_Mac Mac)
    {
        memcpy(&(_Arp_Header->EtherDestHost),
               &Mac,
               sizeof(char)*sizeof(Raw_Mac));
    }
     void SetArpSrcMac(QString Mac)
    {
         QByteArray temp=Mac.toLocal8Bit();
         char* mac_cstr=temp.data();
         Raw_Mac temp_mac=CStrMacToRawMac(mac_cstr);
         memcpy(&(_Arp_Header->EtherSrcHost),
                &temp_mac,
                sizeof(char)*sizeof(Raw_Mac));
    }
    void SetArpSrcMac(Raw_Mac Mac)
    {
        memcpy(&(_Arp_Header->EtherSrcHost),
               &Mac,
               sizeof(char)*sizeof(Raw_Mac));
    }
     void SetArpDestIP(QString IP)
    {
         QByteArray temp=IP.toLocal8Bit();
         char* IP_cstr=temp.data();
         unsigned long ip_tmp=inet_addr(IP_cstr);
         memcpy(&(_Arp_Header->DestIp),&ip_tmp,
                sizeof(unsigned long));
    }
    void SetArpSrcIP(QString IP)
     {
        QByteArray temp=IP.toLocal8Bit();
        char* IP_cstr=temp.data();
        unsigned long ip_tmp=inet_addr(IP_cstr);
        memcpy(&(_Arp_Header->SrcIp),&ip_tmp,
               sizeof(unsigned long));
     }
    void SetArpOperationCode(unsigned short Opcode)
    {
        _Arp_Header->OperationCode=htons(Opcode);
    }
    void SetArpHardwareType(unsigned short Type)
    {
        _Arp_Header->HardwareType=htons(Type);
    }
    void SetArpHardwareLength(unsigned char Length)
    {
        _Arp_Header->HardwareLength=Length;
    }
    void SetArpProtocolType(unsigned short Type)
    {
        _Arp_Header->ProtocolType=htons(Type);
    }
    void SetArpProtocolLength(unsigned char Length)
    {
        _Arp_Header->ProtocolLength=Length;
    }

private:
    int _Begin_Pos;
    int _End_Pos;
    arp_hdr* _Arp_Header;
}
class NetProtocolTools
{
public:
    NetProtocolTools();
};

#endif // NETPROTOCOLTOOLS_H
