#ifndef NETPROTOCOLTOOLS_H
#define NETPROTOCOLTOOLS_H
#include "NetProtocol.h"
#include "NetTools.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <QByteArray>
#include <QVector>
#include <QPair>
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
    NetPacket();
    NetPacket(int Pack_Capacity);
    NetPacket(const char* Data,int Size);
    NetPacket(const NetPacket& Packet)=delete;
    NetPacket& operator=(const NetPacket& rhs)=delete;
    int GetPacketSize();
    int GetPacketCapacity();
    const char* Dump() const;
    virtual void BuildFromRawData(const char* Data,int Size);
    //int JungePacketType();
    ~NetPacket();
protected:
    void ReginsterHeaderPoint(void* PHeader,int Hdr_offset);
    void ExpandCapacity(int New_Size);
    void AppendData(void* Phdr,int Size);
    char* Packet_Data;
private:
//    QVector< QPair<char**,int> > _RHPList;//RegisterHeaderPointList
//    void _UpdataChildHeaderAddr();
    int _Capacity;
    int _FillSize;
};
class Ether_Packet:public NetPacket
{
public:
    Ether_Packet();
    Ether_Packet(int Size);
    /*Setter*/
    void SetEtherDestMac(QString Mac);
    void SetEtherDestMac(const char* Mac);
    void SetEtherDestMac(Raw_Mac Mac);
    void SetEtherSrcMac(QString Mac);
    void SetEtherSrcMac(const char* Mac);
    void SetEtherSrcMac(Raw_Mac Mac);
    void SetEtherType(unsigned short Type);
    /*Getter*/
    QString GetEtherDestMac();
    Raw_Mac GetRawEtherDestMac();
    QString GetEtherSrcMac();
    Raw_Mac GetRawEtherSrcMac();
    unsigned short GetEtherType();
    virtual void BuildFromRawData(const char* Data,int Size);
private:
    int _Begin_Pos;
    int _End_Pos;
    ether_hdr* _Ether_Header;
};

class Arp_Packet:public Ether_Packet
{
public:
    Arp_Packet();
    virtual void BuildFromRawData(const char* Data,int Size);
    /*Setter*/
    void SetArpDestMac(QString Mac);
    void SetArpDestMac(const char* Mac);
    void SetArpDestMac(Raw_Mac Mac);

    void SetArpSrcMac(QString Mac);
    void SetArpSrcMac(const char* Mac);
    void SetArpSrcMac(Raw_Mac Mac);

    void SetArpDestIP(QString IP);
    void SetArpDestIP(const char* IP);
    void SetArpDestIP(unsigned long IP);

    void SetArpSrcIP(QString IP);
    void SetArpSrcIP(const char* IP);
    void SetArpSrcIP(unsigned long IP);

    void SetArpOperationCode(unsigned short Opcode);
    void SetArpHardwareType(unsigned short Type);
    void SetArpHardwareLength(unsigned char Length);
    void SetArpProtocolType(unsigned short Type);
    void SetArpProtocolLength(unsigned char Length);
    /*Getter*/
    QString GetArpDestMac();
    Raw_Mac GetRawArpDestMac();

    QString GetArpSrcMac();
    Raw_Mac GetRawArpSrcMac();
    QString GetArpDestIP();
    unsigned long GetRawArpDestIP();
    QString GetArpSrcIP();
    unsigned long GetRawArpSrcIP();
    unsigned short GetArpOperationCode();
    unsigned short GetArpHardwareType();
    unsigned char GetArpHardwareLength();
    unsigned short GetArpProtocolType();
    unsigned char GetArpProtocolLength();
private:
    int _Begin_Pos;
    int _End_Pos;
    arp_hdr* _Arp_Header;
};


#endif // NETPROTOCOLTOOLS_H
