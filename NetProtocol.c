#include "NetTools.h"
#include "NetProtocol.h"



static int FillEthHdr(u_char* Packet, size_t len, u_char* SRC_Mac, u_char* DST_Mac, unsigned short	EtherType)
{
	if (len < sizeof(ETHER_HEADER))
		return -1;
	ETHER_HEADER* EthHdr = (ETHER_HEADER*)Packet;

	memcpy(EthHdr->EtherSrcHost, SRC_Mac, sizeof(unsigned char) * 6);
	memcpy(EthHdr->EtherDestHost, DST_Mac, sizeof(unsigned char) * 6);
	EthHdr->EtherType = htons(EtherType);

	return 0;
}
int FillArpHdr(u_char* packet, size_t len, u_short op, u_char* SRC_Mac, u_char* SRC_IP, u_char* DST_Mac, u_char* DST_IP)
{
	if (len < sizeof(ETHER_HEADER) + sizeof(ARP_HEADER))
	{
		return -1;
	}

	FillEthHdr(packet, len, SRC_Mac, DST_Mac, 0X0806);
	u_char* pHdr = (packet + sizeof(ETHER_HEADER)*sizeof(u_char));
	ARP_HEADER* ArpHdr = (ARP_HEADER*)pHdr;

	ArpHdr->HardwareType = htons(0x0001);
	ArpHdr->ProtocolType = htons(0x0800);
	ArpHdr->HardwareLength = 0x06;
	ArpHdr->ProtocolLength = 0x04;
	//ARP包类型为ARP请求
	ArpHdr->OperationCode = htons(op);

	memcpy(ArpHdr->EtherSrcHost, SRC_Mac, sizeof(unsigned char) * 6);
	memcpy(ArpHdr->EtherDestHost, DST_Mac, sizeof(unsigned char) * 6);
	memcpy(ArpHdr->SrcIp, SRC_IP, sizeof(unsigned char) * 4);
	memcpy(ArpHdr->DestIp, DST_IP, sizeof(unsigned char) * 4);

	return 0;
}
size_t BuildArPacket(u_char** packet, u_short op, u_char* SRC_Mac, u_char* SRC_IP, u_char* DST_Mac, u_char* DST_IP)
{
	size_t pack_len = (sizeof(struct ether_hdr) + sizeof(struct arp_hdr))*sizeof(u_char);
	*packet = malloc(pack_len);
	memset(*packet, 0, pack_len);

	FillArpHdr(*packet, pack_len, op, SRC_Mac, SRC_IP, DST_Mac, DST_IP);

	return pack_len;
	
}
