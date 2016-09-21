#undef  UNICODE
#undef _UNICODE

#ifndef WIN32
#define WIN32
#endif
#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")

#include <stdio.h>
#include <tchar.h>
#include <pcap.h>
#include <winsock2.h>
#include <string.h>
#include <memory.h> 

struct mac_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
};

struct ether_header
{
	struct mac_address	ether_dhost;
	struct mac_address	ether_shost;
	u_short				ether_type;
};

struct ip_address
{
	u_char		byte1;
	u_char		byte2;
	u_char		byte3;
	u_char		byte4;
};

struct ip_header
{
	u_char			ip_leng : 4;
	u_char			ip_version : 4;
	u_char			typeOfService;
	u_short		totalLen;
	u_short		identification;
	u_short		flags_fo;				
	u_char			ttl;
	u_char			proto;
	u_short		crc;
	ip_address		saddr;
	ip_address		daddr;
	u_int			op_pad;
};

struct tcp_header
{
	u_short		sport;			// Source port
	u_short		dport;			// Destination port
	u_int			seqnum;			// Sequence Number
	u_int			acknum;			// Acknowledgement number
	u_char			th_off;			// Header length
	u_char			flags;			// packet flags
	u_short		win;				// Window size
	u_short		crc;				// Header Checksum
	u_short		urgptr;			// Urgent pointer
	u_int			op_pad[10];	// option & padding
};

#pragma pack(push, 1)
struct ptcp_header
{
	ip_address		saddr;
	ip_address		daddr;
	u_char			reser;
	u_char			proto;
	u_short		tcp_seg;		// TCP header + data
	tcp_header		tcph;
};
#pragma pack(pop)

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
USHORT tcp_checksum_calc(const u_char* pkt_data, struct tcp_header* th, struct ip_header* ih);


int _tmain(int argc, TCHAR* argv[])
{
	pcap_if_t* alldevs;
	pcap_if_t* dev;
	pcap_t* adhandle;
	TCHAR errbuf[PCAP_ERRBUF_SIZE];
	INT inum;
	INT i = 0;
	struct bpf_program fcode;				
	TCHAR packet_filter[] = "tcp";		
	u_int netmask = 0 ;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		_ftprintf(stderr, _T("Error in pcap_findalldevs : %s\n"), errbuf);
		exit(1);
	}

	for (dev = alldevs; dev; dev = dev->next)
	{
		_tprintf(_T("%d. %s"), ++i, dev->name);	
		if (dev->description)
			_tprintf(_T("(%s)\n"), dev->description);	
		else
			_fputts(_T("No description available\n"), stdout);
	}

	if (i == 0)
	{
		_fputts(_T("No interfaces found! Make sure WinPcap is installed.\n"), stdout);
		return -1;
	}

		_tprintf(_T("You choose device (1-%d) : "), i), _tscanf(_T("%d"), &inum);

	
	if (inum < 1 || inum > i)
	{
		_fputts(_T("\nInterFace number out of range.\n"), stdout);
		pcap_freealldevs(alldevs);
		return -1;
	}

	
	for (dev = alldevs, i = 0; i < inum - 1; i++)
		dev = dev->next;	
	if ((adhandle = pcap_open_live(dev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == NULL)
	{
		_ftprintf(stderr, _T("\n%s isn't supported by winpcap\n"), dev->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		_ftprintf(stderr, _T("\nUnable to compile the packet filter. Check the syntax.\n"));
		pcap_freealldevs(alldevs);
		return -1;
	}

	
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		_ftprintf(stderr, _T("\nError setting the filter.\n"));
		pcap_freealldevs(alldevs);
		return -1;
	}

	_tprintf(_T("\nlistening on %s...\n"), dev->description);
	
	pcap_freealldevs(alldevs);
	
	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	pcap_close(adhandle);

	return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
# define IP_HEADER					0x0800
# define ARP_HEADER					0x0806
# define REVERSE_ARP_HEADER		0x0835

# define SYN							0x02
# define PUSH							0x08
# define ACK							0x10
# define SYN_ACK						0x12
# define PUSH_ACK					0x18
# define FIN_ACK						0x11

	FILE* f = fopen("c:\\tcpdump.txt", "at");
		
	

	struct ether_header* eth;						// ethernet header
	eth = (struct ether_header*) pkt_data;
	UINT ptype = ntohs(eth->ether_type);

	ip_header* ih;									// ip header
	ih = (ip_header*)(pkt_data + 14);				

													
	
		_fputts(_T("********************* Ethernet Frame Header **********************\n\n"), stdout);
		_tprintf(_T("Destination Mac Address : %02x.%02x.%02x.%02x.%02x.%02x\n"),
			eth->ether_dhost.byte1, eth->ether_dhost.byte2,
			eth->ether_dhost.byte3, eth->ether_dhost.byte4,
			eth->ether_dhost.byte5, eth->ether_dhost.byte6);
		_tprintf(_T("Source Mac Address	: %02x.%02x.%02x.%02x.%02x.%02x\n\n"),
			eth->ether_shost.byte1, eth->ether_shost.byte2,
			eth->ether_shost.byte3, eth->ether_shost.byte4,
			eth->ether_shost.byte5, eth->ether_shost.byte6);

		if (ptype == IP_HEADER)
		{
			_tprintf(_T("Upper Protocol is IP HEADER (%04x)\n\n"), ptype);
		}
		else if (ptype == ARP_HEADER)
		{
			_tprintf(_T("Upper Protocol is ARP HEADER (%04x)\n\n"), ptype);

		}
		else if (ptype == REVERSE_ARP_HEADER)
		{
			_tprintf(_T("Upper Protocol is REVERSE_ARP_HEADER (%04x)\n\n"), ptype);
		}
		else
		{
			_tprintf(_T("Upper Protocol is Unknown (%04x)\n\n"), ptype);
		}


		if (ntohs(eth->ether_type) == IP_HEADER)
		{
			_fputts(_T("**************************** IP Header ***************************\n\n"), stdout);
			_tprintf(_T("ip version is %d\n"), ih->ip_version);
			_tprintf(_T("ip length is %d byte\n\n"), (ih->ip_leng) * 4);
			_tprintf(_T("Destination IP Address  : %d.%d.%d.%d\n"),
				ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
			_tprintf(_T("Source IP Address	: %d.%d.%d.%d\n\n"),
				ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
			if (ih->proto == 1)
			{
				_fputts(_T("Upper Protocol is ICMP\n\n"), stdout);
			}
			else if (ih->proto == 6)
			{
				_fputts(_T("Upper Protocol is TCP\n"), stdout);
				tcp_header* th;
				th = (tcp_header*)((u_char*)ih + (ih->ip_leng) * 4);

				_fputts(_T("**************************** TCP Header **************************\n\n"), stdout);
				_tprintf(_T("Destination port number : %d\n"), ntohs(th->dport));
				_tprintf(_T("Source port number : %d\n"), ntohs(th->sport));


				if (th->flags == SYN)
					_fputts(_T("Flags : SYN\n\n"), stdout);
				else if (th->flags == PUSH)
					_fputts(_T("Flags : PUSH\n\n"), stdout);
				else if (th->flags == ACK)
					_fputts(_T("Flags : ACK\n\n"), stdout);
				else if (th->flags == SYN_ACK)
					_fputts(_T("Flags : SYN_ACK\n\n"), stdout);
				else if (th->flags == PUSH_ACK)
					_fputts(_T("Flags : PUSH_ACK\n\n"), stdout);
				else if (th->flags == FIN_ACK)
					_fputts(_T("Flags : FIN_ACK\n\n"), stdout);
				else
					_tprintf(_T("Flags (Unknown) : %04x\n"), th->flags);
			}
			else if (ih->proto == 11)
			{
				_fputts(_T("Upper Protocol is UDP\n\n"), stdout);
			}
			else
			{
				_fputts(_T("Upper Protocol is Unknown\n\n"), stdout);
			}

			_fputts(_T("******************************************************************\n\n\n"), stdout);
		}
		else
		{
			_fputts(_T("************************** NO IP Header *************************\n\n\n"), stdout);
		}
	
	fclose(f);
}

USHORT tcp_checksum_calc(const u_char* pkt_data, struct tcp_header* th, struct ip_header* ih)
{
	struct ptcp_header pth = { 0, };
	PUSHORT	uspth = (PUSHORT)&pth;
	ULONG		psum = 0;
	USHORT	startDataPointer = 0;								
	USHORT	tcpHeaderLen = (th->th_off >> 4) * 4;
	USHORT	ipHeaderLen = ih->ip_leng * 4;

	

	int			len = (sizeof(pth) - sizeof(pth.tcph.op_pad)		
		+ ((th->th_off >> 4) * 4 - 20))			//len 길이만큼 루프, 현재 패딩 길이가 40 으로 패킷을 캡쳐했을 때 패딩길이는 다를 수 도 있어 원래 패딩 길이를 뺀 뒤, 패킷으로 잡은 패딩 길이를 정확히 넣어준다
		


		/ sizeof(USHORT);							

	pth.saddr = ih->saddr, pth.daddr = ih->daddr;
	pth.reser = 0x0, pth.proto = ih->proto;
	pth.tcp_seg = htons(ntohs(ih->totalLen) - ipHeaderLen);		// 직접계산한 값이므로 빅 엔디안으로 변환
	memcpy(&pth.tcph, th, sizeof(tcp_header)), pth.tcph.crc = 0x0;		// tcp 헤더

	while (len--)			// 가상헤더값을 2바이트씩 가져옴
	{
		psum += ntohs(*(uspth++));
	}

	len = (ntohs(ih->totalLen) - ipHeaderLen - tcpHeaderLen) / sizeof(USHORT);
	startDataPointer = sizeof(ether_header) + ipHeaderLen + tcpHeaderLen;
	uspth = (PUSHORT)(pkt_data + startDataPointer);				// 시작점을 data로 바꿈

	while (len--)
	{
		psum += ntohs(*(uspth++));
	}

	// data 길이가 홀수 일때를 위해 여기서 계산
	// 2 바이트로 맞추기위해 하위 4비트에 0x0을 넣음.
	len = (ntohs(ih->totalLen) - ipHeaderLen - tcpHeaderLen);
	if ((len & 1) == 1)
	{
		psum += ((u_char)(*uspth) << 8) | 0x0;
	}

	return (USHORT)(~((psum & 0xffff) + (psum >> 16)));
}