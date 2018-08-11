#include <stdio.h>
#include <stdint.h>
#include <dpdk.h>
#include <inet.h>
#include <inetaddr.h>
//#include <netinet/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include <ns_typedefs.h>
#include <macros.h>
#include <ns_dbg.h>
#include <ioctl.h>
#include <utils.h>


DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////

extern struct timezone sys_tz;

//////////////////////////////////////////////////////

desc_proto_t* ns_get_protocol_desc(uint8_t p);
char* ns_get_nic_name_by_idx(int32_t ifidx, char* buf);
uint32_t inet_addr_get_port_ip(int af, uint16_t port_id);


/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

uint8_t icmp_type_invmap[] = {
	[ICMP_ECHO] = ICMP_ECHOREPLY + 1,
	[ICMP_ECHOREPLY] = ICMP_ECHO + 1,
	[ICMP_TIMESTAMP] = ICMP_TIMESTAMPREPLY + 1,
	[ICMP_TIMESTAMPREPLY] = ICMP_TIMESTAMP + 1,
	[ICMP_INFO_REQUEST] = ICMP_INFO_REPLY + 1,
	[ICMP_INFO_REPLY] = ICMP_INFO_REQUEST + 1,
	[ICMP_ADDRESS] = ICMP_ADDRESSREPLY + 1,
	[ICMP_ADDRESSREPLY] = ICMP_ADDRESS + 1
};

#define NDISC_NEIGHBOUR_SOLICITATION    135
#define NDISC_NEIGHBOUR_ADVERTISEMENT   136
uint8_t icmp6_type_invmap[] = {
	[ICMPV6_ECHO_REQUEST - 128]	= ICMPV6_ECHO_REPLY + 1,
	[ICMPV6_ECHO_REPLY - 128]	= ICMPV6_ECHO_REQUEST + 1,
	[NDISC_NEIGHBOUR_SOLICITATION - 128] = NDISC_NEIGHBOUR_ADVERTISEMENT + 1,
	[NDISC_NEIGHBOUR_ADVERTISEMENT - 128] = NDISC_NEIGHBOUR_SOLICITATION + 1,
	[ICMPV6_NI_QUERY - 128]		= ICMPV6_NI_REPLY + 1,
	[ICMPV6_NI_REPLY - 128]		= ICMPV6_NI_QUERY +1

};


desc_proto_t desc_p [] = {
//{	  0,     "HOPOPT",		"IPv6 Hop-by-Hop Option "},
{	  0,     "IP",			"Internet Protocol"},
{     1,     "ICMP",		"Internet Control Message"},
{     2,     "IGMP",		"Internet Group Management"},
{     3,     "GGP",			"Gateway-to-Gateway"},
{     4,     "IP",			"IP in IP (encapsulation)"},
{     5,     "ST",			"Stream"},
{     6,     "TCP",			"Transmission Control"},
{     7,     "CBT",			"CBT"},
{     8,     "EGP",			"Exterior Gateway Protocol"},
{     9,     "IGP",			"any private interior gateway (used by Cisco for their IGRP)"},
{    10,     "BBN-RCC-MON",	" BBN RCC Monitoring"},
{    11,     "NVP-II",		"Network Voice Protocol"},
{    12,     "PUP",			"PUP"},
{    13,     "ARGUS",		"ARGUS"},
{    14,     "EMCON",		"EMCON"},
{    15,     "XNET",		"Cross Net Debugger"},
{    16,     "CHAOS",		"Chaos"},
{    17,     "UDP",			"User Datagram"},
{    18,     "MUX",			"Multiplexing"},
{    19,     "DCN-MEAS",	"DCN Measurement Subsystems"},
{    20,     "HMP",			"Host Monitoring"},
{    21,     "PRM ",		"Packet Radio Measurement"},
{    22,     "XNS-IDP",		"XEROX NS IDP"},
{    23,     "TRUNK-1",		"Trunk-1"},
{    24,     "TRUNK-2",		"Trunk-2"},
{    25,     "LEAF-1",		"Leaf-1"},
{    26,     "LEAF-2",		"Leaf-2"},
{    27,     "RDP",			"Reliable Data Protocol"},
{    28,     "IRTP",		"Internet Reliable Transaction"},
{    29,     "ISO-TP4",		"ISO Transport Protocol Class 4"},
{    30,     "NETBLT",		"Bulk Data Transfer Protocol"},
{    31,     "MFE-NSP",		"MFE Network Services Protocol"},
{    32,     "MERIT-INP",	"MERIT Internodal Protocol"},
{    33,     "SEP",			"Sequential Exchange Protocol"},
{    34,     "3PC",			"Third Party Connect Protocol"},
{    35,     "IDPR",		"Inter-Domain Policy Routing Protocol"},
{    36,     "XTP",			"XTP"},
{    37,     "DDP",			"Datagram Delivery Protocol"},
{    38,     "IDPR-CMTP",	"IDPR Control Message Transport Protocol"},
{    39,     "TP++",		"TP++ Transport Protocol"},
{    40,     "IL",			"IL Transport Protocol"},
{    41,     "ISATAP",		"ISATAP"},
{    42,     "SDRP",		"Source Demand Routing Protocol"},
{    43,     "IPv6-Route",	"Routing Header for IPv6"},
{    44,     "IPv6-Frag",	"Fragment Header for IPv6"},
{    45,     "IDRP",		"Inter-Domain Routing Protocol"},
{    46,     "RSVP",		"Reservation Protocol"},
{    47,     "GRE",			"General Routing Encapsulation"},
{    48,     "MHRP",		"Mobile Host Routing Protocol"},
{    49,     "BNA",			"BNA"},
{    50,     "ESP",			"Encap Security Payload for IPv6"},
{    51,     "AH",			"Authentication Header for IPv6"},
{    52,     "I-NLSP",		"Integrated Net Layer Security  TUBA"},
{    53,     "SWIPE",		"IP with Encryption"},
{    54,     "NARP",		"NBMA Address Resolution Protocol"},
{    55,     "MOBILE",		"IP Mobility"},
{    56,     "TLSP",		"Transport Layer Security Protocol using Kryptonet key management"},
{    57,     "SKIP",		"SKIP"},
{    58,     "IPv6-ICMP",	"ICMP for IPv6"},
{    59,     "IPv6-NoNxt",	"No Next Header for IPv6"},
{    60,     "IPv6-Opts",	"Destination Options for IPv6"},
{    61,     "Unknown",		"any host internal protocol"},
{    62,     "CFTP",		"CFTP"},
{    63,     "Unknown",		"any local network"},
{    64,     "SAT-EXPAK",	"SATNET and Backroom EXPAK"},
{    65,     "KRYPTOLAN",	"Kryptolan"},
{    66,     "RVD",			"MIT Remote Virtual Disk Protocol"},
{    67,     "IPPC ",		"Internet Pluribus Packet Core"},
{    68,     "Unknown",		"any distributed file system"},
{    69,     "SAT-MON",		"SATNET Monitoring"},
{    70,     "VISA",		"VISA Protocol"},
{    71,     "IPCV",		"Internet Packet Core Utility"},
{    72,     "CPNX",		"Computer Protocol Network Executive"},
{    73,     "CPHB",		"Computer Protocol Heart Beat"},
{    74,     "WSN",			"Wang Span Network"},
{    75,     "PVP",			"Packet Video Protocol"},
{    76,     "BR-SAT-MON",	"Backroom SATNET Monitoring"},
{    77,     "SUN-ND",		"SUN ND PROTOCOL-Temporary"},
{    78,     "WB-MON",		"WIDEBAND Monitoring"},
{    79,     "WB-EXPAK",	"WIDEBAND EXPAK"},
{    80,     "ISO-IP",		"ISO Internet Protocol"},
{    81,     "VMTP",		"VMTP"},
{    82,     "SECURE-VMTP",	"SECURE-VMTP"},
{    83,     "VINES",		"VINES"},
{    84,     "TTP",			"TTP"},
{    85,     "NSFNET-IGP",	"NSFNET-IGP"},
{    86,     "DGP",			"Dissimilar Gateway Protocol"},
{    87,     "TCF",			"TCF"},
{    88,     "EIGRP",		"EIGRP"},
{    89,     "OSPFIGP",		"OSPFIGP"},
{    90,     "Sprite-RPC",	"Sprite RPC Protocol"},
{    91,     "LARP",		"Locus Address Resolution Protocol"},
{    92,     "MTP",			"Multicast Transport Protocol"},
{    93,     "AX.25",		"AX.25 Frames"},
{    94,     "IPIP",		"IP-within-IP Encapsulation Protocol"},
{    95,     "MICP",		"Mobile Internetworking Control Protocol"},
{    96,     "SCC-SP",		"Semaphore Communications Sec. Protocol"},
{    97,     "ETHERIP",		"Ethernet-within-IP Encapsulation"},
{    98,     "ENCAP",		"Encapsulation Header"},
{    99,     "Unknown",		"any private encryption scheme"},
{   100,     "GMTP",		"GMTP"},
{   101,     "IFMP",		"Ipsilon Flow Management Protocol"},
{   102,     "PNNI",		"PNNI over IP"},
{   103,     "PIM",			"Protocol Independent Multicast"},
{   104,     "ARIS",		"ARIS"},
{   105,     "SCPS",		"SCPS"},
{   106,     "QNX",			"QNX"},
{   107,     "A/N",			"Active Networks"},
{   108,     "IPComp",		"IP Payload Compression Protocol"},
{   109,     "SNP",			"Sitara Networks Protocol"},
{   110,     "Compaq-Peer",	"Compaq Peer Protocol"},
{   111,     "IPX-in-IP",	"IPX in IP"},
{   112,     "VRRP",		"Virtual Router Redundancy Protocol"},
{   113,     "PGM ",		"PGM Reliable Transport Protocol"},
{   114,     "Unknown",		"any 0-hop protocol"},
{   115,     "L2TP",		"Layer Two Tunneling Protocol"},
{   116,     "DDX",			"D-II Data Exchange (DDX)"},
{   117,     "IATP",		"Interactive Agent Transfer Protocol"},
{   118,     "STP",			"Schedule Transfer Protocol"},
{   119,     "SRP",			"SpectraLink Radio Protocol"},
{   120,     "UTI",			"UTI"},
{   121,     "SMP",			"Simple Message Protocol"},
{   122,     "SM",			"SM"},
{   123,     "PTP",			"Performance Transparency Protocol"},
{   124,     "ISIS",		"over IPv4"},
{   125,     "FIRE",		"Fire"},
{   126,     "CRTP",		"Combat Radio Transport Protocol"},
{   127,     "CRUDP",		"Combat Radio User Datagram"},
{   128,     "SSCOPMCE",	" "},
{   129,     "IPLT",		" "},
{   130,     "SPS",			"Secure Packet Shield"},
{   131,     "PIPE",		"Private IP Encapsulation within IP"},
{   132,     "SCTP",		"Stream Control Transmission Protocol"},
{   133,     "FC",			"Fibre Channel"},
{   255,     "Unknown",		"Reserved"},
};

desc_proto_t unassigned_p = {
	134, 	"Unknown", "Unassigned"
};


#if defined(__LITTLE_ENDIAN)
void ns_dec_ip(ip4_t *ip)
{
	char* str_ip = (char*)ip;

	if (ip == NULL)
		return;

	str_ip[0] --;
}

void ns_inc_ip(ip4_t* ip)
{
	char* str_ip = (char*)ip;

	if (ip == NULL)
		return;

	str_ip[0] ++;
}
#elif defined(__BIG_ENDIAN)

void ns_dec_ip(ip4_t *ip)
{
	char* str_ip = (char*)ip;

	if (ip == NULL)
		return;

#error "We'll need to get a test on BIG endian mode, Please call patrick !!"
//	str_ip[3] --;
}

void ns_inc_ip(ip4_t* ip)
{
	char* str_ip = (char*)ip;

	if (ip == NULL)
		return;

#error "We'll need to get a test on BIG endian mode, Please call patrick !!"
//	str_ip[3] ++;
}
#else
#error Not defined Endian Mode
#endif

#if 0
int32_t ns_is_local_address(ip4_t ip)
{
	struct net_device *dev = NULL;

	ENT_FUNC(3);

	dev = ip_dev_find(&init_net, ip);

	if (dev)
		dev_put(dev);

	return dev != NULL;

#if 0
	if (inet_addr_type(net, fl.fl4_src) == RTN_LOCAL) {
	}
#endif

}

int32_t ns_is_zeronet(ip4_t ip)
{
	return (ipv4_is_zeronet(ip));
}

#define ADDR_LOOPBACK 	0x0100007f
int32_t ns_is_loopback(ip4_t ip)
{
	ENT_FUNC(3);

	return (ip == ADDR_LOOPBACK);
}

int32_t ns_is_loopback6(ip_t* ip)
{
	return ipv6_addr_loopback((const struct in6_addr *)ip);
}

int32_t ns_is_local_broadcast(ip4_t addr)
{

	if ((addr & htonl(0x000000FF)) == htonl(0x000000FF))
		return 1;

	if ((addr & htonl(0x0000FFFF)) == htonl(0x0000FFFF))
		return 1;

	if ((addr & htonl(0x00FFFFFF)) == htonl(0x00FFFFFF))
		return 1;

	return 0;
}

#endif

desc_proto_t* ns_get_protocol_desc(uint8_t p)
{
	int32_t i,asize;
	desc_proto_t *dp=&unassigned_p;

	// init
	dp->p = p;

	asize = sizeofa(desc_p);

	for (i=0; i<asize; i++) {
		if (desc_p[i].p == p) {
			dp = &desc_p[i];
			break;
		}
	}
	
	return dp;
}

char* ns_get_protocol_name(uint8_t p)
{
	desc_proto_t* pd = ns_get_protocol_desc(p);

	if (pd)
		return pd->name;

	return "Unknown";
}

uint8_t ns_get_inv_icmp_type(uint8_t icmp_type, uint32_t fflag)
{
	if (fflag & FUNC_FLAG_IPV6)
		return (icmp6_type_invmap[icmp_type-128]-1);
	else
		return (icmp_type_invmap[icmp_type]-1);
}

uint32_t ns_get_nic_ip(uint32_t if_idx)
{
	return inet_addr_get_port_ip(AF_INET, (uint16_t)if_idx);
}

uint8_t ns_get_nic_idx_by_ip(ip4_t ip)
{
	struct netif_port *dev;
	union inet_addr a;

	a.in.s_addr = ip;

	dev = inet_addr_get_iface(AF_INET, &a);
	if (dev) {
		return (uint8_t)dev->id;
	}

	return IFACE_IDX_MAX;
}

int copy_expand(ioctl_data_t *iodata, uint8_t *src, int srclen, int extlen)
{
	uint8_t *p = iodata->out; 

	if ((iodata->out_buf_len - iodata->outsize) < srclen) {
		iodata->out_buf_len += (srclen < extlen ? extlen:srclen+extlen);
		p = rte_realloc(p, iodata->out_buf_len, 1);

		if (p == NULL) {
			iodata->out_buf_len = 0;
			iodata->outsize = 0;
			
			if (iodata->out) {
				iodata->out = NULL;
				rte_free(iodata->out);	
			}

			return -1;
		}

		iodata->out = p;
	}

	memcpy(&p[iodata->outsize], src, srclen);
	iodata->outsize += srclen;

	return 0;
}


