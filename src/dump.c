#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include "dpdk.h"
#include "ns_type_defs.h"

static void print_hex_ascii_line(const uint8_t *payload, int len, int offset)
{
	int i;
	int gap;
	const uint8_t *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const char *msg, const uint8_t *payload, int len)
{
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const uint8_t *ch = payload;

	if (len <= 0)
		return;

	printf("===== %s =====\n", msg);

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		printf("================\n");
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	printf("================\n");
}

void dump_pkt(char* func, int32_t line, iph_t *iph, uint8_t inic)
{
	uint8_t* data;
	tcph_t* t = NULL;
	udph_t* u = NULL;
	struct icmphdr* ic = NULL;
	uint16_t sp, dp;
	char buf[256];
	char *p;
	//desc_proto_t *p_desc;
	//char nic_name[IFNAMSIZ+1];

#if 0
	data = (uint8_t *)iph + (iph->ihl << 2);
	//p_desc = ns_get_protocol_desc(iph->protocol);

	switch (iph->protocol) {
	case IPPROTO_UDP:
		u = (udph_t*)data;
		sp = ntohs(u->source);
		dp = ntohs(u->dest);

		break;

	case IPPROTO_TCP:
		t = (tcph_t*)data;
		sp = ntohs(t->source);
		dp = ntohs(t->dest);

		break;

	case IPPROTO_ICMP:
		ic = (struct icmphdr*)data;
		sp = ic->type;
		dp =  ntohs(ic->un.echo.id);
		break;

	default:
		dp = sp = 0;
	};

	if (inic > 0 ) {
		p = ns_get_nic_name_by_idx(inic, nic_name);
	}
	else {
		p = NULL;
	}

	//snprintf(buf, 256, "NetShield: " NS_FUNC_FMT "Packet Dump:iph=0x%p NIC=%s(%u):", func, line, iph, p?p:"NULL", inic);
	snprintf(buf, 256, "NetShield: " NS_FUNC_FMT "Packet Dump:NIC=%s(%u):", func, line, p?p:"NULL", inic);

	if (iph->protocol == IPPROTO_ICMP) {
		printk("%s"IP_FMT "->" IP_FMT ":%s(%d)-type:%d id:%d code:%d seq:%d \n",
			   buf,
			   IPN(iph->saddr),
			   IPN(iph->daddr),
			   p_desc->name,
			   iph->protocol, sp, dp, ic->code, ic->un.echo.sequence);
	}
	else {
		printk("%s"IP_FMT ":%d->" IP_FMT ":%d: %s(%d) \n",
			   buf,
			   IPN(iph->saddr),
			   sp,
			   IPN(iph->daddr),
			   dp,
			   p_desc->name,
			   iph->protocol);
	}
#endif
}

void dump_eth_pkt(char* data, int32_t len, char *msg)
{
	int32_t i;
	uint32_t c;

#if 0
	printk("===== %s =====\n", msg);

	for (i=0; i<len; i++) {

		if (i>0 && (i%8) == 0)
			printk("\n");

		c = (uint32_t)(data[i] & 0x000000ff);
		printk("0x%02x(%c) ", c, c<128?isalnum(c)?c:' ':' ');

	}

	printk("\n");
#endif

}

