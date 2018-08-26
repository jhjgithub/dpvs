#include <stdio.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <dpdk.h>
#include <ipv4.h>
#include <ns_typedefs.h>
#include <macros.h>
#include <netshield.h>
#include <ns_task.h>
#include <cmds.h>
#include <ns_dbg.h>
#include <dump.h>
#include <utils.h>
#include <tcp_opt.h>

//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(2);

uint16_t parse_ip_options(iph_t* iph);
int32_t parse_tcp_options(ns_task_t* nstask);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */

int32_t build_icmp_key(const char *data, skey_t *skey, int32_t *pkt_len, uint32_t *flags)
{
	int32_t ret = 0;
	uint8_t icmp_type[2] = {0 , 0};
	icmph_t *ic = NULL;

	ic = (icmph_t *)data;
	*pkt_len += sizeof(icmph_t);

	/*
	 *	18 is the highest 'known' ICMP type. Anything else is a mystery
	 *	RFC 1122: 3.2.2  Unknown ICMP messages types MUST be silently  discarded.
	 *	from netfilter
	 */

	if (ic->type > NR_ICMP_TYPES) {
		ns_err("Invalid ICMP type : %d", ic->type);
		return -1;
	}

	// icmp type
	icmp_type[0] = ic->type;
	icmp_type[1] = 0;
	skey->sp = 0;

	switch (ic->type) {
	case ICMP_ECHOREPLY:
	case ICMP_ECHO:
		// icmp id를 채운다.
		skey->sp = ntohs(ic->un.echo.id);
		icmp_type[1] = ns_get_inv_icmp_type(ic->type, 0);
		break;

	case 9:
	case 10:
		break;

	case ICMP_TIMESTAMP:
	case ICMP_TIMESTAMPREPLY:
		*pkt_len += 12;
		icmp_type[1] = ns_get_inv_icmp_type(ic->type, 0);
		break;

	case ICMP_INFO_REQUEST:
	case ICMP_INFO_REPLY:
		icmp_type[1] = ns_get_inv_icmp_type(ic->type, 0);
		break;

	case ICMP_ADDRESS:
	case ICMP_ADDRESSREPLY:
		icmp_type[1] = ns_get_inv_icmp_type(ic->type, 0);
		*pkt_len += 4;
		break;

	case ICMP_DEST_UNREACH:
	case ICMP_SOURCE_QUENCH:
	case ICMP_REDIRECT:
	case ICMP_TIME_EXCEEDED:
	case ICMP_PARAMETERPROB:
		*pkt_len += (sizeof(iph_t) + 8);
		*flags |= TASK_FLAG_ICMPERR;

		break;

	default:
		break;
	}

	skey->dp = icmp_type[0] ^ icmp_type[1];

	return ret;
}

int32_t build_skey(iph_t *iph, skey_t *skey, int32_t *pkt_len, uint32_t *flags)
{
	int32_t hlen = *pkt_len;
	uint8_t *data = (uint8_t *)iph + hlen;
	tcph_t *t = NULL;
	udph_t *u = NULL;
	icmph_t *ic = NULL;
	int32_t ret = 0;

	ENT_FUNC(3);

	// 패킷 정보를 이용해서 룰 검색 데이터를 만든다.
	// 영역 검사 등 비교를 위해서는 host order로 저장 되어야 한다.
	skey->src = ntohl(iph->src_addr);
	skey->dst = ntohl(iph->dst_addr);
	skey->proto = iph->next_proto_id;

	switch (iph->next_proto_id) {
	case IPPROTO_UDP:
		u = (udph_t *)data;
		*pkt_len += sizeof(struct udphdr);

		skey->sp = ntohs(u->source);
		skey->dp = ntohs(u->dest);

		break;

	case IPPROTO_TCP:
		t = (tcph_t *)data;
		*pkt_len += sizeof(tcph_t);

		skey->sp = ntohs(t->source);
		skey->dp = ntohs(t->dest);

		break;

	case IPPROTO_ICMP: 
		ret = build_icmp_key(data, skey, pkt_len, flags);
		break;

	default:
		// 나머지 프로토콜은 src/dst ip만으로 구분한다.
		skey->sp = 0;
		skey->dp = 0;

		break;
	}

	return ret;
}

int32_t parse_inet_protocol(ns_task_t *nstask)
{
	skb_t *skb;
	iph_t *iph;
	tcph_t *th;
	int32_t dlen;

	ENT_FUNC(3);

	skb = ns_get_skb(nstask);
	iph = ns_iph(skb);

	// XXX dlen과 iph->tot_len이 같은지 검사해야 한다 !
	//dlen = ntohs(iph->total_length);
	dlen = skb->pkt_len;
	nstask->ip_hlen = ip4_hdrlen(skb);

	// is this correct length ?
	if (nstask->ip_hlen > dlen) {
		return NS_DROP;
	}

	nstask->ip_dlen = dlen - nstask->ip_hlen;
	// no more IP data
	if (nstask->ip_dlen < 1) {
		nstask->ip_dlen = 0;

		return NS_ACCEPT;
	}

	nstask->l4_hlen = 0;
	nstask->l4_dlen = 0;
	nstask->iopt = parse_ip_options(iph);

	switch (iph->next_proto_id) {
	case IPPROTO_TCP:
		th = rte_pktmbuf_mtod_offset(skb, tcph_t *, nstask->ip_hlen);
		//uh = rte_pktmbuf_mtod_offset(skb, struct udp_hdr *, sizeof(struct ether_hdr) + 
		// (IPV4_HDR_IHL_MASK & iph->version_ihl) * sizeof(uint32_t));
		//th = mbuf_header_pointer(mbuf, iph->len, sizeof(_tcph), &_tcph);
		//nstask->l4_hlen = ns_tcph(nstask->pkt)->doff << 2;
		nstask->l4_hlen = th->doff << 2;

		parse_tcp_options(nstask);
		break;

	case IPPROTO_UDP:
		nstask->l4_hlen = sizeof(udph_t);
		break;

	case IPPROTO_ICMP:
		nstask->l4_hlen = sizeof(icmph_t);
		break;

#if 0
	case IPPROTO_AH:
		nstask->l4_hlen = sizeof(ah_t);
		break;

	case IPPROTO_ESP:
		nstask->l4_hlen = sizeof(esp_t);
		break;
#endif

	default:
		break;
	}

	// invalid L4 Header length
	if (nstask->l4_hlen > nstask->ip_dlen) {
		dbg(2, "invalid IP packet !");

		return NS_DROP;
	}

	nstask->l4_dlen = nstask->ip_dlen - nstask->l4_hlen;
	nstask->l4_data = rte_pktmbuf_mtod_offset(skb, void *, nstask->ip_hlen + nstask->l4_hlen);

	dbg(4, "Packet length info: pkt_len=%d, ip_hlen=%d, ip_dlen=%d, l4_hlen=%d, l4_dlen=%d",
		dlen, nstask->ip_hlen, nstask->ip_dlen, nstask->l4_hlen, nstask->l4_dlen);

#if 0
	if (nstask->l4_dlen) {
		print_payload("TCP Payload", (const uint8_t *)nstask->l4_data, nstask->l4_dlen);
	}
#endif

	return NS_ACCEPT;
}

int32_t init_task_info(ns_task_t *nstask)
{
	int32_t ret = NS_ACCEPT;
	skb_t *skb;
	iph_t *iph;
	int32_t pkt_len;

	ENT_FUNC(3);

	skb = ns_get_skb(nstask);
	iph = ns_iph(skb);

	// 패킷 사이즈를 검사할 크기
	pkt_len = nstask->ip_hlen;

	ret = build_skey(iph, &nstask->skey, &pkt_len, &nstask->flags);

	if (unlikely(ret == 0 && nstask->flags & TASK_FLAG_ICMPERR)) {
		uint32_t f;
		uint128_t swap_ip;
		uint16_t swap_port;

		dbg(5, "build_skey for icmp error");

		// icmp error 패킷에는 원본 패킷이 실려 있다.
		iph = (iph_t *)(nstask->l4_data + sizeof(icmph_t));

		DUMP_PKT(4, iph, nstask->skey.inic);

		// icmp error 패킷은 이후 모든 처리를 데이터 부분에 실려 있는 
		// 패킷을 기준으로 처리 한다.
		// nat 인 경우는 별도의 처리가 필요 하다.
		pkt_len = nstask->ip_hlen;
		ret = build_skey(iph, &nstask->skey, &pkt_len, &f);

		// 역방향 키를 찾기 위해서 키를 뒤집는다.
		// 이때 NAT도 역방향 키가 검색 된다.

		// swap ip
		swap_ip = nstask->skey.src;
		nstask->skey.src = nstask->skey.dst;
		nstask->skey.dst = swap_ip;

		// swap port
		swap_port = nstask->skey.sp;
		nstask->skey.sp = nstask->skey.dp;
		nstask->skey.dp = swap_port;

		DBGKEY(0, ICMP_ERR_KEY, &nstask->skey);
	}
	else {
		//DBGKEY(0, NORMAL_KEY, &nstask->skey);
	}

	if (ret != 0) {
		// some error
		ret = NS_DROP;
	}
	else if (mbuf_may_pull(skb, pkt_len) != 0) {
		ns_err("Abnormal sized packet: SRC=" IP_FMT " DST=" IP_FMT " PROTO=%d hsize=%d dsize=%d",
				IPN(iph->src_addr), IPN(iph->dst_addr), iph->next_proto_id, nstask->ip_hlen, 0);
		ret = NS_ACCEPT;
	}
	else {
		ret = NS_ACCEPT;
	}

	DBGKEY(2, SKEY, &nstask->skey);

	return ret;
}

uint16_t parse_ip_options(iph_t* iph)
{
	uint8_t 	*optp;
	int32_t    	optslen = 0;
	int32_t    	optsdone = 0;
	int32_t    	olen;
	uint16_t  	ip_opt_flags = 0;

	optslen = iph->version_ihl * 4 - sizeof(iph_t);
	if (optslen < 1)
		return 0;

	optp = (uint8_t*) iph + sizeof(iph_t);

	while (optsdone < optslen) {
		switch(*optp) {
		case IPOPT_END:
			/*end of option list - RFC791*/
			optsdone = optslen;
			break;

		case IPOPT_NOOP:
			/* No op*/
			optp++;
			optsdone++;
			break;

		case IPOPT_SEC:
		case 133:
			/*Security - see RFC1108*/
			/*we sanity check this, but otherwise pass it normally*/
			optp++;
			olen=*optp;
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= IPOPT_SEC;
			break;

		case IPOPT_LSRR:
			/*Loose Source and Record Route - RFC791*/
			optp++;
			olen=*optp;
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= IPOPT_LSRR;
			break;

		case IPOPT_SSRR:
			/*Strict Source and Record Route - RFC791*/
			optp++;
			olen=*optp;
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= IPOPT_SSRR;
			break;

		case IPOPT_RR:
			/*Record Route - RFC791*/
			optp++;
			olen=*optp;
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= IPOPT_RR;
			break;

		case IPOPT_SID:
			/*Stream ID - RFC791*/
			/*we sanity check this, but otherwise pass it normally*/
			optp++;
			olen=*optp;
			if (olen!=4) {
				dbg(2, "Incorrect stream ID length: %d", olen);
				return ip_opt_flags;
			}
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= IPOPT_SID;
			break;

		case IPOPT_TIMESTAMP:
			/*Internet timestamp - RFC791*/
			/*harmless...*/
			optp++;
			olen=*optp;
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= IPOPT_TIMESTAMP;
			break;

		case IPOPT_RA:
			/*Router Alert - See RFC2113*/
			/*we sanity check this, but otherwise pass it normally*/
			optp++;
			olen=*optp;
			if (olen!=4) {
				dbg(0, "Incorrect router alert length: %d", olen);
				return ip_opt_flags;
			}
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= IPOPT_RA;
			break;

		default:
			optp ++;
			optsdone++;
			dbg(6, "unknown option type: %d", *optp);
			break;
		}

		if (optsdone>optslen) {
			dbg(0, "bogus variable-length IP option");
		}
	}

	return ip_opt_flags;
}

/*
 *	TCP option
 */

#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG		19	/* MD5 Signature (RFC2385) */
#define TCPOPT_FASTOPEN		34	/* Fast open (RFC7413) */
#define TCPOPT_EXP		254	/* Experimental */
/* Magic number to be after the option value for sharing TCP
 * experimental options. See draft-ietf-tcpm-experimental-options-00.txt
 */
#define TCPOPT_FASTOPEN_MAGIC	0xF989

/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_MD5SIG         18
#define TCPOLEN_FASTOPEN_BASE  2
#define TCPOLEN_EXP_FASTOPEN_BASE  4

/* But this is what stacks really send out. */
#define TCPOLEN_TSTAMP_ALIGNED		12
#define TCPOLEN_WSCALE_ALIGNED		4
#define TCPOLEN_SACKPERM_ALIGNED	4
#define TCPOLEN_SACK_BASE		2
#define TCPOLEN_SACK_BASE_ALIGNED	4
#define TCPOLEN_SACK_PERBLOCK		8
#define TCPOLEN_MD5SIG_ALIGNED		20
#define TCPOLEN_MSS_ALIGNED		4

int32_t parse_tcp_options(ns_task_t* nstask)
{
	uint8_t buff[40];
	uint8_t *ptr;
	int32_t length = nstask->l4_hlen - sizeof(struct tcphdr);
	int32_t opsize, i;
	uint32_t tmp;
	skb_t *skb;
	topt_t *topt = (topt_t*)&nstask->topt;

	if (length < 1)
		return 0;

	skb = ns_get_skb(nstask);

	ptr = mbuf_header_pointer(skb, nstask->ip_hlen + nstask->l4_hlen, length, buff);

	if (ptr == NULL)
		return -1;

	topt->td_scale = topt->flags = topt->sack = 0;

	while (length > 0) {
		int32_t opcode=*ptr++;

		switch (opcode) {
		case TCPOPT_EOL:
			return 0;

		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;

		default:
			opsize=*ptr++;

			if (opsize < 2) /* "silly options" */
				return 0;

			if (opsize > length)
				break;	/* don't parse partial options */

			switch(opcode) {
			case TCPOPT_SACK_PERM:
				if (opsize == TCPOLEN_SACK_PERM)
					topt->flags |= TOPT_FLAG_SACK_PERM;
				break;

			case TCPOPT_WINDOW:
				if (opsize == TCPOLEN_WINDOW) {
					topt->td_scale = *(uint8_t *)ptr;

					if (topt->td_scale > 14) {
						/* See RFC1323 */
						topt->td_scale = 14;
					}

					topt->flags |= TOPT_FLAG_WINDOW_SCALE;
				}
				break;

			case TCPOPT_MSS:
				if(opsize == TCPOLEN_MSS) {
					//topt->mss = ntohs(get_unaligned((__u16 *)ptr));
					topt->mss = ntohs(*ptr);
					topt->flags |= TOPT_FLAG_MSS;
				}
				break;

			case TCPOPT_SACK:
				if ( (opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK))
					 && !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK)) {

					for (i = 0; i < (opsize - TCPOLEN_SACK_BASE); i += TCPOLEN_SACK_PERBLOCK) {
						tmp = ntohl(*((u_int32_t *)(ptr+i)+1));

#define after(a1, a2) (a2-a1) < 0
						if (after(tmp, topt->sack)) {
							topt->flags |= TOPT_FLAG_SACK;
							topt->sack = tmp;
						}
					}
				}

				break;

			case TCPOPT_TIMESTAMP:
				if (opsize == TCPOLEN_TIMESTAMP) {
					uint32_t *tsecr;

					topt->flags |= TOPT_FLAG_TIMESTAMP;
					tsecr = (uint32_t*)ptr;

					//opt_rx->rcv_tsval = get_unaligned_be32(ptr);
					topt->tsval = ntohl(*tsecr);
				}

			} // end of opcode

			ptr += opsize - 2;
			length -= opsize;
		}
	}

	dbg(6, "TCP Options: td_sclae=%d, flags=0x%x, mss=%d, sack=%d, tsval=%d \n", 
		topt->td_scale, topt->flags, topt->mss, topt->sack, topt->tsval);

	return 0;
}

///////////////////////////////////

static nscmd_module_t mod_task[] = {
	[0] = {CMD_ITEM(taskinfo, TASKINFO, init_task_info, NULL, NULL, NULL)},
	[1] = {CMD_ITEM(inet, INET, parse_inet_protocol, NULL, NULL, NULL)},
};

static void __attribute__ ((constructor)) net_register(void)
{
	nscmd_register(NSCMD_IDX(taskinfo), &mod_task[0]);
	nscmd_register(NSCMD_IDX(inet), &mod_task[1]);
}

