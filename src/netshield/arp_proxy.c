#include <stdio.h>
#include <stdint.h>
#include <neigh.h>
#include <linux/if_arp.h> 

#include <ns_typedefs.h>
#include <macros.h>
#include "ns_task.h"
#include <ns_dbg.h>
#include <options.h>
#include <ns_malloc.h>
#include <utils.h>
#include <arp_proxy.h>
#include <ioctl.h>


// 방화벽에서 NAT를 사용시 NAT IP에 대한 ARP 응답 모듈
// 동작 방식: 
// ARP protocol handler를 등록해서 ARP 패킷을 수신 한다.
// handler에서는 ARP 패킷이 NAT IP에 대한 요청인 경우
// arp_send()를 이용해서 응답 메세지를 보낸다.

arp_proxy_t g_arpp_root;

DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////

/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

/*
 *	Process an arp request.
 */

int send_arp_reply(struct netif_port *port, int code, uint32_t src_ip, 
				   char *smac, uint32_t dst_ip, char *dmac)
{
    struct rte_mbuf *m;
    struct ether_hdr *eth;
    struct arp_hdr *arp;
    uint32_t addr;

	ENT_FUNC(3);

    m = rte_pktmbuf_alloc(port->mbuf_pool);
    if (unlikely(m==NULL)){
        return EDPVS_NOMEM;
    }

    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    arp = (struct arp_hdr *)&eth[1];

    //memset(&eth->d_addr,0xFF,6);
    ether_addr_copy((const struct ether_addr *)dmac, &eth->d_addr);
    ether_addr_copy((const struct ether_addr *)smac, &eth->s_addr);
    eth->ether_type = htons(ETHER_TYPE_ARP);

    memset(arp, 0, sizeof(struct arp_hdr));

    rte_memcpy(&arp->arp_data.arp_sha, &port->addr, 6);
    addr = src_ip;
    inetAddrCopy(&arp->arp_data.arp_sip, &addr);

    rte_memcpy(&arp->arp_data.arp_tha, dmac, 6);
    addr = dst_ip;
    inetAddrCopy(&arp->arp_data.arp_tip, &addr);

    arp->arp_hrd = htons(ARP_HRD_ETHER);
    arp->arp_pro = htons(ETHER_TYPE_IPv4);
    arp->arp_hln = 6;
    arp->arp_pln = 4;
    arp->arp_op  = htons(code);
    m->pkt_len   = 60;
    m->data_len  = 60;
    m->l2_len    = sizeof(struct ether_hdr);
    m->l3_len    = sizeof(struct arp_hdr);

    memset(&arp[1], 0, 18);

    netif_xmit(m, port);

    return EDPVS_OK;
}

int32_t arpp_send_reply_for_nat(struct netif_port *dev, uint32_t tip, char* tha, uint32_t sip, char* sha)
{
	int32_t rc = -1;
	ip4_t htip, hsip;
	arp_proxy_ip_t* prxyip;

	ENT_FUNC(3);

	htip = ntohl(tip);
	hsip = ntohl(sip);

	dbg(5, "RCV ARP Request: %s: target=" IP_FMT ":" MAC_FMT " , from=" IP_FMT ":" MAC_FMT, 
		dev->name, IPN(tip), MAC(tha), IPN(sip), MAC(sha)); 

	ns_rd_lock() {
		// XXX: 흠, NAT 룰이 많은 경우 검색 성능에 문제가 생긴다.
		list_for_each_entry(prxyip, &g_arpp_root.ip_list, list) {
			// entry가 추가 될때 dev를 못찾은 경우이다.
			// dev를 새로 찾아서 업데이트 한다.
			if (prxyip->ifidx == IFACE_IDX_MAX) {
				prxyip->ifidx = ns_get_nic_idx_by_ip(prxyip->sip);
			}

			// arp를 수신한 dev가 NAT로 설정된 NIC 인지 검사 해야 한다.
			if (dev->id != prxyip->ifidx || 
				!(prxyip->sip <= htip && htip <= prxyip->eip)) {

				continue;
			}

			dbg(5, "SND ARP Reply Unicast: %s: target=" IP_FMT ", from=" IP_FMT, 
				dev->name, IPN(tip), IPN(sip));

			rc = send_arp_reply(dev, ARPOP_REPLY, tip, (char*)&dev->addr, sip, sha);  
			break;
		}

	} ns_rd_unlock();

	return rc;
}

int arpp_recv(struct rte_mbuf *m, struct netif_port *port)
{
	struct arp_hdr *arp = rte_pktmbuf_mtod(m, struct arp_hdr *);
	struct ether_hdr *eth;
	uint32_t ipaddr;
	int32_t rc = -1;

	ENT_FUNC(3);

	eth = (struct ether_hdr *)rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct ether_hdr));

#if 0
	// IP/MAC monitoring
	if (OPT_VAL(l2fw)) {
		if (l2f_arp_main(eth->h_source, dev, tip, tha, sip, sha) == NS_DROP) {
			return NS_DROP;
		}
	}
#endif


	if (rte_be_to_cpu_16(arp->arp_op) != ARP_OP_REQUEST) {
		// keep going to handle it
		return -1;
	}


	if (GET_OPT_VALUE(nat_arp_proxy)) {
		struct arp_ipv4 *a = &arp->arp_data;
		rc = arpp_send_reply_for_nat(port, a->arp_tip, (char*)&a->arp_tha, a->arp_sip, (char*)&a->arp_sha);
	}

	return rc;
}

int32_t arpp_add_ip(uint8_t ifidx, ip4_t sip, ip4_t eip, uint16_t flag)
{
	arp_proxy_ip_t* prxyip;
	ns_node_id_t nid = 0;

	ENT_FUNC(3);

	prxyip = ns_malloc_kz(sizeof(arp_proxy_ip_t));
	ns_mem_assert(prxyip, "arp_proxy_ip_t", return -1);

	INIT_LIST_HEAD(&prxyip->list);
	prxyip->sip = sip;
	prxyip->eip = eip;
	prxyip->ifidx = ifidx;
	prxyip->flag = flag;

	prxyip->nid = nid;
	prxyip->owner_nid = nid;

	dbg(5, "arp proxy ip: iface_idx=%u, sip="IP_FMT ",eip="IP_FMT, ifidx, IPH(sip), IPH(eip));

	ns_rw_lock(&g_arpp_root.lock) {
		list_add_tail(&prxyip->list, &g_arpp_root.ip_list);
	} ns_rw_unlock(&g_arpp_root.lock);

	atomic_inc(&g_arpp_root.cnt);

	return 0;
}

///////////////////////////////////////////////////////

void arpp_clean_ip(void)
{
	arp_proxy_ip_t* prxyip;
	int32_t cnt=0;

	ENT_FUNC(3);

	ns_rw_lock(&g_arpp_root.lock) {

		while (!list_empty(&g_arpp_root.ip_list)) {
			prxyip = list_entry(g_arpp_root.ip_list.next, arp_proxy_ip_t, list);

			// dsync를 안하므로, 모든 노드는 자신의 소유이다.
			// 그래서 모두 지워도 무방하다.
			list_del_init(&prxyip->list);
			ns_free(prxyip);
			cnt ++;
		}

	} ns_rw_unlock(&g_arpp_root.lock);
}


/////////////////////////////////////////////////////////

int32_t arpp_show_natip(ioctl_data_t *iodata)
{
	arp_proxy_ip_t* prxyip;
	char sip[20], eip[20];
	char buf[1024];
	int32_t i;
	size_t len;

	ENT_FUNC(3);

	len = sprintf(buf, "%-3s %-5s %-4s %-3s %-5s %-10s %-15s %-15s \n",
				  "No", "Dev", "NAT", "NID", "Owner", "Flag", "Start IP", "End IP");

	if (copy_expand(iodata, buf, len, 1024)) {
		return -1;
	}

	i = 1;
	ns_rd_lock() {

		list_for_each_entry(prxyip, &g_arpp_root.ip_list, list) {
			// entry가 추가 될때 dev를 못찾은 경우이다.
			// dev를 새로 찾아서 업데이트 한다.
			if (prxyip->ifidx == IFACE_IDX_MAX) {
				prxyip->ifidx = ns_get_nic_idx_by_ip(prxyip->sip);
			}

			sprintf(sip, IP_FMT, IPH(prxyip->sip));
			sprintf(eip, IP_FMT, IPH(prxyip->eip));

			struct netif_port* port = netif_port_get(prxyip->ifidx);

			len = sprintf(buf, "%-3d %-5s %-4s %-3d %-5d 0x%08x %-15s %-15s\n",
						  i,
						  port?port->name:"None",
						  (prxyip->flag&ARP_PRXY_SNAT)?"SNAT":"DNAT", 
						  prxyip->nid, 
						  prxyip->owner_nid,
						  prxyip->flag,
						  sip,
						  eip);

			if (copy_expand(iodata, buf, len, 1024)) {
				break;
			}

			i++;
		}

	} ns_rd_unlock();

	return iodata->out == NULL ? -1:0;
}

//////////////////////////////////////////////////////

/*
 *	Called once on startup.
 */

int32_t arpp_init(void)
{
	ns_init_lock(&g_arpp_root.lock);
	INIT_LIST_HEAD(&g_arpp_root.ip_list);
	atomic_set(&g_arpp_root.cnt, 0);
	g_ns_arphook = arpp_recv;

	return 0;
}

void arpp_clean(void) 
{
	g_ns_arphook = NULL;
	arpp_clean_ip();
}

