#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_log.h>

#include "list.h"
#include "netif.h"
#include "common.h"
#include "inetaddr.h"
#include "route.h"
#include "conf/inetaddr.h"
#include "conf/route.h"
#include "netlink.h"
#include "ctrl.h"


#define RTE_LOGTYPE_NETLINK RTE_LOGTYPE_USER2

//#define NETL_POLL_TIMEOUT 1000
#define NETL_POLL_TIMEOUT 1

struct ether_addr invalid_mac = { { 0x00, 0x00, 0x00, 0x00, 0x00 } };
struct netl_handle *g_netl_h = NULL;

static inline __u32 rta_getattr_u32(struct rtattr *rta)
{
	return *(__u32 *)RTA_DATA(rta);
}

static inline __u16 rta_getattr_u16(struct rtattr *rta)
{
	return *(__u16 *)RTA_DATA(rta);
}

static inline __u8 rta_getattr_u8(struct rtattr *rta)
{
	return *(__u8 *)RTA_DATA(rta);
}

static inline char* rta_getattr_str(struct rtattr *rta)
{
	return (char *)RTA_DATA(rta);
}

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
	__u32 table = r->rtm_table;

	if (tb[RTA_TABLE]) {
		table = rta_getattr_u32(tb[RTA_TABLE]);
	}
	return table;
}

#define parse_rtattr_nested(tb, max, rta) \
	(parse_rtattr_flags((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta), 0))


static int parse_rtattr_flags(struct rtattr *tb[], int max,
							  struct rtattr *rta, int len,
							  unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		//dpvs_log(INFO, NETLINK, "rta_type=%d \n", rta->rta_type);
		
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type])) {
			tb[type] = rta;
		}
		rta = RTA_NEXT(rta, len);
	}

	if (len) {
		dpvs_log(INFO, NETLINK, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	}

	return 0;
}

static uint16_t get_vlan_id(struct rtattr *linkinfo[])
{
	struct rtattr *vlaninfo[IFLA_VLAN_MAX + 1];

	if (!linkinfo[IFLA_INFO_DATA]) {
		return 0;
	}
	parse_rtattr_nested(vlaninfo, IFLA_VLAN_MAX, linkinfo[IFLA_INFO_DATA]);
	if (vlaninfo[IFLA_VLAN_PROTOCOL]
		&& RTA_PAYLOAD(vlaninfo[IFLA_VLAN_PROTOCOL]) < sizeof(__u16)) {
		return 0;
	}
	if (!vlaninfo[IFLA_VLAN_ID] ||
		RTA_PAYLOAD(vlaninfo[IFLA_VLAN_ID]) < sizeof(__u16)) {
		return 0;
	}
	return rta_getattr_u16(vlaninfo[IFLA_VLAN_ID]);
}

static int
netl_handler(struct netl_handle *h,
			 struct sockaddr_nl *nladdr __attribute__((unused)),
			 struct nlmsghdr *hdr, void *args)
{
	int len = hdr->nlmsg_len;

	switch (hdr->nlmsg_type) {
	// TODO RTM_SETLINK
	case RTM_NEWLINK:
	case RTM_DELLINK:
	{
		struct ifinfomsg *ifi = NLMSG_DATA(hdr);
		struct rtattr *rta_tb[IFLA_MAX + 1];
		struct ether_addr lladdr;
		int ifid = ifi->ifi_index;
		int mtu = -1;
		const char *ifname = "";
		uint16_t vlanid = 0;
		oper_state_t state = LINK_UNKNOWN;
		link_action_t action = LINK_ADD;

		len -= NLMSG_LENGTH(sizeof(*ifi));

		if (len < 0) {
			dpvs_log(INFO, NETLINK, "Bad length\n");
			return -1;
		}

		parse_rtattr_flags(rta_tb, IFLA_MAX, IFLA_RTA(ifi), len, 0);

		if (ifi->ifi_type != ARPHRD_ETHER) {
			return 0;           // This is not ethernet
		}
		if (rta_tb[IFLA_IFNAME] == NULL) {
			dpvs_log(INFO, NETLINK, "No if name\n");
			return -1;          // There should be a name, this is a bug
		}
		if (hdr->nlmsg_type == RTM_DELLINK) {
			action = LINK_DELETE;
		}

		if (rta_tb[IFLA_MTU]) {
			mtu = *(int *)RTA_DATA(rta_tb[IFLA_MTU]);
		}
		if (rta_tb[IFLA_IFNAME]) {
			ifname = rta_getattr_str(rta_tb[IFLA_IFNAME]);
		}
		if (rta_tb[IFLA_OPERSTATE]) {
			state = rta_getattr_u8(rta_tb[IFLA_OPERSTATE]);
		}
		if (rta_tb[IFLA_ADDRESS]) {
			memcpy(&lladdr.addr_bytes, RTA_DATA(rta_tb[IFLA_ADDRESS]), sizeof(lladdr.addr_bytes));
		}

		if (rta_tb[IFLA_LINKINFO]) {
			struct rtattr *linkinfo[IFLA_INFO_MAX + 1];
			parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, rta_tb[IFLA_LINKINFO]);

			if (linkinfo[IFLA_INFO_KIND]) {
				char *kind = RTA_DATA(linkinfo[IFLA_INFO_KIND]);
				//XXX only handle vlan type for now
				if (!strcmp(kind, "vlan")) {
					vlanid = get_vlan_id(linkinfo);
				}
			}
		}

		if (h->cb.link != NULL) {
			// call netlink_eth_link()
			h->cb.link(action, ifid, &lladdr, mtu, ifname, state, vlanid, args);
		}
	}
	break;
	}

	if (hdr->nlmsg_type == RTM_NEWADDR || hdr->nlmsg_type == RTM_DELADDR) {
		struct rtattr *rta_tb[IFA_MAX + 1];
		struct ifaddrmsg *ifa = NLMSG_DATA(hdr);
		unsigned char buf_addr[sizeof(struct in6_addr)];

		len -= NLMSG_LENGTH(sizeof(*ifa));

		if (len < 0) {
			dpvs_log(INFO, NETLINK, "Bad length\n");
			return -1;
		}

		if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6) {
			dpvs_log(INFO, NETLINK, "Not support protocol\n");
			return -1;
		}

		parse_rtattr_flags(rta_tb, IFA_MAX, IFA_RTA(ifa), len, 0);

		if (!rta_tb[IFA_LOCAL]) {
			rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];
		}
		if (!rta_tb[IFA_ADDRESS]) {
			rta_tb[IFA_ADDRESS] = rta_tb[IFA_LOCAL];
		}

		if (rta_tb[IFA_LOCAL]) {
			//we may optimize by passing directly RTA_DATA(rta_tb[IFA_LOCAL]) to the cb
			memcpy(buf_addr, RTA_DATA(rta_tb[IFA_LOCAL]), RTA_PAYLOAD(rta_tb[IFA_LOCAL]));
		}

		netlink_if_addr(hdr->nlmsg_type, buf_addr, ifa);
	}

	if (hdr->nlmsg_type == RTM_NEWROUTE || hdr->nlmsg_type == RTM_DELROUTE) {
		struct rtattr *tb[RTA_MAX + 1];
		struct rtmsg *r = NLMSG_DATA(hdr);
		len -= NLMSG_LENGTH(sizeof(*r));

		if (len < 0) {
			dpvs_log(INFO, NETLINK, "Bad length\n");
			return -1;
		}

		if (r->rtm_family == RTNL_FAMILY_IPMR ||
			r->rtm_family == RTNL_FAMILY_IP6MR) {
			return 0;
		}

		parse_rtattr_flags(tb, RTA_MAX, RTM_RTA(r), len, 0);

		if (r->rtm_type == RTN_UNICAST) {
			if (!tb[RTA_DST] || !tb[RTA_GATEWAY] || !tb[RTA_OIF]) {
				return 0;
			}
		}
		else {
			// FIXME:
			//dpvs_log(INFO, NETLINK, "not supported rtm_type=%d  \n", r->rtm_type);
			return 0;
		}

		int idx;
		idx = rta_getattr_u32(tb[RTA_OIF]);

		char ifname[64];
		if_indextoname(idx, ifname);

#if 0
		int table;
		table = rta_getattr_u32(tb[RTA_TABLE]);
		dpvs_log(INFO, NETLINK, "##### iif=%p, oif=%p, via=%p, type=%d, oif=%d, ifname=%s, table=%d \n", 
				 tb[RTA_IIF],
				 tb[RTA_OIF],
				 tb[RTA_VIA], r->rtm_type, 
				 idx,
				 ifname, 
				 table);
#endif

		netlink_route(hdr->nlmsg_type, r, RTA_DATA(tb[RTA_DST]), RTA_DATA(tb[RTA_GATEWAY]), idx);
	}

#if 0
	if (hdr->nlmsg_type == RTM_NEWNEIGH || hdr->nlmsg_type == RTM_DELNEIGH) {
		struct ndmsg *neighbor = NLMSG_DATA(hdr);
		struct rtattr *tb[NDA_MAX + 1];
		uint16_t vlanid = 0;

		len -= NLMSG_LENGTH(sizeof(*neighbor));

		if (len < 0) {
			dpvs_log(INFO, NETLINK, "Bad length\n");
			return -1;
		}

		// Ignore non-ip
		if (neighbor->ndm_family != AF_INET &&
			neighbor->ndm_family != AF_INET6) {
			dpvs_log(INFO, NETLINK, "Bad protocol\n");
			return 0;
		}

		parse_rtattr_flags(tb, NDA_MAX, RTM_RTA(neighbor), len, 0);

		neighbor_action_t action;
		if (hdr->nlmsg_type == RTM_NEWNEIGH) {
			action = NEIGHBOR_ADD;
		}
		else {
			action = NEIGHBOR_DELETE;
		}

		if (tb[NDA_VLAN]) {
			vlanid = rta_getattr_u16(tb[NDA_VLAN]);
		}

		switch (neighbor->ndm_family) {
		case AF_INET:
			if (h->cb.neighbor4 != NULL) {
				if (tb[NDA_LLADDR]) {
					// call netlink_neighbor4()
					h->cb.neighbor4(action, neighbor->ndm_ifindex,
									RTA_DATA(tb[NDA_DST]),
									RTA_DATA(tb[NDA_LLADDR]),
									neighbor->ndm_state, vlanid, args);
				}
				else {
					h->cb.neighbor4(action, neighbor->ndm_ifindex,
									RTA_DATA(tb[NDA_DST]),
									&invalid_mac,
									neighbor->ndm_state, vlanid, args);
				}
			}
			break;
		case AF_INET6:
			if (h->cb.neighbor6 != NULL) {
				if (tb[NDA_LLADDR]) {
					// call netlink_neighbor6()
					h->cb.neighbor6(action, neighbor->ndm_ifindex,
									RTA_DATA(tb[NDA_DST]),
									RTA_DATA(tb[NDA_LLADDR]),
									neighbor->ndm_state, vlanid, args);
				}
				else {
					h->cb.neighbor6(action, neighbor->ndm_ifindex,
									RTA_DATA(tb[NDA_DST]),
									&invalid_mac,
									neighbor->ndm_state, vlanid, args);
				}
			}
			break;
		default:
			dpvs_log(INFO, NETLINK, "Bad protocol\n");
			return -1;
		}
	}
#endif

	return 0;
}

int netl_close(struct netl_handle *h)
{
	h->closing = 1;
	return 0;
}

int netl_listen(struct netl_handle *h, void *args)
{
	int len, err;
	int msg_count;
	ssize_t status;
	struct nlmsghdr *hdr;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name		= &nladdr,
		.msg_namelen	= sizeof(nladdr),
		.msg_iov		= &iov,
		.msg_iovlen		= 1,
	};
	char buf[8192];
	struct pollfd fds[1];

	if (h == NULL) {
		return -1;
	}

	iov.iov_base = buf;

#if 0
	if (h->cb.init != NULL) {
		err = h->cb.init(args);
		if (err != 0) {
			return err;
		}
	}
#endif

	fds[0].events = POLLIN;
	fds[0].fd = h->fd;

START:
	if (h->closing) {
		return 0;
	}

	int res = poll(fds, 1, NETL_POLL_TIMEOUT);

	if (res < 0) {
		if (errno == EINTR) {
			goto START;
		}

		return 0;
	}

	if (!(fds[0].revents & POLLIN)) {
		return 0;
	}

	iov.iov_len = sizeof(buf);
	status = recvmsg(h->fd, &msg, 0);
	if (status < 0) {
		dpvs_log(INFO, NETLINK, "error receiving netlink %s (%d) \n", strerror(errno), errno);
		return 0;
	}

	if (status == 0) {
		dpvs_log(INFO, NETLINK, "EOF on netlink\n");
		return 0;
	}

	if (msg.msg_namelen != sizeof(nladdr)) {
		dpvs_log(INFO, NETLINK, "Wrong address length\n");
		return 0;
	}

	if (iov.iov_len < ((size_t)status) || (msg.msg_flags & MSG_TRUNC)) {
		dpvs_log(INFO, NETLINK, "Malformatted or truncated message, skipping\n");
		return 0;
	}

	msg_count = 0;
	//dpvs_log(DEBUG, NETLINK, "##### Parsing netlink msg\n");

	for (hdr = (struct nlmsghdr *)buf; (size_t)status >= sizeof(*hdr);) {
		len = hdr->nlmsg_len;

		//dpvs_log(DEBUG, NETLINK, "Processing netlink msg of %d length \n", len);

		err = netl_handler(h, &nladdr, hdr, args);
		if (err < 0) {
			dpvs_log(INFO, NETLINK, "netl_handler failed\n");
		}

		msg_count++;
		status -= NLMSG_ALIGN(len);
		hdr = (struct nlmsghdr *)((char *)hdr + NLMSG_ALIGN(len));
	}

	//dpvs_log(DEBUG, NETLINK, "processed %d netlink msg in buffer\n", msg_count);

	if (status) {
		dpvs_log(DEBUG, NETLINK, "Remnant data not read\n");
	}

	return 0;
}

static inline __u32 nl_mgrp(__u32 group)
{
	return group ? (1 << (group - 1)) : 0;
}

struct netl_handle* netl_create(unsigned events)
{
	struct netl_handle *netl_handle;
	int rcvbuf = 1024 * 1024 * 1024;
	socklen_t addr_len;
	unsigned subscriptions = 0;

	switch (events) {
	case NETLINK4_EVENTS:
		subscriptions |= nl_mgrp(RTNLGRP_LINK);
		subscriptions |= nl_mgrp(RTNLGRP_IPV4_IFADDR);
		subscriptions |= nl_mgrp(RTNLGRP_IPV4_ROUTE);
		break;
	case NETLINK6_EVENTS:
		subscriptions |= nl_mgrp(RTNLGRP_IPV6_IFADDR);
		subscriptions |= nl_mgrp(RTNLGRP_IPV6_ROUTE);
		break;
	case NETLINK4_EVENTS | NETLINK6_EVENTS:
		subscriptions |= nl_mgrp(RTNLGRP_LINK);
		subscriptions |= nl_mgrp(RTNLGRP_IPV4_IFADDR);
		subscriptions |= nl_mgrp(RTNLGRP_IPV4_ROUTE);
		subscriptions |= nl_mgrp(RTNLGRP_IPV6_IFADDR);
		subscriptions |= nl_mgrp(RTNLGRP_IPV6_ROUTE);
	}
	subscriptions |= nl_mgrp(RTNLGRP_NEIGH);

	netl_handle = rte_calloc_socket("netl_handle", 1, sizeof(struct netl_handle), 0, SOCKET_ID_ANY);
	if (netl_handle == NULL) {
		return NULL;
	}

	netl_handle->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (netl_handle->fd < 0) {
		dpvs_log(ERR, NETLINK, "Cannot open netlink socket");
		goto free_netl_handle;
	}

	if (setsockopt(netl_handle->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
		dpvs_log(ERR, NETLINK, "Cannot set RCVBUF");
		goto free_netl_handle;
	}

	memset(&netl_handle->local, 0, sizeof(netl_handle->local));
	netl_handle->local.nl_family = AF_NETLINK;
	netl_handle->local.nl_groups = subscriptions;

	netl_handle->cb.neighbor4 = NULL;
	netl_handle->cb.route4 = NULL;

	if (bind(netl_handle->fd, (struct sockaddr *)&(netl_handle->local), sizeof(netl_handle->local)) < 0) {
		dpvs_log(ERR, NETLINK, "Cannot bind netlink socket");
		goto free_netl_handle;
	}

	addr_len = sizeof(netl_handle->local);
	if (getsockname(netl_handle->fd, (struct sockaddr *)&netl_handle->local, &addr_len) < 0) {
		dpvs_log(ERR, NETLINK, "Cannot getsockname");
		goto free_netl_handle;
	}

	if (addr_len != sizeof(netl_handle->local)) {
		dpvs_log(ERR, NETLINK, "Wrong address length");
		goto free_netl_handle;
	}

	if (netl_handle->local.nl_family != AF_NETLINK) {
		dpvs_log(ERR, NETLINK, "Wrong address family");
		goto free_netl_handle;
	}

	netl_handle->closing = 0;

	return netl_handle;

free_netl_handle:
	rte_free(netl_handle);

	return NULL;
}

int netl_free(struct netl_handle *h)
{
	if (h != NULL) {
		if (h->fd > 0) {
			close(h->fd);
			h->fd = -1;
		}

		rte_free(h);
	}

	return 0;
}

/////////////////////////////////////////
//

int netlink_if_addr(int action, unsigned char *addr, struct ifaddrmsg *ifa)
{
	struct inet_addr_param pm;

	memset(&pm, 0, sizeof(pm));

	pm.af = ifa->ifa_family;
	if (ifa->ifa_family == AF_INET6) {
		memcpy(&pm.addr.in, addr, sizeof(struct in6_addr));
	}
	else {
		memcpy(&pm.addr.in, addr, sizeof(struct in_addr));
	}

	if_indextoname(ifa->ifa_index, pm.ifname);
	pm.plen = ifa->ifa_prefixlen;
	pm.scope = ifa->ifa_scope;

	sockoptid_t opt;

	if (action == RTM_NEWADDR) {
		opt = SOCKOPT_SET_IFADDR_ADD;
	}
	else if (action == RTM_DELADDR) {
		opt = SOCKOPT_SET_IFADDR_DEL;
	}
	else {
		dpvs_log(INFO, NETLINK, "Unknown action of ifaddr: %d\n", action);
		return -1;
	}

	int ret = inet_set_iface((int)opt, (const void *)&pm, sizeof(pm));
	if (ret) {
		dpvs_log(DEBUG, NETLINK, "ifaddr operation ret=%d \n", ret);
	}

	return 0;
}

int netlink_route(uint16_t msg_type, struct rtmsg *msg, struct in_addr *addr, struct in_addr *nexthop, int oif)
{
	struct dp_vs_route_conf cf;
	sockoptid_t opt;

	if (msg_type == RTM_NEWROUTE) {
		opt = SOCKOPT_SET_ROUTE_ADD;
	}
	else if (msg_type == RTM_DELROUTE) {
		opt = SOCKOPT_SET_ROUTE_DEL;
	}
	else {
		dpvs_log(ERR, NETLINK, "Unknown msg_type=%d\n", msg_type);
		return -1;
	}

	memset(&cf, 0, sizeof(cf));

	cf.af =  msg->rtm_family;
	cf.scope = ROUTE_CF_SCOPE_KNI;
	memcpy(&cf.dst.in, addr, sizeof(struct in_addr));
	cf.plen = msg->rtm_dst_len;
	memcpy(&cf.src.in, nexthop, sizeof(struct in_addr));

	if_indextoname(oif, cf.ifname);

	int ret = route_set_entry((int)opt, (const void *)&cf, sizeof(cf));
	if (ret) {
		dpvs_log(ERR, NETLINK, "route operation ret=%d \n", ret);
	}

	return 0;
}

static int
netlink_neighbor4(neighbor_action_t		action,
				  __s32					port_id,
				  struct in_addr		*addr,
				  struct ether_addr		*lladdr,
				  __u8					flags,
				  __rte_unused __u16	vlan_id,
				  void					*args)
{
	// if port_id is not handled
	//   ignore, return immediatly
	// if neighbor add
	//   lookup neighbor
	//   if exists
	//     update lladdr, set flag as REACHABLE/STALE/DELAY
	//   else
	//     // This should not happen
	//     insert new nexthop
	//     set insert date=now, refcount = 0, flag=REACHABLE/STALE/DELAY
	// if neighbor delete
	//   lookup neighbor
	//   if exists
	//     if refcount != 0
	//       set nexthop as invalid
	//     else
	//       set flag empty
	//   else
	//     do nothing
	//     // this should not happen

	int s;
	uint16_t nexthop_id = 0;
	char ipbuf[INET_ADDRSTRLEN];
	char ibuf[IFNAMSIZ];
	unsigned kni_vlan = 0;


	//uint32_t find_id;
	//struct control_handle *handle = args;
	//int32_t socket_id = handle->socket_id;
	//assert(neighbor4_struct != NULL);

	if (addr == NULL) {
		return -1;
	}

	inet_ntop(AF_INET, addr, ipbuf, INET_ADDRSTRLEN);
	if_indextoname(port_id, ibuf);

	if (action == NEIGHBOR_ADD) {
		if (lladdr == NULL) {
			return -1;
		}

		s = sscanf(ibuf, "dpdk%10u.%10u", &port_id, &kni_vlan);
		if (s <= 0) {
			//dpvs_log(DEBUG, NETLINK, "received a neighbor announce for an unmanaged iface %s\n", ibuf);
			return -1;
		}
		else if (s == 1) {
			// no vlan
			kni_vlan = 0;
		}
#if 0
#define NUD_INCOMPLETE0x01
#define NUD_REACHABLE0x02
#define NUD_STALE0x04
#define NUD_DELAY0x08
#define NUD_PROBE0x10
#define NUD_FAILED0x20
/* Dummy states */
#define NUD_NOARP0x40
#define NUD_PERMANENT0x80
#define NUD_NONE0x00
#endif

		if (flags != NUD_REACHABLE && flags != NUD_FAILED && flags != NUD_PERMANENT) {
			dpvs_log(NOTICE, NETLINK, "don't handle state of neighbor4 (state 0x%x, %s)...\n", flags, ipbuf);
			return -1;
		}

		dpvs_log(NOTICE, NETLINK, "Adding ipv4 neighbor %s with port %s vlan_id %x nexthop_id %d state 0x%x...\n", 
				 ipbuf, ibuf, kni_vlan, nexthop_id, flags);

#if 0
		s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id], addr, &nexthop_id);
		if (s < 0) {
			s = neighbor4_add_nexthop(neighbor4_struct[socket_id], addr, &nexthop_id, NEI_ACTION_FWD);
			if (s < 0) {
				dpvs_log(ERR, NETLINK, "failed to add a nexthop in neighbor table...\n");
				return -1;
			}

			dpvs_log(NOTICE, NETLINK, "adding ipv4 neighbor %s with port %s vlan_id %x nexthop_id %d ...\n", 
					 ipbuf, ibuf, kni_vlan, nexthop_id);

			s = rte_lpm_lookup(ipv4_pktj_lookup_struct[socket_id], 
							   rte_be_to_cpu_32(addr->s_addr), &find_id);
			if (s == 0) {
				s = rte_lpm_add(ipv4_pktj_lookup_struct[socket_id],
								rte_be_to_cpu_32(addr->s_addr), 32, nexthop_id);
				if (s < 0) {
					lpm4_stats[socket_id].nb_add_ko++;
					dpvs_log(ERR, NETLINK, "failed to add a route in lpm during neighbor adding...\n");
					return -1;
				}

				lpm4_stats[socket_id].nb_add_ok++;
			}
		}

		if (flags == NUD_FAILED) {
			neighbor4_set_action(neighbor4_struct[socket_id], nexthop_id, NEI_ACTION_KNI);
		}
		else {
			neighbor4_set_action(neighbor4_struct[socket_id], nexthop_id, NEI_ACTION_FWD);
		}

		dpvs_log(DEBUG, NETLINK, "set neighbor4 with port_id %d state %d\n", port_id, flags);
		neighbor4_set_lladdr_port(neighbor4_struct[socket_id], nexthop_id, 
								  &ports_eth_addr[port_id], lladdr, port_id, kni_vlan);

		neighbor4_set_state(neighbor4_struct[socket_id], nexthop_id, flags);
#endif
	}
	else if (action == NEIGHBOR_DELETE) {
		if (flags != NUD_FAILED && flags != NUD_STALE) {
			dpvs_log(DEBUG, NETLINK, "neighbor4 delete ope failed, bad NUD state: 0x%x \n", flags);
			return -1;
		}

		dpvs_log(NOTICE, NETLINK, "Deleting ipv4 neighbor %s with port %s vlan_id %d state 0x%x ...\n", 
				 ipbuf, ibuf, kni_vlan, flags);
#if 0
		dpvs_log(DEBUG, NETLINK, "deleting ipv4 neighbor...\n");
		s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id], addr, &nexthop_id);
		if (s < 0) {
			dpvs_log(NOTICE, NETLINK, "failed to find a nexthop to delete in neighbor table...\n");
			return 0;
		}

		neighbor4_delete(neighbor4_struct[socket_id], nexthop_id);
		// FIXME not thread safe
		if (neighbor4_struct[socket_id]->entries.t4[nexthop_id].neighbor.refcnt == 0) {
			s = rte_lpm_delete(ipv4_pktj_lookup_struct[socket_id], rte_be_to_cpu_32(addr->s_addr), 32);
			if (s < 0) {
				lpm4_stats[socket_id].nb_del_ko++;
				dpvs_log(ERR, NETLINK, "failed to delete route...\n");
				return -1;
			}

			lpm4_stats[socket_id].nb_del_ok++;
		}
#endif
	}

	dpvs_log(DEBUG, NETLINK, "neigh %s operation success\n", ipbuf);

	return 0;
}

static int
netlink_neighbor6(neighbor_action_t		action,
				  int32_t				port_id,
				  struct in6_addr		*addr,
				  struct ether_addr		*lladdr,
				  uint8_t				flags,
				  __rte_unused uint16_t vlan_id,
				  void					*args)
{
	// if port_id is not handled
	//   ignore, return immediatly
	// if neighbor add
	//   lookup neighbor
	//   if exists
	//     update lladdr, set flag as REACHABLE/STALE/DELAY
	//   else
	//     // This should not happen
	//     insert new nexthop
	//     set insert date=now, refcount = 0, flag=REACHABLE/STALE/DELAY
	// if neighbor delete
	//   lookup neighbor
	//   if exists
	//     if refcount != 0
	//       set nexthop as invalid
	//     else
	//       set flag empty
	//   else
	//     do nothing
	//     // this should not happen

#if 0
	struct control_handle *handle = args;

	assert(handle != NULL);
	int s;
	uint16_t nexthop_id;
	lpm6_neigh find_id;
	int32_t socket_id = handle->socket_id;
	char ipbuf[INET6_ADDRSTRLEN];

	assert(neighbor6_struct != NULL);

	if (addr == NULL) {
		return -1;
	}
	inet_ntop(AF_INET6, addr, ipbuf, INET6_ADDRSTRLEN);

	if (action == NEIGHBOR_ADD) {
		if (lladdr == NULL) {
			return -1;
		}
		char ibuf[IFNAMSIZ];
		unsigned kni_vlan;

		if_indextoname(port_id, ibuf);
		s = sscanf(ibuf, "dpdk%10u.%10u", &port_id, &kni_vlan);

		if (s <= 0) {
			dpvs_log(NOTICE, NETLINK,
					 "received a neighbor "
					 "announce for an unmanaged "
					 "iface %s\n",
					 ibuf);
			return -1;
		}
		else if (s == 1) {
			kni_vlan = 0;
		}

		if (flags != NUD_REACHABLE && flags != NUD_FAILED
			&& flags != NUD_PERMANENT) {
			dpvs_log(NOTICE, NETLINK,
					 "don't handle state of neighbor6 "
					 "(state %d, %s)...\n",
					 flags, ipbuf);
			return -1;
		}

		s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id], addr,
									 &nexthop_id);
		if (s < 0) {
			dpvs_log(
				DEBUG, NETLINK,
				"adding ipv6 neighbor %s with port_id %d "
				"vlan_id %d...\n",
				ipbuf, port_id, kni_vlan);

			s = neighbor6_add_nexthop(neighbor6_struct[socket_id],
									  addr, &nexthop_id,
									  NEI_ACTION_FWD);
			if (s < 0) {
				dpvs_log(ERR, NETLINK,
						 "failed to add a "
						 "nexthop in neighbor "
						 "table...\n");
				return -1;
			}

			// apply rate limit rule if next hop neighbor is in the
			// table
			apply_rate_limit_ipv6(addr, nexthop_id, socket_id);

			if (rte_lpm6_lookup(ipv6_pktj_lookup_struct[socket_id],
								addr->s6_addr, &find_id) == 0) {
				s = rte_lpm6_add(
					ipv6_pktj_lookup_struct[socket_id],
					addr->s6_addr, 128, nexthop_id);
				if (s < 0) {
					lpm6_stats[socket_id].nb_add_ko++;
					dpvs_log(ERR, NETLINK,
							 "failed to add a route in "
							 "lpm during neighbor "
							 "adding...\n");
					return -1;
				}
				lpm6_stats[socket_id].nb_add_ok++;
			}
		}

		if (flags == NUD_FAILED) {
			neighbor6_set_action(neighbor6_struct[socket_id],
								 nexthop_id, NEI_ACTION_KNI);
		}
		else {
			neighbor6_set_action(neighbor6_struct[socket_id],
								 nexthop_id, NEI_ACTION_FWD);
		}
		dpvs_log(DEBUG, NETLINK,
				 "set neighbor6 with port_id %d state %d \n", port_id,
				 flags);
		neighbor6_set_lladdr_port(neighbor6_struct[socket_id],
								  nexthop_id, &ports_eth_addr[port_id],
								  lladdr, port_id, kni_vlan);
		neighbor6_set_state(neighbor6_struct[socket_id], nexthop_id,
							flags);
	}
	if (action == NEIGHBOR_DELETE) {
		if (flags != NUD_FAILED && flags != NUD_STALE) {
			dpvs_log(
				DEBUG, NETLINK,
				"neighbor6 delete ope failed, bad NUD state: %d \n",
				flags);
			return -1;
		}

		dpvs_log(DEBUG, NETLINK, "deleting ipv6 neighbor...\n");
		s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id], addr,
									 &nexthop_id);
		if (s < 0) {
			dpvs_log(NOTICE, NETLINK,
					 "failed to find a nexthop to "
					 "delete in neighbor "
					 "table...\n");
			return 0;
		}
		neighbor6_delete(neighbor6_struct[socket_id], nexthop_id);
		// FIXME not thread safe
		if (neighbor6_struct[socket_id]
			->entries.t6[nexthop_id]
			.neighbor.refcnt == 0) {
			s = rte_lpm6_delete(ipv6_pktj_lookup_struct[socket_id],
								addr->s6_addr, 128);
			if (s < 0) {
				lpm6_stats[socket_id].nb_del_ko++;
				dpvs_log(ERR, NETLINK,
						 "failed to delete route...\n");
				return -1;
			}

			// reset rate limit for this id
			rlimit6_max[socket_id][nexthop_id] = UINT32_MAX;

			lpm6_stats[socket_id].nb_del_ok++;
		}
	}
	dpvs_log(DEBUG, NETLINK, "neigh %s ope success\n", ipbuf);
#else
	dpvs_log(DEBUG, NETLINK, "neigh6 operation success\n");
#endif

	return 0;
}

static int
netlink_eth_link(link_action_t		action,
				 int				ifid,
				 struct ether_addr	*lladdr,
				 int				mtu,
				 const char			*name,
				 oper_state_t		state,
				 uint16_t			vlanid,
				 __rte_unused void	*args)
{
#if 0
	char action_buf[4];
	char ebuf[32];
	unsigned l, i;

	if (action == LINK_ADD) {
		memcpy(action_buf, "add", 4);
	}
	else {
		memcpy(action_buf, "del", 4);
	}

	l = 0;
	for (i = 0; i < sizeof(*lladdr); i++) {
		if (i == 0) {
			snprintf(ebuf + l, sizeof(ebuf) - l, "%02x",
					 lladdr->addr_bytes[i]);
			l += 2;
		}
		else {
			snprintf(ebuf + l, sizeof(ebuf) - l, ":%02x",
					 lladdr->addr_bytes[i]);
			l += 3;
		}
	}
	if (l >= 32) {
		l = 31;
	}
	ebuf[l] = '\0';

	fprintf(stdout, "%d: link %s %s mtu %d label %s vlan %d ", ifid,
			action_buf, ebuf, mtu, name, vlanid);
	print_operstate(stdout, state);
	fprintf(stdout, "\n");
	fflush(stdout);
#else
	//dpvs_log(DEBUG, NETLINK, "ether link operation success \n");
#endif

	return 0;
}

void* _netlink_init(int32_t socket_id, unsigned events)
{
	struct netl_handle *netl_h;

	//struct handle_res *res;

	netl_h = netl_create(events);
	if (netl_h == NULL) {
		dpvs_log(ERR, NETLINK, "Couldn't initialize netlink socket");
		goto err;
	}

	netl_h->cb.init = NULL;
	netl_h->cb.addr4 = NULL;
	netl_h->cb.addr6 = NULL;
	netl_h->cb.neighbor4 = netlink_neighbor4;
	netl_h->cb.neighbor6 = netlink_neighbor6;
	netl_h->cb.route4 = NULL;
	netl_h->cb.route6 = NULL;
	netl_h->cb.link = netlink_eth_link;

	return netl_h;

err:
	dpvs_log(ERR, NETLINK, "failed to init control_main");

	return NULL;
}


void netlink_init(void)
{
	g_netl_h = _netlink_init(-1, NETLINK4_EVENTS);

	if (g_netl_h == NULL) {
		dpvs_log(ERR, NETLINK, "Couldn't initialize netlink socket");
	}
}

void netlink_term(void)
{
	if (g_netl_h) {
		netl_close(g_netl_h);
		netl_free(g_netl_h);
	}
}

void netlink_run(void)
{
	netl_listen(g_netl_h, NULL);
}
